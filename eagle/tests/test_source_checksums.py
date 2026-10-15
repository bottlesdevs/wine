import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import sources
import symbols
from protocol import read_message, write_message


class SourceChecksums(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all((symbols.host_tool('llvm-dwarfdump'), shutil.which('clang'), shutil.which('gcc'), shutil.which('objcopy'))):
            raise unittest.SkipTest('source checksum fixtures require existing Clang,GCC,binutils and LLVM')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def image(self, name='fixture', compiler='clang', version=5, split=False):
        root = self.root / name
        root.mkdir()
        source = root / 'fixture.c'
        source.write_text('int eagle_source(int n)\n{\n    return n + 7;\n}\nint main(void) { return eagle_source(1); }\n')
        image = root / ('module.exe' if 'mingw32' in compiler else 'module')
        flags = ['-gsplit-dwarf'] if split else []
        subprocess.run([compiler, '-g', '-O0', '-gdwarf-' + str(version), *flags, str(source), '-o', str(image)],
                       check=True, capture_output=True, timeout=30)
        return image, source

    def report(self, image, files=()):
        return symbols.query(image, sources=True, source_files=list(map(str, files)))['source_checksums']

    def test_real_dwarf5_checksums_distinguish_matches_from_changes(self):
        image, source = self.image()
        before = self.report(image, [source])
        self.assertEqual(before['status'], 'available')
        self.assertEqual(before['files'][0]['status'], 'matched')
        self.assertEqual(len(before['entries']), 1)
        self.assertEqual(before['entries'][0]['path'], str(source))
        self.assertEqual(before['entries'][0]['md5'], before['files'][0]['md5'])
        source.write_text(source.read_text() + '\n/* owned changed source */\n')
        after = self.report(image, [source])
        self.assertEqual(after['files'][0]['status'], 'mismatched')
        self.assertEqual(before['entries'], after['entries'])
        self.assertNotEqual(before['files'][0]['sha256'], after['files'][0]['sha256'])

    def test_absent_compiler_checksums_are_not_claimed_as_matches(self):
        for compiler, version in [('gcc', 5), ('clang', 4), ('i686-w64-mingw32-gcc', 4), ('x86_64-w64-mingw32-gcc', 4)]:
            with self.subTest(compiler=compiler, version=version):
                image, source = self.image(compiler + str(version), compiler, version)
                result = self.report(image, [source])
                self.assertEqual(result['status'], 'not-recorded')
                self.assertEqual(result['files'][0]['status'], 'not-recorded')
                self.assertTrue(result['entries'])
                self.assertTrue(all(entry['md5'] is None for entry in result['entries']))

    def test_malformed_reported_checksum_is_rejected(self):
        image, _ = self.image()
        text = subprocess.check_output([symbols.host_tool('llvm-dwarfdump'), '--debug-line', str(image)], text=True)
        checksum = self.report(image)['entries'][0]['md5']
        with self.assertRaisesRegex(ValueError, 'invalid DWARF source checksum'):
            sources.line_files(text.replace(checksum, 'owned-invalid-checksum'))

    def test_matching_separate_debug_crc_is_required(self):
        image, source = self.image()
        debug = image.parent / '.debug/module.debug'
        debug.parent.mkdir()
        subprocess.run(['objcopy', '--only-keep-debug', str(image), str(debug)], check=True, capture_output=True)
        subprocess.run(['objcopy', '--strip-unneeded', '--add-gnu-debuglink=' + str(debug), str(image)], check=True, capture_output=True)
        matched = self.report(image, [source])
        self.assertEqual(matched['files'][0]['status'], 'matched')
        self.assertEqual(matched['debug_image']['path'], str(debug))
        with debug.open('ab') as file:
            file.write(b'owned-corruption')
        result = self.report(image, [source])
        self.assertEqual(result['status'], 'unavailable')
        self.assertFalse(result['files'])

    def test_listing_never_opens_sources_from_encoded_paths(self):
        image, source = self.image()
        source.unlink()
        os.mkfifo(source)
        with patch.object(sources, 'source_identity', side_effect=AssertionError('implicit source read')):
            result = self.report(image)
        self.assertEqual(result['status'], 'available')
        self.assertFalse(result['files'])
        self.assertEqual(result['entries'][0]['path'], str(source))

    def test_selected_missing_fifo_and_unreferenced_files_have_distinct_states(self):
        image, source = self.image()
        fifo = self.root / 'fifo.c'
        os.mkfifo(fifo)
        other = self.root / 'other.c'
        other.write_text(source.read_text())
        result = self.report(image, [self.root / 'missing.c', fifo, other])
        self.assertEqual([file['status'] for file in result['files']], ['missing', 'invalid', 'not-referenced'])
        self.assertIn('regular file', result['files'][1]['reason'])

    def test_same_basename_is_associated_by_recorded_content(self):
        objects = []
        selected = None
        for name, text in [('first', 'int first(void) { return 1; }'), ('second', 'int main(void) { return 0; }')]:
            root = self.root / name
            root.mkdir()
            source = root / 'shared.c'
            source.write_text(text + '\n')
            obj = root / 'shared.o'
            subprocess.run(['clang', '-g', '-gdwarf-5', '-c', str(source), '-o', str(obj)], check=True, capture_output=True)
            objects.append(str(obj))
            selected = source
        image = self.root / 'module'
        subprocess.run(['clang', *objects, '-o', str(image)], check=True, capture_output=True)
        result = self.report(image, [selected])
        self.assertEqual(len(result['entries']), 2)
        record, = result['files']
        self.assertEqual(record['status'], 'matched')
        self.assertEqual(len(record['candidates']), 2)
        self.assertEqual(len(record['matches']), 1)
        self.assertEqual(result['entries'][record['matches'][0]]['path'], str(selected))

    def test_split_line_table_checksums_do_not_certify_dwo_contents(self):
        image, source = self.image(split=True)
        for path in image.parent.glob('*.dwo'):
            path.unlink()
        result = self.report(image, [source])
        self.assertEqual(result['files'][0]['status'], 'matched')
        self.assertIn('not type/inline', result['scope'])

    def test_large_address_rows_are_streamed_without_exhausting_header_limit(self):
        root = self.root / 'large'
        root.mkdir()
        source = root / 'large.c'
        source.write_text('int main(void) { int n = 1;\n' + ''.join('n += ' + str(i % 19) + ';\n' for i in range(15000)) + 'return n; }\n')
        image = root / 'module'
        subprocess.run(['clang', '-g', '-O0', '-gdwarf-5', str(source), '-o', str(image)], check=True, capture_output=True, timeout=60)
        raw = subprocess.check_output([symbols.host_tool('llvm-dwarfdump'), '--debug-line', str(image)], timeout=20)
        self.assertGreater(len(raw), 1024 * 1024)
        result = self.report(image, [source])
        self.assertEqual(result['files'][0]['status'], 'matched')
        self.assertEqual(len(result['entries']), 1)

    def test_missing_tool_and_bad_flags_are_explicit(self):
        image, source = self.image()
        with patch.object(symbols, 'host_tool', return_value=None):
            result = self.report(image, [source])
        self.assertEqual(result['status'], 'unavailable')
        for options in [{'sources': 'true'}, {'source_files': True}, {'source_files': [False]}, {'source_files': ['x'] * 257}]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                symbols.query(image, **options)

    def test_changed_debug_image_during_inspection_is_rejected(self):
        image, source = self.image()
        original = sources.dump
        def changed(tool, path, deadline, **options):
            text = original(tool, path, deadline, **options)
            with path.open('ab') as file:
                file.write(b'owned-mutation')
            return text
        with patch.object(sources, 'dump', side_effect=changed):
            result = self.report(image, [source])
        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('changed', result['reason'])
        self.assertFalse(result['files'])

    def test_source_report_is_bound_to_the_queried_image_hash(self):
        image, source = self.image()
        original = sources.inspect_sources
        def changed(*arguments, **options):
            with image.open('ab') as file:
                file.write(b'owned-change-after-identity')
            return original(*arguments, **options)
        with patch.object(sources, 'inspect_sources', side_effect=changed):
            result = self.report(image, [source])
        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('image changed', result['reason'])
        self.assertFalse(result['files'])

    def test_cli_and_backend_agree_and_recover_after_invalid_source_flags(self):
        image, source = self.image()
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        cli = subprocess.run([*command, 'symbols', str(image), '--sources', '--source-file', str(source)], capture_output=True, text=True, timeout=25)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        expected = json.loads(cli.stdout)['data']
        requests = [(1, 'initialize', {'schema': 1}), (2, 'symbols', {'path': str(image), 'sources': True, 'source_files': [str(source)]}),
                    (3, 'symbols', {'path': str(image), 'sources': 'invalid'}),
                    (4, 'symbols', {'path': str(image), 'sources': True, 'source_files': [str(source)]}), (5, 'shutdown', {})]
        stream = io.BytesIO()
        for i, method, params in requests:
            write_message(stream, dict(id=i, method=method, params=params))
        process = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        stream = io.BytesIO(process.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertEqual(replies[1]['result'], expected)
        self.assertEqual(replies[3]['result'], expected)
        self.assertEqual(replies[2]['error']['code'], -32602)


if __name__ == '__main__':
    unittest.main()
