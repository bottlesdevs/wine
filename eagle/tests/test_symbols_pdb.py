import hashlib
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


PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
sys.path.insert(0, str(PACKAGE))
import symbols
from protocol import read_message, write_message


class PdbSymbols(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        symbolizer = symbols.pdb_resolver()
        suffix = Path(symbolizer).name.removeprefix('llvm-symbolizer') if symbolizer else ''
        cls.linker = shutil.which(os.environ.get('EAGLE_TEST_LLD_LINK', 'lld-link')) or shutil.which('lld-link' + suffix)
        if not shutil.which('clang-cl') or not cls.linker or not symbolizer:
            raise unittest.SkipTest('PDB source fixtures require clang-cl, lld-link and llvm-symbolizer')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def build(self, name, target='x86_64', pdb_path='fixture.pdb', constant=7):
        root = self.root / name
        root.mkdir()
        source = root / 'Eagle Fixture.c'
        source.write_text('__declspec(noinline) int eagle_pdb_fixture(int value)\n{\n    return value + ' + str(constant) + ';\n}\nint entry(void) { return eagle_pdb_fixture(1); }\n')
        image, pdb, obj = [root / filename for filename in ('fixture.exe', 'fixture.pdb', 'fixture.obj')]
        subprocess.run(['clang-cl', '--target=' + target + '-pc-windows-msvc', '/nologo', '/Od', '/Z7',
                        '/c', str(source), '/Fo' + str(obj)], check=True, capture_output=True, timeout=20)
        subprocess.run([self.linker, '/nologo', '/entry:entry', '/subsystem:console', '/nodefaultlib', '/debug',
                        '/pdb:' + str(pdb), '/pdbaltpath:' + pdb_path, '/out:' + str(image), str(obj)],
                       check=True, capture_output=True, timeout=20)
        return image, pdb, source

    def cli(self, image, pdb, *rvas):
        arguments = [value for rva in rvas for value in ('--rva', rva)]
        return subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'symbols', str(image),
                               '--pdb', str(pdb), *arguments], capture_output=True, text=True, timeout=10)

    def test_source_lines_on_all_static_pe_architectures(self):
        for target in ('i686', 'x86_64', 'aarch64'):
            with self.subTest(target=target):
                image, pdb, source = self.build(target, target)
                result = self.cli(image, pdb, '0x1000', '0')
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads(result.stdout)['data']
                self.assertTrue(data['pdb_matches'])
                frame, unknown = data['resolved']
                self.assertEqual(frame['symbol'], 'eagle_pdb_fixture')
                self.assertEqual(frame['file'], str(source))
                self.assertEqual(frame['line'], 2)
                self.assertEqual(frame['status'], 'source-resolved')
                self.assertEqual(frame['resolver'], 'llvm-matched-pdb')
                self.assertEqual(unknown['status'], 'unresolved')

    def test_selected_relocated_pdb_overrides_adjacent_wrong_file(self):
        for path in ('fixture.pdb', r'C:\unavailable\debug\fixture.pdb', '/unavailable/debug/fixture.pdb', 'module-0.exe'):
            with self.subTest(path=path):
                image, pdb, source = self.build(str(len(list(self.root.iterdir()))), pdb_path=path)
                moved = image.parent / 'Selected Symbols.pdb'
                pdb.rename(moved)
                other, wrong, _ = self.build('other-' + image.parent.name, constant=23)
                shutil.copyfile(wrong, pdb)
                before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (image, moved, pdb)}
                result = self.cli(image, moved, '0x1000')
                self.assertEqual(result.returncode, 0, result.stderr)
                frame, = json.loads(result.stdout)['data']['resolved']
                self.assertEqual((frame['file'], frame['line']), (str(source), 2))
                self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before})

    def test_mismatch_is_rejected_before_running_resolver(self):
        image, pdb, _ = self.build('target')
        _, other, _ = self.build('other', constant=23)
        original = pdb.read_bytes()
        guid = symbols.pdb_identity(pdb)['guid']
        import uuid
        offset = original.index(uuid.UUID(guid).bytes_le)
        age = bytearray(original)
        age[offset - 4:offset] = (2).to_bytes(4, 'little')
        for content in (other.read_bytes(), bytes(age), b'truncated'):
            with self.subTest(size=len(content)):
                pdb.write_bytes(content)
                with patch('symbols.resolve_pdb', side_effect=AssertionError('resolver must not run'), create=True):
                    with self.assertRaises(ValueError):
                        symbols.query(image, pdb=pdb, rvas=['0x1000'])
        pdb.write_bytes(original)

    def test_identity_and_empty_query_do_not_require_llvm(self):
        image, pdb, _ = self.build('identity')
        with patch('symbols.pdb_resolver', return_value=None):
            result = symbols.query(image, pdb=pdb)
            self.assertTrue(result['pdb_matches'])
            self.assertNotIn('resolved', result)
            self.assertEqual(symbols.query(image, pdb=pdb, rvas=[]), dict(result, resolved=[]))
            with self.assertRaisesRegex(ValueError, 'PDB source resolver unavailable'):
                symbols.query(image, pdb=pdb, rvas=['0x1000'])
        empty = self.root / 'empty-path'
        empty.mkdir()
        with patch.dict(os.environ, PATH=str(empty)):
            result = self.cli(image, pdb, '0x1000')
        self.assertEqual(result.returncode, 1)
        self.assertIn('PDB source resolver unavailable', json.loads(result.stderr)['error'])

    def test_versioned_resolver_discovery_uses_executable_numeric_suffixes(self):
        for name in ('llvm-symbolizer-18', 'llvm-symbolizer-21', 'llvm-symbolizer-999-backup'):
            (self.root / name).symlink_to(sys.executable)
        (self.root / 'llvm-symbolizer-99').write_text('not executable')
        with patch('symbols.shutil.which', return_value=None), patch('symbols.os.get_exec_path', return_value=[str(self.root)]):
            self.assertEqual(symbols.pdb_resolver(), str(self.root / 'llvm-symbolizer-21'))

    def test_ambiguous_image_identities_do_not_reach_the_resolver(self):
        image, pdb, _ = self.build('ambiguous')
        from session import identity
        metadata = identity(image)
        metadata['codeview'].append(dict(metadata['codeview'][0], age=2))
        with patch('session.identity', return_value=metadata), patch('symbols.resolve_pdb', side_effect=AssertionError('resolver must not run')):
            with self.assertRaisesRegex(ValueError, 'ambiguous PDB identities'):
                symbols.query(image, pdb=pdb, rvas=['0x1000'])

    def test_bad_resolver_output_and_failure_leave_no_staging_files(self):
        image, pdb, _ = self.build('failure')
        staging = self.root / 'staging'
        staging.mkdir()
        directory = tempfile.TemporaryDirectory
        with patch('symbols.tempfile.TemporaryDirectory', side_effect=lambda **options: directory(dir=staging, **options)):
            for code, output in ((1, ''), (0, '{}'), (0, 'not-json'), (0, '[]')):
                with self.subTest(code=code, output=output):
                    with patch('symbols.subprocess.run', return_value=subprocess.CompletedProcess([], code, output, 'failure')):
                        with self.assertRaisesRegex(ValueError, 'PDB source resolver failed'):
                            symbols.resolve_pdb(image, pdb, ['fixture.pdb'], ['0x1000'])
                    self.assertEqual(list(staging.iterdir()), [])
            with patch('symbols.subprocess.run', side_effect=subprocess.TimeoutExpired('llvm-symbolizer', 10)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    symbols.resolve_pdb(image, pdb, ['fixture.pdb'], ['0x1000'])
            self.assertEqual(list(staging.iterdir()), [])

    def test_stdio_matches_cli_and_recovers_after_a_mismatch(self):
        image, pdb, _ = self.build('backend')
        _, wrong, _ = self.build('other', constant=23)
        expected = self.cli(image, pdb, '0x1000')
        self.assertEqual(expected.returncode, 0, expected.stderr)
        requests = [(1, 'initialize', {'schema': 1}),
                    (2, 'symbols', {'path': str(image), 'pdb': str(pdb), 'rvas': ['0x1000']}),
                    (3, 'symbols', {'path': str(image), 'pdb': str(wrong), 'rvas': ['0x1000']}),
                    (4, 'capabilities', {}), (5, 'shutdown', {})]
        stream = io.BytesIO()
        for request_id, method, params in requests:
            write_message(stream, dict(id=request_id, method=method, params=params))
        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'serve'],
                                input=stream.getvalue(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        messages = io.BytesIO(result.stdout)
        responses = [read_message(messages) for _ in requests]
        self.assertEqual([item['id'] for item in responses], list(range(1, 6)))
        self.assertEqual(responses[1]['result'], json.loads(expected.stdout)['data'])
        self.assertEqual(responses[2]['error']['code'], -32602)
        self.assertIn('llvm-symbolizer', responses[3]['result']['symbol_queries']['pdb'])
        self.assertIsNone(responses[4]['result'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
