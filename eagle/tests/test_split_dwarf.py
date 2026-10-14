import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
sys.path.insert(0, str(PACKAGE))
import symbols
from protocol import read_message, write_message


class SplitDwarf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dumper = shutil.which(os.environ.get('EAGLE_TEST_DWARFDUMP', 'llvm-dwarfdump'))
        cls.packager = shutil.which(os.environ.get('EAGLE_TEST_DWP', 'llvm-dwp'))
        if not cls.dumper or not cls.packager or not shutil.which('gcc'):
            raise unittest.SkipTest('split-DWARF fixtures require gcc, llvm-dwarfdump and llvm-dwp')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def build(self, name, version=5):
        root = self.root / name
        root.mkdir()
        source = root / 'fixture.c'
        source.write_text('int eagle_split(int value)\n{\n return value + 7;\n}\nint main(void) { return eagle_split(1); }\n')
        image = root / 'fixture'
        subprocess.run(['gcc', '-O0', '-g', '-gdwarf-' + str(version), '-gsplit-dwarf', '-fno-pie',
                        '-no-pie', str(source), '-o', str(image)], check=True, capture_output=True, timeout=20)
        return image, root / 'fixture.dwo', source

    def cli(self, image, *args):
        return subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'symbols', str(image), *args],
                              capture_output=True, text=True, timeout=25)

    def report(self, image, *args):
        result = self.cli(image, '--artifacts', *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)['data']['split_dwarf']

    def test_dwarf4_and5_companions_match_the_skeleton_identity(self):
        for version in (4, 5):
            with self.subTest(version=version):
                image, dwo, _ = self.build(str(version), version)
                report = self.report(image)
                self.assertEqual(report['status'], 'matched')
                unit, = report['units']
                self.assertRegex(unit['dwo_id'], r'^0x[0-9a-f]{16}$')
                self.assertEqual(unit['name'], str(dwo))
                self.assertEqual(unit['status'], 'matched')
                file = report['files'][unit['matches'][0]]
                self.assertEqual(file['dwo_ids'], [unit['dwo_id']])
                self.assertRegex(file['sha256'], r'^[0-9a-f]{64}$')

    def test_missing_wrong_and_truncated_companions_remain_distinct(self):
        for version in (4, 5):
            with self.subTest(version=version):
                image, dwo, _ = self.build('target-' + str(version), version)
                _, wrong, _ = self.build('other-' + str(version), version)
                original = dwo.read_bytes()
                for state, content in [('missing', None), ('mismatched', wrong.read_bytes()), ('invalid', b'truncated')]:
                    dwo.unlink(missing_ok=True)
                    if content is not None:
                        dwo.write_bytes(content)
                    report = self.report(image)
                    self.assertEqual(report['status'], 'incomplete')
                    self.assertEqual(report['units'][0]['status'], state)
                dwo.write_bytes(original)

    def test_dwp4_and5_indexes_supply_missing_dwo_units(self):
        for version in (4, 5):
            with self.subTest(version=version):
                image, dwo, _ = self.build(str(version), version)
                package = Path(str(image) + '.dwp')
                subprocess.run([self.packager, str(dwo), '-o', str(package)], check=True, capture_output=True, timeout=10)
                dwo.unlink()
                report = self.report(image)
                self.assertEqual(report['status'], 'matched')
                unit, = report['units']
                self.assertEqual(report['files'][unit['matches'][0]]['path'], str(package))
                moved = image.parent / 'Selected Symbols.dwp'
                package.rename(moved)
                self.assertEqual(self.report(image)['status'], 'incomplete')
                self.assertEqual(self.report(image, '--debug-file', str(moved))['status'], 'matched')

    def test_missing_dwo_does_not_discard_valid_skeleton_lines(self):
        image, dwo, source = self.build('source')
        listing = subprocess.check_output(['nm', '-n', str(image)], text=True)
        address = int(next(line.split()[0] for line in listing.splitlines() if line.endswith(' eagle_split')), 16)
        from session import identity
        rva = hex(address - int(identity(image)['image_base'], 0))
        dwo.unlink()
        result = self.cli(image, '--artifacts', '--rva', rva)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)['data']
        self.assertEqual(data['split_dwarf']['status'], 'incomplete')
        frame, = data['resolved']
        self.assertEqual((frame['file'], frame['line'], frame['status']), (str(source), 2, 'source-resolved'))

    def test_unrelated_units_do_not_turn_a_missing_file_into_a_mismatch(self):
        root = self.root / 'multi'
        root.mkdir()
        for name, content in [('first', 'int first(void) { return 7; }\n'),
                              ('second', 'int first(void); int main(void) { return first(); }\n')]:
            source = root / (name + '.c')
            source.write_text(content)
            subprocess.run(['gcc', '-O0', '-g', '-gdwarf-5', '-gsplit-dwarf', '-c', str(source),
                            '-o', str(root / (name + '.o'))], check=True, capture_output=True, timeout=20)
        image = root / 'fixture'
        subprocess.run(['gcc', str(root / 'first.o'), str(root / 'second.o'), '-o', str(image)],
                       check=True, capture_output=True, timeout=20)
        (root / 'first.dwo').unlink()
        report = self.report(image)
        self.assertEqual(report['status'], 'incomplete')
        self.assertEqual([unit['status'] for unit in report['units']], ['missing', 'matched'])

    def test_a_skeleton_does_not_count_as_its_own_debug_companion(self):
        for version in (4, 5):
            with self.subTest(version=version):
                image, dwo, _ = self.build(str(version), version)
                dwo.unlink()
                report = self.report(image, '--debug-file', str(image))
                self.assertEqual(report['status'], 'incomplete')
                self.assertEqual(report['units'][0]['matches'], [])
                self.assertEqual(report['files'][0]['status'], 'invalid')

    def test_unavailable_tool_and_nonregular_companions_are_explicit(self):
        image, dwo, _ = self.build('limits')
        with patch('symbols.host_tool', return_value=None, create=True):
            result = symbols.query(image, artifacts=True)
        self.assertEqual(result['split_dwarf']['status'], 'unavailable')
        from dwarf import companion
        fifo = self.root / 'pipe.dwo'
        os.mkfifo(fifo)
        with patch('dwarf.dump', side_effect=AssertionError('nonregular file reached tool')):
            for path in (fifo, self.root):
                report = companion(self.dumper, path, time.monotonic() + 2)
                self.assertEqual(report['status'], 'invalid')
                self.assertIn('regular file', report['reason'])

    def test_a_companion_changed_during_inspection_is_not_accepted(self):
        _, dwo, _ = self.build('changed')
        from dwarf import companion, dump
        def change(tool, path, deadline):
            text = dump(tool, path, deadline)
            path.write_bytes(path.read_bytes() + b'\0')
            return text
        with patch('dwarf.dump', side_effect=change):
            report = companion(self.dumper, dwo, time.monotonic() + 5)
        self.assertEqual(report['status'], 'invalid')
        self.assertIn('changed during inspection', report['reason'])

    def test_tool_output_and_time_are_bounded(self):
        from dwarf import dump
        tool = self.root / 'fixture-tool'
        tool.write_text('#!' + sys.executable + '\nimport sys\nsys.stdout.buffer.write(b"x" * (2 * 1024 * 1024))\n')
        tool.chmod(0o700)
        with self.assertRaisesRegex(ValueError, 'output exceeds limit'):
            dump(str(tool), self.root, time.monotonic() + 5)
        tool.write_text('#!' + sys.executable + '\nimport time\ntime.sleep(10)\n')
        with self.assertRaisesRegex(ValueError, 'timed out'):
            dump(str(tool), self.root, time.monotonic() + 0.1)

    def test_stdio_matches_cli_and_recovers_after_invalid_options(self):
        image, _, _ = self.build('backend')
        expected = json.loads(self.cli(image, '--artifacts').stdout)['data']
        requests = [(1, 'initialize', {'schema': 1}),
                    (2, 'symbols', {'path': str(image), 'artifacts': True}),
                    (3, 'symbols', {'path': str(image), 'debug_files': [False]}),
                    (4, 'symbols', {'path': str(image), 'artifacts': 1}),
                    (5, 'capabilities', {}), (6, 'shutdown', {})]
        stream = io.BytesIO()
        for request_id, method, params in requests:
            write_message(stream, dict(id=request_id, method=method, params=params))
        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'serve'],
                                input=stream.getvalue(), capture_output=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stderr)
        messages = io.BytesIO(result.stdout)
        responses = [read_message(messages) for _ in requests]
        self.assertEqual([item['id'] for item in responses], list(range(1, 7)))
        self.assertEqual(responses[1]['result'], expected)
        self.assertTrue(all(item['error']['code'] == -32602 for item in responses[2:4]))
        self.assertEqual(responses[4]['result']['split_dwarf']['maximum_units'], 256)
        self.assertIsNone(responses[5]['result'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
