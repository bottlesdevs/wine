import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'


class AnalysisDriver(unittest.TestCase):
    def invoke(self, request, driver=None):
        result = subprocess.run([str(driver or PACKAGE / 'native/eagle-driver')], input=json.dumps(request), capture_output=True, text=True, timeout=10)
        return result, [json.loads(line) for line in result.stdout.splitlines()]

    def test_invalid_request_and_nonregular_inputs_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / 'target.fifo'
            os.mkfifo(fifo)
            for request in ([], {}, {'target': str(fifo)}, {'target': str(root)}):
                with self.subTest(request=request):
                    result, messages = self.invoke(request)
                    self.assertEqual(result.returncode, 1)
                    self.assertFalse(messages[-1]['status'])

    def test_configuration_and_scan_limits_are_checked_before_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target.exe'
            target.write_bytes(b'fixture')
            fifo = root / 'config.fifo'
            os.mkfifo(fifo)
            for request in ({'target': str(target), 'scan_limit': 0},
                            {'target': str(target), 'scan_limit': 10001},
                            {'target': str(target), 'scan_limit': True},
                            {'target': str(target), 'config': str(fifo)}):
                with self.subTest(request=request):
                    result, messages = self.invoke(request)
                    self.assertEqual(result.returncode, 1)
                    self.assertFalse(messages[-1]['status'])

    def test_real_pe_pipeline_with_empty_pattern_scanner_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / 'native'
            native.mkdir()
            for name in ('eagle-driver', 'eagle-pe', 'eagle-analysis', 'eagle-intel'):
                shutil.copyfile(PACKAGE / 'native' / name, native / name)
                (native / name).chmod(0o755)
            shutil.copyfile(PACKAGE / 'analysis.json', root / 'analysis.json')
            scanner = native / 'eagle-yara'
            scanner.write_text('#!' + sys.executable + '\nprint(\'{"matches":[]}\')\n')
            scanner.chmod(0o755)
            source = root / 'main.c'
            source.write_text('int main(void) { return 0; }\n')
            for compiler, architecture in (('i686', 'x86 (32-bit)'), ('x86_64', 'x86_64 (64-bit)')):
                with self.subTest(compiler=compiler):
                    app = root / compiler
                    app.mkdir()
                    target = app / 'app.exe'
                    subprocess.run([compiler + '-w64-mingw32-gcc', str(source), '-o', str(target)], check=True, capture_output=True)
                    result, messages = self.invoke({'target': str(target), 'database': str(root / 'missing.sqlite')}, native / 'eagle-driver')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(messages[-1]['status'])
                    self.assertEqual(messages[-1]['data']['arch'], architecture)
                    self.assertEqual(messages[-1]['data']['details']['Analysed Files'], ['app.exe'])
                    self.assertEqual(messages[0], {'event': 'step', 'data': 'Initialising Eagle...'})
                    self.assertEqual(messages[-2], {'event': 'step', 'data': 'Analysis complete.'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
