import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'


class AnalysisDriver(unittest.TestCase):
    def invoke(self, request, driver=None, env=None):
        result = subprocess.run([str(driver or PACKAGE / 'native/eagle-driver')], input=json.dumps(request), capture_output=True, text=True, timeout=10, env=env)
        return result, [json.loads(line) for line in result.stdout.splitlines()]

    def package(self, root):
        native = root / 'native'
        native.mkdir()
        for name in ('eagle-driver', 'eagle-pe', 'eagle-analysis', 'eagle-intel'):
            shutil.copyfile(PACKAGE / 'native' / name, native / name)
            (native / name).chmod(0o755)
        shutil.copyfile(PACKAGE / 'analysis.json', root / 'analysis.json')
        scanner = native / 'eagle-yara'
        scanner.write_text('#!' + sys.executable + '\nprint(\'{"matches":[]}\')\n')
        scanner.chmod(0o755)
        return native

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
            native = self.package(root)
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

    def test_msi_external_fallback_fixture_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = self.package(root)
            modules = root / 'modules'
            modules.mkdir()
            (modules / 'patoolib.py').write_text('import zipfile\n'
                'def extract_archive(path, outdir, verbosity):\n'
                '    with zipfile.ZipFile(path) as archive:\n'
                '        archive.extractall(outdir)\n')
            work = root / 'work'
            work.mkdir()
            env = dict(os.environ, PATH=str(root / 'no-tools'), PYTHONPATH=str(modules))
            target = root / 'package.msi'
            with zipfile.ZipFile(target, 'w') as archive:
                archive.writestr('first.exe', b'fixture')
                archive.writestr('second.dll', b'fixture')
            request = dict(target=str(target), work=str(work), scan_limit=1,
                           extractor_python=sys.executable, database=str(root / 'missing.sqlite'))
            result, messages = self.invoke(request, native / 'eagle-driver', env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(messages[-1]['data']['details']['Analysed Files'], ['package.msi'])
            self.assertNotIn('messages', messages[-1]['data'])
            self.assertIn({'event': 'step', 'data': '[1/1] Scanning: first.exe'}, messages)
            self.assertEqual(list(work.iterdir()), [])
            target.write_bytes(b'invalid archive')
            result, messages = self.invoke(request, native / 'eagle-driver', env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn({'event': 'step', 'data': 'Extraction skipped (not supported)'}, messages)
            self.assertEqual(list(work.iterdir()), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
