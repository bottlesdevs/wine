import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile

from test_imports import image


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

    @unittest.skipUnless(shutil.which('wixl') and shutil.which('7z'), 'wixl and 7z required')
    def test_real_msi_file_ids_without_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = self.package(root)
            source = root / 'main.c'
            source.write_text('int main(void) { return 0; }\n')
            (root / 'note.txt').write_text('Not an executable')
            wix = root / 'package.wxs'
            wix.write_text('<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">'
                '<Product Id="*" Name="Fixture" Language="1033" Version="1.0.0" Manufacturer="Example" '
                'UpgradeCode="115D7030-2F9F-4F82-AB60-AD34E63B86D8">'
                '<Package InstallerVersion="200" Compressed="yes"/>'
                '<Media Id="1" Cabinet="payload.cab" EmbedCab="yes"/>'
                '<Directory Id="TARGETDIR" Name="SourceDir"><Directory Id="ProgramFilesFolder">'
                '<Directory Id="INSTALLDIR" Name="Fixture"><Component Id="Main" Guid="*">'
                '<File Id="App" Source="sample.exe" KeyPath="yes"/><File Id="Note" Source="note.txt"/>'
                '</Component></Directory></Directory></Directory>'
                '<Feature Id="MainFeature" Level="1"><ComponentRef Id="Main"/></Feature></Product></Wix>')
            work = root / 'work'
            work.mkdir()
            target = root / 'package.msi'
            for architecture in ('i686', 'x86_64'):
                with self.subTest(architecture=architecture):
                    subprocess.run([architecture + '-w64-mingw32-gcc', str(source), '-o', str(root / 'sample.exe')], check=True, capture_output=True)
                    subprocess.run(['wixl', '-o', str(target), str(wix)], cwd=root, check=True, capture_output=True)
                    result, messages = self.invoke(dict(target=str(target), work=str(work), database=str(root / 'missing.sqlite')), native / 'eagle-driver')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn({'event': 'step', 'data': 'Found 1 binaries in installer'}, messages)
                    self.assertIn({'event': 'step', 'data': '[1/1] Scanning: App'}, messages)
                    self.assertTrue(messages[-1]['status'])
                    self.assertEqual(list(work.iterdir()), [])

    @unittest.skipUnless(shutil.which('makensis') and shutil.which('7z') and (PACKAGE / 'native/eagle-yara').is_file(), 'NSIS, 7z and YARA helper required')
    def test_nsis_member_extension_case(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'main.c'
            source.write_text('int main(void) { return 0; }\n')
            payload = root / 'payload.exe'
            subprocess.run(['x86_64-w64-mingw32-gcc', str(source), '-o', str(payload)], check=True, capture_output=True)
            work = root / 'work'
            work.mkdir()
            target = root / 'package.exe'
            script = root / 'package.nsi'
            for member in ('app.exe', 'APP.EXE', 'App.ExE', 'Library.DlL'):
                with self.subTest(member=member):
                    script.write_text(f'Name "Fixture"\nOutFile "{target}"\nSection\nSetOutPath "$INSTDIR"\n'
                        f'File /oname={member} "{payload}"\nFile /oname=Support.DlL "{payload}"\nSectionEnd\n')
                    subprocess.run(['makensis', '-V2', str(script)], check=True, capture_output=True)
                    result, messages = self.invoke(dict(target=str(target), work=str(work), database=str(root / 'missing.sqlite')))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn({'event': 'step', 'data': 'Found 2 binaries in installer'}, messages)
                    scans = [message['data'] for message in messages
                             if message.get('event') == 'step' and '] Scanning: ' in message['data']]
                    names = [step.split('] Scanning: ', 1)[1] for step in scans]
                    self.assertCountEqual(names, [member, 'Support.DlL'])
                    self.assertEqual(scans, [f'[{index}/2] Scanning: {name}' for index, name in enumerate(names, 1)])
                    if member.lower().endswith('.exe'):
                        self.assertEqual(names[0], member)
                    self.assertTrue(messages[-1]['status'])
                    self.assertEqual(messages[-1]['data']['details']['Analysed Files'], ['package.exe', *names])
                    self.assertEqual(list(work.iterdir()), [])

    def test_incomplete_intel_database_keeps_no_match_progress(self):
        for missing in ('name', 'imphash'):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                native = self.package(root)
                target = root / 'app.exe'
                target.write_bytes(image('unknown.dll', 0x8664))
                database = root / 'intel.sqlite'
                with sqlite3.connect(database) as connection:
                    connection.executescript("""
                        CREATE TABLE meta (key TEXT, value TEXT);
                        INSERT INTO meta VALUES ('schema_version', '1');
                        CREATE TABLE artifact (software_id INTEGER, sha256 TEXT, imphash TEXT);
                        CREATE TABLE software (id INTEGER, name TEXT, steam_appid TEXT,
                                               trick_name TEXT, source TEXT);
                        INSERT INTO software VALUES (1, 'Example', NULL, NULL, 'protondb');
                        CREATE TABLE report_agg (software_id INTEGER, reports INTEGER,
                            verdict_yes INTEGER, verdict_no INTEGER, tinkered INTEGER, tier TEXT);
                        INSERT INTO report_agg VALUES (1, 50, 50, 0, 0, 'gold');
                        CREATE TABLE tweak (software_id INTEGER, kind TEXT, value TEXT, evidence INTEGER);
                        CREATE TABLE trick (id INTEGER);
                    """)
                    connection.execute('INSERT INTO artifact VALUES (1, ?, ?)',
                                       (hashlib.sha256(target.read_bytes()).hexdigest(), 'other'))
                    table = 'software' if missing == 'name' else 'artifact'
                    connection.execute('ALTER TABLE ' + table + ' DROP COLUMN ' + missing)
                result, messages = self.invoke(dict(target=str(target), database=str(database)),
                                               native / 'eagle-driver')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(messages[-1]['status'])
                self.assertIsNone(messages[-1]['data']['intel'])
                self.assertIn({'event': 'step', 'data': 'No community intelligence match'}, messages)


if __name__ == '__main__':
    unittest.main(verbosity=2)
