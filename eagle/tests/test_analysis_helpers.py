import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import tempfile
import unittest


NATIVE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle/native'


class AnalysisHelpers(unittest.TestCase):
    def analysis(self, **request):
        result = subprocess.run([str(NATIVE / 'eagle-analysis')], input=json.dumps(request), capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_hashes_and_steam_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'app.exe'
            target.write_bytes(b'Example\0application')
            imports = 'kernel32.createfilew'
            result = self.analysis(operation='artifact-hashes', path=str(target), imports=imports)
            self.assertEqual(result, {'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'imphash': hashlib.md5(imports.encode()).hexdigest()})
            (root / 'steam_appid.txt').write_text('1234\n')
            self.assertEqual(self.analysis(operation='steam-appid', path=str(target)), '1234')

    def test_directory_discovery_and_asar(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'app.exe'
            target.write_bytes(b'fixture')
            (root / 'app.runtimeconfig.json').write_text('{}')
            details = {name: [] for name in ('Runtimes', 'Engines', 'Frameworks', 'Analysed Files')}
            result = self.analysis(operation='discover', path=str(target), details=details)
            self.assertIn('.NET Core/5+', result['details']['Runtimes'])
            self.assertIn('app.runtimeconfig.json', result['details']['Analysed Files'])
            payload = b'console.log("example");'
            header = json.dumps({'files': {'app.js': {'offset': '0', 'size': len(payload)}}}).encode()
            archive = root / 'app.asar'
            archive.write_bytes(struct.pack('<4I', 0, 0, 0, len(header)) + header + payload)
            output = root / 'extracted'
            output.mkdir(mode=0o700)
            self.assertEqual(self.analysis(operation='asar', path=str(archive), output=str(output)), [str(output / 'app.js')])
            self.assertEqual((output / 'app.js').read_bytes(), payload)

    def test_empty_suggestions_and_rule_results(self):
        self.assertEqual(self.analysis(operation='merge', suggestions=[], intel=None), [])
        details = {name: [] for name in ('Graphics', 'Upscaling', 'Engines', 'Runtimes', 'Physics', 'Protection', 'Frameworks', 'Warning')}
        advice = self.analysis(operation='recommend', details=details, metadata={'is_packed': False}, is_net=False, dpi_aware=True, ue_shipping_exe=None, intel=None)
        self.assertEqual(advice['suggestions'], [])
        self.assertEqual(advice['frameworks'], [])
        result = self.analysis(operation='yara-insights', matches=[], details=details, source='Main Executable')
        self.assertEqual(result['matches'], [])
        self.assertEqual(result['details'], details)

    def test_pe_interpretation_keeps_architecture_and_dependencies(self):
        details = {name: [] for name in ('Graphics', 'Runtimes', 'Warning')}
        structure = dict(machine=0x8664, min_os='10.0', timestamp=0,
                         characteristics=0, dll_characteristics=0x140,
                         rich_products=[], sections=[], manifests=[],
                         imports=[{'name': 'D3D11.DLL'}], managed=False,
                         version={'CompanyName': 'Example', 'ProductName': ''})
        result = self.analysis(operation='pe-insights', structure=structure,
                               details=details, metadata={}, basename='app.exe',
                               compilers={}, packers={}, mapping={'d3d11.dll': ['DirectX 11', 'Graphics']})
        self.assertEqual(result['arch'], 'x86_64 (64-bit)')
        self.assertEqual(result['publisher'], 'Example')
        self.assertEqual(result['product_name'], 'app.exe')
        self.assertTrue(result['metadata']['dep_enabled'])
        self.assertTrue(result['metadata']['aslr_enabled'])
        self.assertEqual(result['details']['Graphics'], [{'name': 'DirectX 11', 'source': 'Imports'}])

    def test_database_status_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'intel.sqlite'
            with sqlite3.connect(path) as connection:
                connection.execute('CREATE TABLE meta (key TEXT, value TEXT)')
                connection.execute("INSERT INTO meta VALUES ('schema_version', '1')")
                for table in ('artifact', 'report_agg', 'software', 'trick', 'tweak'):
                    connection.execute('CREATE TABLE ' + table + ' (id INTEGER)')
            before = path.read_bytes()
            result = subprocess.run([str(NATIVE / 'eagle-intel'), str(path)], input='{"operation":"status"}', capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {'available': True, 'has_artifacts': False, 'schema_version': '1'})
            self.assertEqual(path.read_bytes(), before)

    def test_invalid_requests_return_errors(self):
        for request in ('[]', '{}', '{', '{"operation":"unknown"}', '{"operation":"merge","suggestions":{}}'):
            with self.subTest(request=request):
                result = subprocess.run([str(NATIVE / 'eagle-analysis')], input=request, capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertTrue(result.stderr.strip())


if __name__ == '__main__':
    unittest.main(verbosity=2)
