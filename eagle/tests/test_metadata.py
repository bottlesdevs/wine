import json
import os
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest

from test_imports import image


ROOT = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
CONFIG = json.loads((ROOT / 'analysis.json').read_text())


class MetadataTests(unittest.TestCase):
    def test_section_names_ignore_invalid_utf8_and_strip_only_edge_nulls(self):
        names = [b'\xffUPX0\0\0\0', b'\0UPX0\0\0\0', b'UPX0\0XYZ',
                 b'UPX0\0\0\0\0', b'12345678', b'\xc3\xa9UPX0\0\0',
                 b'\xed\xa0\x80UPX0\0', b'UPX0\xf0\x90\x80\0',
                 b'\0\0\0\0\0\0\0\0', b'\xf4\x8f\xbf\xbf\0\0\0\0']
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'app.exe'
            for machine in (0x14c, 0x8664, 0xaa64):
                for name in names:
                    with self.subTest(machine=machine, name=name):
                        data = bytearray(image('unknown.dll', machine))
                        offset = 0x98 + (224 if machine == 0x14c else 240)
                        data[offset:offset + 8] = name
                        target.write_bytes(data)
                        result = subprocess.run([str(ROOT / 'native/eagle-pe'), str(target)],
                                                capture_output=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        report = json.loads(result.stdout)
                        self.assertEqual(report['sections'][0]['name'],
                                         name.decode('utf-8', errors='ignore').strip('\0'))
                        result = self.invoke([], sections=report['sections'])
                        self.assertEqual(result.returncode, 0, result.stderr)
                        expected = next((CONFIG['packers'][entry['name']] for entry in report['sections']
                                         if entry['name'] in CONFIG['packers']), None)
                        self.assertEqual(json.loads(result.stdout)['metadata'].get('packer'), expected)

    def invoke(self, tables, flat=None, sections=None, machine=0x8664, **fields):
        structure = dict(machine=machine, min_os='10.0', timestamp=0,
                         characteristics=0, dll_characteristics=0, rich_products=[],
                         sections=sections or [], manifests=[], imports=[], managed=False,
                         version=flat or {}, version_tables=tables)
        structure.update(fields)
        request = dict(operation='pe-insights', structure=structure,
                       details={'Warning': [], 'Runtimes': []}, metadata={}, basename='app.exe',
                       compilers=CONFIG['compilers'], packers=CONFIG['packers'], mapping=CONFIG['mapping'])
        return subprocess.run([str(ROOT / 'native/eagle-analysis')], input=json.dumps(request),
                              capture_output=True, text=True, timeout=5)

    def test_rich_records_describe_tools_without_guessing_visual_studio(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'app.exe'
            for machine in (0x14c, 0x8664, 0xaa64):
                for product, count, detected in ((0x104, 42, True), (0x9999, 0x1040000, False)):
                    with self.subTest(machine=machine, product=product):
                        data = bytearray(image('unknown.dll', machine))
                        pe = struct.unpack_from('<I', data, 0x3c)[0]
                        optional = pe + 24
                        table = optional + struct.unpack_from('<H', data, pe + 20)[0]
                        end = table + 40 * struct.unpack_from('<H', data, pe + 6)[0]
                        self.assertLessEqual(end + 32, struct.unpack_from('<I', data, optional + 60)[0])
                        data[pe + 32:end + 32] = bytes(data[pe:end])
                        struct.pack_into('<I', data, 0x3c, pe + 32)
                        key = 0x12345678
                        data[0x80:0xa0] = struct.pack('<8I', 0x536e6144 ^ key, key, key, key,
                            ((product << 16) | 35229) ^ key, count ^ key, 0x68636952, key)
                        optional = struct.unpack_from('<I', data, 0x3c)[0] + 24
                        data[optional + 2:optional + 4] = bytes((14, 44))
                        target.write_bytes(data)
                        result = subprocess.run([str(ROOT / 'native/eagle-pe'), str(target)],
                                                capture_output=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        header = json.loads(result.stdout)
                        self.assertEqual(header['rich_products'], [product])
                        self.assertEqual(header['linker_version'], '14.44')
                        result = self.invoke([], machine=machine, rich_products=header['rich_products'],
                                             linker_version=header['linker_version'])
                        self.assertEqual(result.returncode, 0, result.stderr)
                        report = json.loads(result.stdout)
                        expected = 'Microsoft tools (linker 14.44)' if detected else None
                        self.assertEqual(report['metadata'].get('compiler'), expected)
                        self.assertEqual(any(step == 'Compiler: ' + str(expected) for step in report['steps']), detected)

    def test_arm64_warning_describes_the_required_runner(self):
        result = self.invoke([], machine=0xaa64)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['arch'], 'ARM64')
        self.assertEqual(report['details']['Warning'], [{
            'name': 'ARM64 binary',
            'description': 'Requires an ARM64-capable Wine runner.',
            'severity': 'warning',
            'source': 'Main Executable',
        }])
        self.assertIn('[!] ARM64 requires a matching Wine runner', report['steps'])

    def test_nonempty_version_values_survive_later_empty_tables(self):
        for tables, expected in [
            ([{'CompanyName': 'Example', 'ProductName': 'Product'}, {'CompanyName': '', 'ProductName': ''}], ('Example', 'Product')),
            ([{'CompanyName': '', 'ProductName': ''}, {'CompanyName': 'Later', 'ProductName': 'Later product'}], ('Later', 'Later product')),
            ([{'CompanyName': 'First', 'ProductName': 'First product'}, {'CompanyName': 'Later', 'ProductName': ''}], ('Later', 'First product')),
            ([{'CompanyName': '', 'ProductName': ''}], ('Unknown', 'app.exe')),
        ]:
            with self.subTest(tables=tables):
                result = self.invoke(tables, {'CompanyName': '', 'ProductName': ''})
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual((report['publisher'], report['product_name']), expected)

    def test_flat_version_input_remains_supported(self):
        result = self.invoke([], {'CompanyName': 'Example', 'ProductName': 'Product'})
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report['publisher'], report['product_name']), ('Example', 'Product'))

    def test_invalid_version_tables_are_rejected(self):
        for tables in ({}, ['invalid'], [{'CompanyName': 42}]):
            with self.subTest(tables=tables):
                result = self.invoke(tables)
                self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)

