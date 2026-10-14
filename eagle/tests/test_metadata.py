import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
CONFIG = json.loads((ROOT / 'analysis.json').read_text())


class MetadataTests(unittest.TestCase):
    def invoke(self, tables, flat=None):
        structure = dict(machine=0x8664, min_os='10.0', timestamp=0,
                         characteristics=0, dll_characteristics=0, rich_products=[],
                         sections=[], manifests=[], imports=[], managed=False,
                         version=flat or {}, version_tables=tables)
        request = dict(operation='pe-insights', structure=structure,
                       details={'Warning': [], 'Runtimes': []}, metadata={}, basename='app.exe',
                       compilers=CONFIG['compilers'], packers=CONFIG['packers'], mapping=CONFIG['mapping'])
        return subprocess.run([str(ROOT / 'native/eagle-analysis')], input=json.dumps(request),
                              capture_output=True, text=True, timeout=5)

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

