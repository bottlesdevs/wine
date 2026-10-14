import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
CONFIG = json.loads((ROOT / 'analysis.json').read_text())


class ManifestTests(unittest.TestCase):
    def interpret(self, manifests, structure=None):
        structure = dict(structure or dict(machine=0x8664, min_os='10.0', timestamp=0,
            characteristics=0, dll_characteristics=0, rich_products=[], sections=[],
            imports=[], managed=False, version={}))
        structure['manifests'] = manifests
        request = dict(operation='pe-insights', structure=structure, basename='app.exe',
                       details={name: [] for name in ('Graphics', 'Runtimes', 'Warning')},
                       metadata={}, **{key: CONFIG[key] for key in ('compilers', 'packers')},
                       mapping=CONFIG['mapping'])
        result = subprocess.run([str(ROOT / 'native/eagle-analysis')], input=json.dumps(request),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_dpi_values_and_modern_precedence(self):
        cases = [
            ('', False), ('<dpiAware/>', False), ('<dpiAware>false</dpiAware>', False),
            ('<dpiAware>TRUE</dpiAware>', True), ('<dpiAware> true/pm </dpiAware>', True),
            ('<dpiAware>per monitor</dpiAware>', True), ('<dpiAware>unknown</dpiAware>', False),
            ('<dpiAwareness>unaware</dpiAwareness>', False),
            ('<dpiAwareness>unknown</dpiAwareness>', False),
            ('<dpiAwareness>system</dpiAwareness>', True),
            ('<dpiAwareness>PerMonitor</dpiAwareness>', True),
            ('<dpiAwareness>Unknown, PerMonitorV2, unaware</dpiAwareness>', True),
            ('<dpiAwareness>unaware,PerMonitor</dpiAwareness>', False),
            ('<dpiAware>true</dpiAware><dpiAwareness>unaware</dpiAwareness>', False),
            ('<dpiAware>true</dpiAware><dpiAwareness/>', False),
            ('<dpiAwareness>unaware</dpiAwareness><dpiAware>true</dpiAware>', False),
            ('<dpiAware>false</dpiAware><dpiAwareness>PerMonitorV2</dpiAwareness>', True),
            ('<!-- <dpiAware>true</dpiAware> -->', False),
            ('<description>dpiAware requireAdministrator</description>', False),
            ('<x:dpiAware xmlns:x="http://schemas.microsoft.com/SMI/2005/WindowsSettings"><![CDATA[true]]></x:dpiAware>', True),
        ]
        for content, expected in cases:
            with self.subTest(content=content):
                value = self.interpret(['<assembly>' + content + '</assembly>'])
                self.assertEqual(value['dpi_aware'], expected)
                self.assertFalse(value['admin'])

    def test_admin_requires_execution_level_attribute(self):
        for content, expected in [
            ('<requestedExecutionLevel level="requireAdministrator"/>', True),
            ('<requestedExecutionLevel level="asInvoker"/>', False),
            ('<requestedExecutionLevel level="highestAvailable"/>', False),
            ('<!-- <requestedExecutionLevel level="requireAdministrator"/> -->', False),
            ('<description>requireAdministrator</description>', False),
            ('<requestedExecutionLevel other="requireAdministrator"/>', False),
        ]:
            with self.subTest(content=content):
                self.assertEqual(self.interpret(['<assembly>' + content + '</assembly>'])['admin'], expected)

    def test_invalid_manifest_does_not_set_flags(self):
        for manifest in ('<assembly><dpiAware>true</dpiAware>',
                         '<assembly><requestedExecutionLevel level="requireAdministrator"/>',
                         'dpiAware requireAdministrator'):
            with self.subTest(manifest=manifest):
                value = self.interpret([manifest])
                self.assertFalse(value['admin'])
                self.assertFalse(value['dpi_aware'])

    def test_utf8_byte_order_mark_is_accepted(self):
        value = self.interpret(['\ufeff<?xml version="1.0" encoding="UTF-8"?><assembly>'
                                '<requestedExecutionLevel level="requireAdministrator"/>'
                                '<dpiAware>true</dpiAware></assembly>'])
        self.assertTrue(value['admin'])
        self.assertTrue(value['dpi_aware'])

    def test_real_x86_and_x64_manifest_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'app.c'
            source.write_text('int main(void) { return 0; }\n')
            for manifest, expected in [
                ('<assembly><dpiAware>false</dpiAware></assembly>', False),
                ('<assembly><dpiAware>true/pm</dpiAware></assembly>', True),
                ('<assembly><dpiAware>true</dpiAware><dpiAwareness>unaware</dpiAwareness></assembly>', False),
            ]:
                (root / 'app.manifest').write_text(manifest)
                resource = root / 'app.rc'
                resource.write_text('1 24 "app.manifest"\n')
                for compiler in ('i686', 'x86_64'):
                    with self.subTest(compiler=compiler, manifest=manifest):
                        target = root / (compiler + '.exe')
                        obj = root / (compiler + '.o')
                        subprocess.run([compiler + '-w64-mingw32-windres', str(resource), str(obj)], cwd=root, check=True, capture_output=True)
                        subprocess.run([compiler + '-w64-mingw32-gcc', str(source), str(obj), '-o', str(target)], check=True, capture_output=True)
                        result = subprocess.run([str(ROOT / 'native/eagle-pe'), str(target)], capture_output=True, text=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        structure = json.loads(result.stdout)
                        self.assertEqual(structure['resource_error'], '')
                        self.assertEqual(len(structure['manifests']), 1)
                        self.assertEqual(self.interpret(structure['manifests'], structure)['dpi_aware'], expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
