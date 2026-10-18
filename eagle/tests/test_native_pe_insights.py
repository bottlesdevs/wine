import ast
import copy
import datetime
import json
import os
from pathlib import Path
import random
import sys
from types import SimpleNamespace
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.analyzer import EagleManager
from engine.native import PE, pe_insights


def reference():
    source = Path(os.environ['EAGLE_BASELINE_PACKAGE']) / 'lib/eagle/engine/analyzer.py'
    tree = ast.parse(source.read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'EagleManager')
    analyze = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == 'analyze')
    block = next(node.body for node in analyze.body if isinstance(node, ast.Try))
    start = next(i for i, node in enumerate(block) if isinstance(node, ast.Expr) and 'Detecting architecture...' in ast.unparse(node))
    end = next(i for i, node in enumerate(block) if isinstance(node, ast.Expr) and 'Deep pattern scanning (YARA)...' in ast.unparse(node))
    function = ast.parse('def original(self, structure, insights, metadata, basename):\n    pass').body[0]
    function.body = block[start:end] + ast.parse("return dict(details=insights, metadata=metadata, arch=arch, min_os=os_name, publisher=publisher, product_name=product_name, admin=admin_required, dpi_aware=dpi_aware, is_net=is_net)").body
    namespace = {'datetime': datetime, 'time': SimpleNamespace(sleep=lambda *args: None), 'STEP_DELAY': 0}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[])), str(source), 'exec'), namespace)
    return namespace['original']


def normalized(value):
    value = copy.deepcopy(value)
    for category, items in value['details'].items():
        if category != 'Analysed Files': items.sort(key=lambda item: item if isinstance(item, str) else item['name'])
    return value


class NativePeInsights(unittest.TestCase):
    def test_metadata_and_dependency_mapping_match(self):
        original = reference()
        fixture = PE(os.environ['EAGLE_TARGET_FIXTURE']).data
        randomizer = random.Random(9283)
        categories = ['Graphics', 'Audio', 'Runtimes', 'Input', 'Social/DRM', 'Engines', 'Frameworks', 'Protection', 'Packers', 'Physics', 'Media', 'Crypto', 'Upscaling', 'Installer', 'Warning', 'Registry']
        for iteration in range(150):
            structure = copy.deepcopy(fixture)
            structure.update(machine=randomizer.choice([0x14c, 0x8664, 0xaa64, 0]), characteristics=randomizer.randrange(0x1000), dll_characteristics=randomizer.randrange(0x1000), timestamp=randomizer.choice([0, 1, 631152000, 1700000000, 2147483647]), min_os=randomizer.choice(['5.1', '6.0', '6.1', '6.2', '6.3', '10.0', '7.0']), rich_products=randomizer.sample(list(EagleManager.VS_PRODUCTS), 3), sections=[{'name': randomizer.choice(list(EagleManager.PACKER_SECTIONS))}], version={'CompanyName': 'Publisher' if iteration % 2 else '', 'ProductName': 'Product' if iteration % 3 else ''}, manifests=['<requestedExecutionLevel level="requireAdministrator"/><dpiAware>true</dpiAware>'] if iteration % 2 else [], managed=bool(iteration % 3), imports=[{'name': name.upper(), 'delay': bool(iteration % 2)} for name in randomizer.sample(list(EagleManager.DLL_MAPPINGS), 10)])
            details = {category: [] for category in categories}; details['Analysed Files'] = ['app.exe']
            metadata = dict(compiler=None, build_date=None, is_packed=False, packer=None, large_address_aware=False, dep_enabled=False, aslr_enabled=False, is_debug=False)
            steps = []
            engine = SimpleNamespace(VS_PRODUCTS=EagleManager.VS_PRODUCTS, PACKER_SECTIONS=EagleManager.PACKER_SECTIONS, DLL_MAPPINGS=EagleManager.DLL_MAPPINGS, _send_step=lambda message, delay=True: steps.append(message))
            expected = original(engine, structure, copy.deepcopy(details), copy.deepcopy(metadata), 'app.exe')
            actual = pe_insights(structure, details, metadata, 'app.exe', EagleManager.VS_PRODUCTS, EagleManager.PACKER_SECTIONS, EagleManager.DLL_MAPPINGS)
            actual_steps = actual.pop('steps')
            if structure['machine'] == 0xaa64:
                warning = expected['details']['Warning'][0]
                self.assertEqual(warning['description'], 'NOT SUPPORTED in Wine')
                warning.update(description='Requires an ARM64-capable Wine runner. This debugger supports x86 and x64.', severity='warning')
                steps[steps.index('[!] WARNING: ARM64 binary will not work in Wine')] = '[!] ARM64 requires a matching Wine runner; native debugging is unavailable in this build'

            self.assertEqual(normalized(actual), normalized(expected), iteration)
            # Imports have deterministic native ordering; the phase and all other messages match.
            marker = 'Mapping dependencies...'
            pivot = steps.index(marker) + 1
            self.assertEqual(actual_steps[:pivot], steps[:pivot], iteration)
            self.assertEqual(sorted(actual_steps[pivot:]), sorted(steps[pivot:]), iteration)

    def test_real_arm64_pe_is_analyzed_with_explicit_debug_limit(self):
        import subprocess
        path = Path(os.environ['EAGLE_ARM64_FIXTURE'])
        structure = PE(str(path)).data
        self.assertEqual(structure['machine'], 0xaa64)
        self.assertTrue(structure['codeview'])
        result = subprocess.run([str(PACKAGE / 'bin/eagle'), 'analyze', str(path)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)['data']
        self.assertEqual(report['arch'], 'ARM64')
        warning = next(item for item in report['details']['Warning'] if item['name'] == 'ARM64 binary')
        self.assertEqual(warning['severity'], 'warning')
        self.assertIn('ARM64-capable Wine runner', warning['description'])
        self.assertNotIn('NOT SUPPORTED', warning['description'])
        self.assertIn('x86 and x64', warning['description'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
