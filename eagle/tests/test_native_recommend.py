import ast
import copy
import json
import os
from pathlib import Path
import random
import subprocess
import sys
from types import SimpleNamespace
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.analyzer import EagleManager
from engine.native import recommendations


def reference():
    source = Path(os.environ['EAGLE_BASELINE_PACKAGE']) / 'lib/eagle/engine/analyzer.py'
    tree = ast.parse(source.read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'EagleManager')
    analyze = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == 'analyze')
    block = next(node.body for node in analyze.body if isinstance(node, ast.Try))
    start = next(i for i, node in enumerate(block) if isinstance(node, ast.Expr) and 'Generating optimisation suggestions' in ast.unparse(node))
    end = next(i for i in range(start + 1, len(block)) if isinstance(block[i], ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'results' for target in block[i].targets))
    body = block[start + 1:end]
    body.append(ast.parse("return {'suggestions': suggestions, 'messages': messages, 'frameworks': frameworks}").body[0])
    function = ast.parse('def original(self, insights, metadata, is_net, dpi_aware, ue_shipping_exe, intel_plan):\n    pass').body[0]
    function.body = body
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    namespace = {}
    exec(compile(module, str(source), 'exec'), namespace)
    return namespace['original']


class NativeRecommend(unittest.TestCase):
    def test_recommendations_messages_and_report_fields_match(self):
        original = reference()
        engine = SimpleNamespace(_merge_intel_suggestions=EagleManager._merge_intel_suggestions_legacy, _send_step=lambda *args: None)
        groups = {'Graphics': ['DirectX 9', 'DirectX 11', 'DirectX 12', 'DXGI', 'Vulkan', 'NVAPI'], 'Upscaling': ['DLSS', 'DLSS 3 Frame Gen', 'AMD FSR', 'AMD FSR 2', 'Intel XeSS'], 'Engines': ['Unity', 'Unreal', 'Godot', 'Source', "Ren'Py"], 'Runtimes': ['.NET Framework', 'Mono', 'VC++ 2015-22'], 'Physics': ['PhysX'], 'Protection': ['EAC', 'Denuvo'], 'Frameworks': ['WPF'], 'Warning': ['UWP/Modern API']}
        randomizer = random.Random(9283)
        for iteration in range(150):
            details = {key: [{'name': name, 'source': 'Main Executable', 'context': ['example\nargument']} for name in names if randomizer.choice((True, False))] for key, names in groups.items()}
            details['Analysed Files'] = ['app.exe']
            metadata = {'is_packed': bool(iteration % 2), 'packer': 'UPX' if iteration % 2 else None}
            is_net, dpi = bool(iteration % 3), bool(iteration % 5)
            shipping = 'Game/Binaries/Win64/app-shipping.exe' if iteration % 4 == 0 else None
            expected = original(engine, copy.deepcopy(details), metadata, is_net, dpi, shipping, None)
            actual = recommendations(details, metadata, is_net, dpi, shipping, None)
            self.assertEqual(actual, expected, iteration)

    def test_multiple_runtime_groups_have_stable_order(self):
        details = {'Runtimes': ['.NET Framework', '.NET Core/5+', 'VC++ 2015-22', 'VC++ 2010']}
        result = recommendations(details, {'is_packed': False}, False, True, None, None)
        self.assertEqual([row['label'] for row in result['suggestions']], ['.NET Core/5+', '.NET Framework', 'Visual C++ (VC++ 2010, VC++ 2015-22)'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
