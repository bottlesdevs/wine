import copy
import json
import os
from pathlib import Path
import random
import sqlite3
import subprocess
import sys
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.analyzer import EagleManager
from engine.intel import EagleIntel, PACKAGED_DB_PATH


class NativeMerge(unittest.TestCase):
    def test_database_plans_preserve_suggestion_merge(self):
        intel = EagleIntel(PACKAGED_DB_PATH)
        self.addCleanup(intel.close)
        with sqlite3.connect(PACKAGED_DB_PATH) as connection:
            rows = connection.execute("SELECT DISTINCT s.name FROM software s JOIN tweak t ON t.software_id=s.id").fetchall()
        selected = random.Random(9283).sample(rows, min(300, len(rows)))
        for (name,) in selected:
            plan = intel.plan(intel.lookup(product_name=name))
            for initial in ([], [{'key': 'dxvk', 'value': True, 'label': 'Enable DXVK (DX9-11)'}, {'key': 'dep_vcredist', 'value': False, 'label': 'Visual C++'}, {'key': 'sync', 'value': 'esync', 'label': 'Esync (threading)'}]):
                with self.subTest(name=name, initial=initial):
                    expected, actual = copy.deepcopy(initial), copy.deepcopy(initial)
                    EagleManager._merge_intel_suggestions_legacy(expected, plan)
                    EagleManager._merge_intel_suggestions(actual, plan)
                    self.assertEqual(actual, expected)

    def test_null_plan_and_invalid_request(self):
        values = [{'key': 'dxvk', 'value': True, 'label': 'Enable DXVK'}]
        before = copy.deepcopy(values)
        EagleManager._merge_intel_suggestions(values, None)
        self.assertEqual(values, before)
        command = PACKAGE / 'lib/eagle/native/eagle-analysis'
        for request in ('[]', '{}', '{"operation":"merge","suggestions":{}}', '{"operation":"merge","suggestions":[],"intel":{}}', '{"operation":"merge","suggestions":[],"intel":null} trailing'):
            result = subprocess.run([str(command)], input=request, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
