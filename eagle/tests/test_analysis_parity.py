import json
import os
from pathlib import Path
import subprocess
import unittest


class AnalysisParity(unittest.TestCase):
    def test_native_pe_preserves_analysis_results(self):
        fixtures = Path(os.environ['EAGLE_TEST_ROOT'])
        baseline = Path(os.environ['EAGLE_BASELINE_PACKAGE']) / 'bin/eagle'
        candidate = Path(os.environ['EAGLE_PACKAGE']) / 'bin/eagle'
        for path in sorted(fixtures.glob('*.exe')):
            with self.subTest(path=path.name):
                outputs = []
                for executable in (baseline, candidate):
                    result = subprocess.run([str(executable), 'analyze', '--scan-limit', '1', str(path)], capture_output=True, text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    outputs.append(json.loads(result.stdout))
                self.assertEqual(outputs[0], outputs[1])


if __name__ == '__main__':
    unittest.main()
