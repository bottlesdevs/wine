import ast
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

import yara


class YaraParity(unittest.TestCase):
    def test_every_bundled_rule_matches_existing_engine(self):
        package = Path(os.environ['EAGLE_PACKAGE'])
        rules_path = package / 'lib/eagle/engine/eagle.yar'
        native = package / 'lib/eagle/native/eagle-yara'
        destination = Path(os.environ['EAGLE_TEST_ROOT']) / 'yara-corpus'
        destination.mkdir(exist_ok=False)
        reference = yara.compile(filepath=str(rules_path))
        declarations = re.split(r'(?m)^rule (\w+) \{', rules_path.read_text())
        rules = list(zip(declarations[1::2], declarations[2::2]))
        self.assertEqual(len(rules), 67)
        for name, body in rules:
            with self.subTest(rule=name):
                strings = body.split('strings:', 1)[1].split('condition:', 1)[0]
                payload = []
                for literal, flags in re.findall(r'(?m)^\s+\$\w+\s*=\s*("(?:\\.|[^"\\])*")([^\n]*)', strings):
                    value = ast.literal_eval(literal)
                    payload.append(value.encode())
                    if 'wide' in flags:
                        payload.append(value.encode('utf-16le'))
                path = destination / (name + '.fixture')
                path.write_bytes(b'\n'.join(payload))
                expected = []
                for match in reference.match(str(path), timeout=30):
                    expected.append(dict(rule=match.rule, meta=match.meta, strings=[dict(identifier=item.identifier, hex=item.instances[0].matched_data.hex()) for item in match.strings if item.instances]))
                self.assertIn(name, [row['rule'] for row in expected])
                result = subprocess.run([str(native), str(rules_path), str(path), '30'], capture_output=True, text=True, timeout=35)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['matches'], expected)
                security = [dict(rule=match.rule, name=match.meta.get('name', match.rule), description=match.meta.get('description', ''), severity=match.meta.get('severity', 'warning')) for match in reference.match(str(path), timeout=30) if match.meta.get('category') == 'Security']
                result = subprocess.run([str(package / 'bin/eagle'), 'security-scan', str(path)], capture_output=True, text=True, timeout=35)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['data'], security)


if __name__ == '__main__':
    unittest.main()
