import copy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.analyzer import EagleManager
from engine.native import Rules, yara_insights


def matches(rows):
    return [SimpleNamespace(rule=row['rule'], meta=row['meta'], strings=[SimpleNamespace(identifier=item['identifier'], instances=[SimpleNamespace(matched_data=bytes.fromhex(item['hex']))]) for item in row['strings']]) for row in rows]


class NativeYaraInsights(unittest.TestCase):
    def compare(self, rows, details, source):
        expected = copy.deepcopy(details)
        steps = []
        engine = SimpleNamespace(_yara_rules=SimpleNamespace(match=lambda *args, **kwargs: matches(rows)), _send_step=lambda message, delay=True: steps.append(message))
        result = EagleManager._scan_yara_legacy(engine, 'fixture', expected, source)
        self.assertEqual(yara_insights(rows, details, source), {'details': expected, 'matches': result, 'steps': steps})

    def test_all_rule_fixture_reports_match_legacy(self):
        corpus = Path(os.environ['EAGLE_YARA_CORPUS'])
        fixtures = sorted(corpus.glob('*.fixture'))
        self.assertEqual(len(fixtures), 67)
        rules = Rules(str(PACKAGE / 'lib/eagle/engine/eagle.yar'))
        for fixture in fixtures:
            with self.subTest(rule=fixture.stem):
                rows = rules.rows(fixture)
                self.compare(rows, {}, 'Main Executable')
                populated = yara_insights(rows, {}, 'Main Executable')['details']
                self.compare(rows, populated, 'Neighbor: fixture.dll')
                steps = []
                actual = {}
                engine = SimpleNamespace(_yara_rules=rules, _send_step=lambda message, delay=True: steps.append(message))
                observed = EagleManager._scan_yara(engine, str(fixture), actual, 'Main Executable')
                expected = yara_insights(rows, {}, 'Main Executable')
                self.assertEqual({'details': actual, 'matches': observed, 'steps': steps}, expected)

    def test_context_encoding_filtering_and_limit(self):
        captures = [('alpha command', 'utf-8'), ('  HKLM\\Software\\Example  ', 'utf-16le'), ('HKCU', 'utf-8'), ('é日', 'utf-8'), ('三字符', 'utf-8'), ('\x1c command \u2003', 'utf-8'), ('before\0after', 'utf-16le')]
        strings = [dict(identifier='$capture', hex=value.encode(encoding).hex()) for value, encoding in captures]
        strings += [dict(identifier='$reg_value', hex=f'key-{i}'.encode().hex()) for i in range(25)]
        strings += [dict(identifier='$capture', hex='fffe'), dict(identifier='$ignored', hex=b'ignored'.hex()), dict(identifier='$capture', hex=b'alpha command'.hex())]
        rows = [dict(rule='Context', meta={'category': 'Warning', 'name': 'Test', 'severity': 'warning', 'description': 'Context'}, strings=strings)]
        self.compare(rows, {}, 'Electron Source: app.js')
        self.assertEqual(len(yara_insights(rows, {}, 'fixture')['details']['Warning'][0]['context']), 20)
        for rule in ('Node_System_Commands', 'Node_Native_Module', 'Node_Kernel_Driver', 'Driver_Service'):
            self.compare([dict(rule=rule, meta={}, strings=[dict(identifier='$other', hex=b'command --flag'.hex())])], {}, 'fixture')

    def test_directory_marker_does_not_abort_later_matches(self):
        rows = [dict(rule='Runtime', meta={'category': 'Runtimes', 'name': '.NET Core/5+'}, strings=[]), dict(rule='Other', meta={'category': 'Security', 'name': 'Finding'}, strings=[])]
        actual = yara_insights(rows, {'Runtimes': ['.NET Core/5+']}, 'Neighbor: fixture.dll')
        self.assertEqual(actual['details']['Runtimes'], ['.NET Core/5+'])
        self.assertEqual(actual['details']['Security'][0]['name'], 'Finding')
        self.assertEqual(len(actual['matches']), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
