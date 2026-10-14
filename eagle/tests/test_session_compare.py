import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
sys.path.insert(0, str(PACKAGE))
from session import compare


class SessionComparison(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.manifest = dict(schema=1, target_identity={'sha256': 'a' * 64},
                             arguments=[], profile='trace', trigger=None, interactive=False)

    def bundle(self, name, events, **changes):
        root = self.root / name
        root.mkdir()
        (root / 'manifest.json').write_text(json.dumps(dict(self.manifest, **changes)))
        (root / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
        return root

    def provider(self, **changes):
        data = dict(provider=4, event='CoCreateInstanceEx', hresult='0x00000000',
                    clsid='fixture-class', iid='fixture-interface', object='0x1000', caller='0x2000')
        data.update(changes)
        return dict(kind='provider', pid=1, tid=2, seq=3, time_ms=4, data=data,
                    frame={'module': 'fixture.dll', 'rva': '0x120'})

    def test_provider_changes_are_reported(self):
        baseline = self.bundle('baseline', [self.provider()])
        for field, value in [('provider', 1), ('event', 'CoGetClassObject'),
                             ('hresult', '0x80040111'), ('clsid', 'other-class'),
                             ('iid', 'other-interface')]:
            with self.subTest(field=field):
                candidate = self.bundle(field, [self.provider(**{field: value})])
                result = compare(baseline, candidate)
                self.assertTrue(result['matching_inputs'])
                self.assertEqual([item['count'] for item in result['added']], [1])
                self.assertEqual([item['count'] for item in result['removed']], [1])

    def test_provider_addresses_and_event_times_do_not_change_counts(self):
        original = self.provider()
        changed = self.provider(object='0x3000', caller='0x4000')
        changed.update(pid=10, tid=20, seq=30, time_ms=40)
        changed['data'] = dict(reversed(list(changed['data'].items())))
        baseline = self.bundle('baseline', [original])
        candidate = self.bundle('candidate', [changed])

        result = compare(baseline, candidate)
        self.assertEqual(result['added'], [])
        self.assertEqual(result['removed'], [])

    def test_wait_and_glyph_outcomes_remain_distinct(self):
        for provider, data, change in [
            (8, dict(event='WaitEnd', value=0, timeout_ms=100), dict(value=258)),
            (2, dict(event='CreateAlphaTexture', width=20, height=10), dict(width=21)),
        ]:
            with self.subTest(provider=provider):
                original = self.provider(provider=provider, **data)
                changed = copy.deepcopy(original)
                changed['data'].update(change)
                baseline = self.bundle(str(provider) + '-baseline', [original])
                candidate = self.bundle(str(provider) + '-candidate', [changed])
                result = compare(baseline, candidate)
                self.assertEqual(len(result['added']), 1)
                self.assertEqual(len(result['removed']), 1)

    def test_explicit_working_directory_is_part_of_the_input(self):
        baseline = self.bundle('baseline', [], target_cwd='/fixture/first')
        candidate = self.bundle('candidate', [], target_cwd='/fixture/second')
        self.assertFalse(compare(baseline, candidate)['matching_inputs'])

    def test_changed_input_and_observer_settings_are_inconclusive(self):
        baseline = self.bundle('baseline', [])
        changes = dict(target_identity={'sha256': 'b' * 64}, arguments=['--other'],
                       profile='crash', trigger={'hresult': '0x80040111', 'action': 'dump'},
                       interactive=True)
        for field, value in changes.items():
            with self.subTest(field=field):
                candidate = self.bundle(field, [], **{field: value})
                result = compare(baseline, candidate)
                self.assertFalse(result['matching_inputs'])
                self.assertTrue(result['verdict'].startswith('inconclusive'))

    def test_nonprovider_fingerprints_keep_existing_counts(self):
        original = dict(kind='process_exit', pid=1, code=0)
        changed = dict(kind='process_exit', pid=99, code=1)
        baseline = self.bundle('baseline', [original, original])
        candidate = self.bundle('candidate', [original, changed])
        result = compare(baseline, candidate)
        self.assertEqual([item['count'] for item in result['added']], [1])
        self.assertEqual([item['count'] for item in result['removed']], [1])
        self.assertEqual(len(result['added'][0]['fingerprint']), 6)

    def test_cli_preserves_provider_comparison(self):
        baseline = self.bundle('baseline', [self.provider()])
        candidate = self.bundle('candidate', [self.provider(hresult='0x80040111')])
        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'),
                                 'compare', str(baseline), str(candidate)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['data'], compare(baseline, candidate))
        self.assertEqual(len(json.loads(result.stdout)['data']['added']), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
