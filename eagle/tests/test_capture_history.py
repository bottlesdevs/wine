import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import capture_history as history
import session
import session_symbols
from test_capture_startup import Collector


class CaptureHistory(unittest.TestCase):
    def limits(self):
        return patch.multiple(history, PREFIX_BYTES=400, RECENT_BYTES=600, TERMINAL_BYTES=600,
                              PREFIX_EVENTS=3, RECENT_EVENTS=3, TERMINAL_EVENTS=2)

    def write(self, events, bounded=True):
        output = io.StringIO()
        manifest = {'dropped_events': 0}
        with self.limits(), history.CaptureHistory(output, manifest, bounded) as writer:
            for seq, event in enumerate(events):
                writer.write(dict(event, seq=seq))
        return [json.loads(line) for line in output.getvalue().splitlines()], manifest, output.getvalue()

    def events(self):
        return [dict(kind='process_create', pid=1, tid=1)] + [dict(kind='snapshot', pid=1, frames=[], note='x' * 100) for _ in range(20)]

    def test_small_capture_remains_complete_with_exact_event_bytes(self):
        events = [dict(kind='process_create', pid=1), dict(kind='process_exit', pid=1, code=37)]
        rows, manifest, data = self.write(events)
        self.assertEqual(data, ''.join(json.dumps(dict(event, seq=seq)) + '\n' for seq, event in enumerate(events)))
        self.assertEqual(manifest['capture_history']['coverage'], 'complete')
        self.assertEqual(manifest['capture_root'], {'pid': 1, 'exit_code': 37})
        self.assertEqual(manifest['dropped_events'], 0)

    def test_prefix_recent_and_terminal_reserves_are_bounded_and_gaps_are_exact(self):
        events = self.events()
        events.insert(8, dict(kind='exception', pid=1, first_chance=False, code=37))
        events.append(dict(kind='process_exit', pid=1, code=37))
        rows, manifest, data = self.write(events)
        info = manifest['capture_history']
        self.assertEqual(info['coverage'], 'partial')
        self.assertLessEqual(info['event_bytes'], 1600)
        self.assertEqual(len(data.encode()), info['event_bytes'] + info['gap_bytes'])
        self.assertEqual(sum(row.get('omitted_events', 0) for row in rows), manifest['dropped_events'])
        self.assertEqual(info['retained_events'] + manifest['dropped_events'], len(events))
        self.assertTrue(any(row['kind'] == 'exception' and row['code'] == 37 for row in rows))
        self.assertEqual(rows[-1]['code'], 37)
        self.assertEqual(len({row['seq'] for row in rows}), len(rows))

    def test_root_outcome_survives_eviction_and_oversized_events_are_not_buffered(self):
        events = [dict(kind='process_create', pid=1, note='x' * 2000), dict(kind='process_exit', pid=1, code=0)]
        events.extend(dict(kind='fixture', note='x' * 200) for _ in range(20))
        rows, manifest, _ = self.write(events)
        self.assertEqual(manifest['capture_root'], {'pid': 1, 'exit_code': 0})
        self.assertFalse(any(row['kind'] == 'process_exit' for row in rows))
        self.assertGreater(manifest['dropped_events'], 0)
        self.assertLessEqual(manifest['capture_history']['event_bytes'], 1600)

    def test_unbounded_profiles_keep_the_existing_count_limit_and_format(self):
        events = self.events()
        rows, manifest, _ = self.write(events, bounded=False)
        self.assertEqual(len(rows), 3)
        self.assertEqual(manifest, {'dropped_events': len(events) - 3})

    def test_exception_exit_flushes_retained_tail_and_metadata(self):
        output = io.StringIO()
        manifest = {'dropped_events': 0}
        with self.limits(), self.assertRaisesRegex(RuntimeError, 'owned fixture'):
            with history.CaptureHistory(output, manifest, True) as writer:
                for event in self.events():
                    writer.write(event)
                raise RuntimeError('owned fixture')
        self.assertTrue(output.getvalue().endswith('\n'))
        self.assertEqual(manifest['capture_history']['coverage'], 'partial')
        self.assertEqual(len(writer.recent), 0)
        self.assertEqual(len(writer.terminal), 0)

    def test_gap_invalidates_module_lifetimes_until_a_new_load(self):
        load = dict(kind='module_load', pid=1, base='0x400000', path='C:\\owned.dll', identity={'sha256': 'a' * 64})
        snapshot = dict(kind='snapshot', pid=1, frames=[dict(module='owned', image='C:\\owned.dll', rva='0x1', address='0x400001')])
        events = [load, snapshot, dict(kind='capture_gap'), snapshot, dict(load, identity={'sha256': 'b' * 64}), snapshot]
        frames = list(session_symbols.recorded_frames({'modules': {}}, events))
        self.assertEqual(frames[0][2], 'a' * 64)
        self.assertIsNone(frames[1][2])
        self.assertEqual(frames[2][2], 'b' * 64)
        partial = {'modules': {'C:\\owned.dll': {'sha256': 'a' * 64}}, 'capture_history': {'coverage': 'partial'}}
        self.assertIsNone(list(session_symbols.recorded_frames(partial, [snapshot]))[0][2])

    def test_partial_session_comparison_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, manifest, events in [('complete', {'schema': 1, 'target_identity': {'sha256': 'a'}}, []),
                                            ('partial', {'schema': 1, 'target_identity': {'sha256': 'a'}, 'dropped_events': 1}, []),
                                            ('gap', {'schema': 1, 'target_identity': {'sha256': 'a'}}, [dict(kind='capture_gap')])]:
                bundle = root / label
                bundle.mkdir()
                (bundle / 'manifest.json').write_text(json.dumps(manifest))
                (bundle / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
            self.assertEqual(session.compare(root / 'complete', root / 'complete')['verdict'], 'comparable')
            for label in ['partial', 'gap']:
                result = session.compare(root / 'complete', root / label)
                self.assertTrue(result['matching_inputs'])
                self.assertIn('incomplete', result['verdict'])

    def test_actual_capture_context_retains_outcome_and_observes_events_after_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'bin').mkdir()
            wine = root / 'bin/wine'
            wine.write_bytes(b'owned nonexecuted launcher fixture')
            wine.chmod(0o700)
            (root / 'share/eagle').mkdir(parents=True)
            (root / 'share/eagle/providers.json').write_text(json.dumps({'profiles': {name: ['64'] for name in ['com', 'winrt', 'dwrite', 'd2d', 'loader', 'wait']}}))
            events = self.events() + [dict(kind='process_exit', pid=1, code=37), dict(kind='finished')]
            events = [dict(event, seq=index, pid=event.get('pid', 0), tid=event.get('tid', 1)) for index, event in enumerate(events)]
            collector = Collector(events)
            self.addCleanup(collector.close)
            observed = []
            with self.limits(), patch('session.subprocess.Popen', return_value=collector):
                report = session.capture(wine, root / 'prefix', root / 'run.session', pid=1,
                                         profile='trace', control_enabled=False, observer=observed.append)
            self.assertEqual(len(observed), len(events))
            self.assertTrue(report['manifest']['completed'])
            self.assertEqual(report['manifest']['capture_root']['exit_code'], 37)
            self.assertGreater(report['manifest']['dropped_events'], 0)
            self.assertEqual(report['exits'][-1]['code'], 37)
            self.assertTrue(collector.stdout.closed)


if __name__ == '__main__':
    unittest.main()
