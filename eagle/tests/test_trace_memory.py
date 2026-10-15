import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import weakref
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import session
import tracing


class Captured(dict):
    pass


class TraceMemory(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.prefix = self.root / 'prefix'
        self.prefix.mkdir()
        self.target = self.root / 'owned.exe'
        self.target.write_bytes(b'owned nonexecuted target fixture')
        self.logs = self.prefix / 'logs/runs'
        self.references = []

    def run_trace(self, events, completed=True):
        def capture(wine, prefix, bundle, **options):
            bundle.mkdir(mode=0o700)
            (bundle / 'manifest.json').write_text(json.dumps(dict(schema=1, completed=completed)))
            with (bundle / 'events.jsonl').open('w') as file:
                for index, event in enumerate(events):
                    event = dict(event, seq=index)
                    file.write(json.dumps(event) + '\n')
                    options['observer'](event)
            report = Captured(session.summary(bundle))
            self.references.append(weakref.ref(report))
            return report
        with patch.object(tracing, 'capture', side_effect=capture):
            return tracing.trace('owned-unused-launcher', self.prefix, self.logs, [str(self.target)])

    def create(self, pid):
        return dict(kind='process_create', pid=pid, tid=pid)

    def exit(self, pid, code):
        return dict(kind='process_exit', pid=pid, tid=pid, code=code)

    def test_capture_report_is_released_before_export_and_no_outcome_reread_is_needed(self):
        export = tracing.export
        def released(*arguments, **options):
            self.assertIsNone(self.references[0]())
            return export(*arguments, **options)
        events = [self.create(1), dict(kind='snapshot', pid=1, frames=[]), self.exit(1, 37)]
        with patch.object(session, 'read_bundle', wraps=session.read_bundle) as read, patch.object(tracing, 'export', side_effect=released):
            result = self.run_trace(events)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(result['exit_code'], 37)
        self.assertEqual(result['counts'], dict(process_create=1, snapshot=1, process_exit=1))

    def test_zero_root_exit_is_preserved_when_child_exits_first(self):
        result = self.run_trace([self.create(1), self.create(2), self.exit(2, 91), self.exit(1, 0)])
        self.assertEqual(result['exit_code'], 0)
        report = json.loads(Path(result['log']).read_text())
        self.assertEqual(report['exits'], [{'pid': 2, 'code': 91}, {'pid': 1, 'code': 0}])

    def test_exit_before_first_creation_does_not_select_a_false_root(self):
        result = self.run_trace([self.exit(2, 91), self.create(1), self.exit(1, 37)])
        self.assertEqual(result['exit_code'], 37)

    def test_pid_reuse_keeps_the_original_root_exit(self):
        result = self.run_trace([self.create(1), self.exit(1, 37), self.create(1), self.exit(1, 91)])
        self.assertEqual(result['exit_code'], 37)

    def test_missing_root_exit_or_incomplete_capture_remains_an_error_with_report(self):
        for events, completed in [([self.create(1), self.create(2), self.exit(2, 91)], True),
                                  ([self.create(1), self.exit(1, 37)], False)]:
            with self.subTest(completed=completed), self.assertRaisesRegex(RuntimeError, 'Trace incomplete'):
                self.run_trace(events, completed)
        self.assertEqual(len(list(self.logs.glob('*.log'))), 2)
        self.assertEqual(list(self.logs.glob('*.running.log')), [])
        for path in self.logs.glob('*.log'):
            self.assertTrue(json.loads(path.read_text())['export']['review_required'])

    def test_root_exit_is_tracked_after_live_log_limit_is_reached(self):
        events = [self.create(1)]
        events.extend(dict(kind='snapshot', pid=1, frames=[], note='x' * (64 * 1024)) for _ in range(270))
        events.append(self.exit(1, 37))
        result = self.run_trace(events)
        self.assertEqual(result['exit_code'], 37)
        self.assertEqual(result['counts']['snapshot'], 270)
        self.assertTrue(json.loads(Path(result['log']).read_text())['export']['review_required'])
        self.assertIsNone(self.references[0]())


if __name__ == '__main__':
    unittest.main()
