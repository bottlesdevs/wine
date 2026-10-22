import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import session
import session_reports


class ReportSize(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.bundle = self.root / 'owned.session'
        self.bundle.mkdir()
        self.destination = self.root / 'final.log'

    def bundle_events(self, events, **manifest):
        (self.bundle / 'manifest.json').write_text(json.dumps(dict(schema=1, **manifest)))
        (self.bundle / 'events.jsonl').write_text(''.join(json.dumps(dict(event, seq=index)) + '\n' for index, event in enumerate(events)))

    def events(self):
        values = []
        for index in range(30):
            values.extend([dict(kind='snapshot', pid=1, tid=1, frames=[], note=str(index) + 'x' * 300),
                           dict(kind='provider', pid=1, data=dict(provider=8, event='fixture', note='x' * 300)),
                           dict(kind='exception', pid=1, tid=1, first_chance=False, code=index, note='x' * 300)])
        values.extend([dict(kind='process_exit', pid=1, tid=1, code=37), dict(kind='finished', pid=0, tid=0)])
        return values

    def test_small_exports_keep_exact_bytes(self):
        self.bundle_events([dict(kind='snapshot', pid=1, frames=[])])
        expected = session.redact(session.summary(self.bundle))
        expected['export'] = dict(redaction='paths and launch arguments removed', review_required=True, memory_and_dumps_included=False)
        session.export(self.bundle, self.destination)
        self.assertEqual(self.destination.read_text(), json.dumps(expected, indent=2) + '\n')

    def test_oversized_views_fit_preserve_counts_recent_fault_and_original_bundle(self):
        self.bundle_events(self.events())
        before = (self.bundle / 'events.jsonl').read_bytes()
        original = session.summary(self.bundle)
        with patch.object(session_reports, 'MAX_REPORT', 12000):
            report = session.export(self.bundle, self.destination)
            imported = session.summary(self.destination)
        self.assertLessEqual(self.destination.stat().st_size, 12000)
        self.assertEqual(report['counts'], original['counts'])
        self.assertEqual(report['terminal_exceptions'][-1]['code'], 29)
        self.assertEqual(report['exits'][-1]['code'], 37)
        self.assertTrue(report['export']['review_required'])
        self.assertEqual(imported['input_coverage']['export_omitted_records'], report['export']['omitted_records'])
        self.assertGreater(sum(report['export']['omitted_records'].values()), 0)
        for name in session_reports.EXPORT_LISTS:
            self.assertEqual(len(report[name]) + report['export']['omitted_records'][name], len(original[name]))
        for name in ('timeline', 'snapshots', 'terminal_exceptions'):
            self.assertTrue(report[name])
            self.assertEqual(report[name], original[name][-len(report[name]):])
        self.assertEqual((self.bundle / 'events.jsonl').read_bytes(), before)
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)

    def test_busy_provider_does_not_displace_other_groups(self):
        events = [dict(kind='provider', pid=1, data=dict(provider=provider, event='rare', note='x' * 200)) for provider in (1, 2, 4)]
        events.extend(dict(kind='provider', pid=1, data=dict(provider=8, event='busy', note='x' * 200)) for _ in range(100))
        self.bundle_events(events)
        with patch.object(session_reports, 'MAX_REPORT', 5000):
            report = session.export(self.bundle, self.destination)
        self.assertEqual({event['data']['provider'] for event in report['providers']}, {1, 2, 4, 8})
        self.assertEqual([event['seq'] for event in report['providers']], sorted(event['seq'] for event in report['providers']))
        self.assertLessEqual(self.destination.stat().st_size, 5000)

    def test_size_limit_preserves_earlier_provider_failures(self):
        failures = [{'hresult': '0x80004005'}, {'hresult': -2147467259}, {'success': False}]
        events = [dict(kind='provider', pid=1, data=dict(provider=2, **data)) for data in failures]
        events.extend(dict(kind='provider', pid=1, data=dict(provider=2, hresult='0x00000000', note='x' * 200)) for _ in range(100))
        self.bundle_events(events)
        with patch.object(session_reports, 'MAX_REPORT', 5000):
            report = session.export(self.bundle, self.destination)
            imported = session.summary(self.destination)
        self.assertEqual([event['seq'] for event in report['providers'][:3]], [0, 1, 2])
        self.assertEqual(report['providers'][-1]['seq'], 102)
        self.assertEqual(imported['providers'], report['providers'])
        self.assertEqual(len(report['providers']) + report['export']['omitted_records']['providers'], 103)
        self.assertLessEqual(self.destination.stat().st_size, 5000)

    def test_size_limit_does_not_prioritize_pending_or_invalid_statuses(self):
        for status in ('0x8000000a', '0x00000001', 'invalid', None):
            with self.subTest(status=status):
                events = [dict(kind='provider', pid=1, data=dict(provider=2, hresult=status))]
                events.extend(dict(kind='provider', pid=1, data=dict(provider=2, hresult=0, note='x' * 200)) for _ in range(100))
                self.bundle_events(events)
                with patch.object(session_reports, 'MAX_REPORT', 5000):
                    report = session.export(self.bundle, self.destination)
                self.assertNotIn(0, [event['seq'] for event in report['providers']])
                self.assertEqual(report['providers'][-1]['seq'], 100)
                self.destination.unlink()

    def test_metadata_alone_over_budget_fails_without_output(self):
        self.bundle_events([], description='x' * 3000)
        with patch.object(session_reports, 'MAX_REPORT', 1000):
            with self.assertRaisesRegex(ValueError, 'metadata exceeds'):
                session.export(self.bundle, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob('.eagle-export-*')), [])

    def test_large_newest_timeline_event_does_not_leave_false_older_history(self):
        self.bundle_events([dict(kind='module_load', pid=1, base='0x400000', path='C:\\old.dll'),
                            dict(kind='module_unload', pid=1, base='0x400000', note='x' * 5000)])
        with patch.object(session_reports, 'MAX_REPORT', 1500):
            report = session.export(self.bundle, self.destination)
        self.assertEqual(report['timeline'], [])
        self.assertEqual(report['export']['omitted_records']['timeline'], 2)
        self.assertLessEqual(self.destination.stat().st_size, 1500)

    def test_reexport_preserves_accumulated_view_omissions(self):
        self.bundle_events(self.events())
        original = session.summary(self.bundle)
        with patch.object(session_reports, 'MAX_REPORT', 12000):
            first = session.export(self.bundle, self.destination)
            second_path = self.root / 'second.log'
            second = session.export(self.destination, second_path)
            third = session.summary(second_path)
        for name in session_reports.EXPORT_LISTS:
            self.assertGreaterEqual(second['export']['omitted_records'][name], first['export']['omitted_records'][name])
            self.assertEqual(len(second[name]) + second['export']['omitted_records'][name], len(original[name]))
        self.assertEqual(third['counts'], original['counts'])
        self.assertEqual(third['input_coverage']['export_omitted_records'], second['export']['omitted_records'])
        self.assertLessEqual(second_path.stat().st_size, 12000)

    def test_invalid_limits_and_omissions_fail_before_reexport(self):
        self.bundle_events([])
        original = session.export(self.bundle, self.destination)
        for index, changes in enumerate([
            {'summary_limit_bytes': True, 'omitted_records': {}},
            {'summary_limit_bytes': 1000, 'omitted_records': {'snapshots': -1}},
            {'summary_limit_bytes': 1000, 'omitted_records': {'snapshots': True}},
            {'summary_limit_bytes': 1000, 'omitted_records': {'unknown': 1}},
            {'summary_limit_bytes': 1000},
        ]):
            report = copy.deepcopy(original)
            report['export'].update(changes)
            source = self.root / ('invalid' + str(index) + '.log')
            destination = self.root / ('invalid-export' + str(index) + '.log')
            source.write_text(json.dumps(report))
            with self.subTest(index=index), self.assertRaises(ValueError):
                session.export(source, destination)
            self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
