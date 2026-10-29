import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
ROOT = Path(os.environ['EAGLE_TRACE_EXPORT_ROOT'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from tracing import trace
from session import export, summary


class TraceExports(unittest.TestCase):
    def test_null_call_recovery_status_survives_export_and_reload(self):
        bundle = ROOT / 'null-call-status'
        bundle.mkdir()
        statuses = ['recovered', 'stack-unreadable', 'stack-top-zero',
                    'return-memory-unavailable', 'stack-top-not-executable', 'return-module-unavailable']
        events = [dict(seq=index, kind='snapshot', pid=1, tid=2,
                       registers={'ip': '0x0', 'sp': '0x1000'},
                       frames=[{'address': '0x0'}], null_call_return_status=status)
                  for index, status in enumerate(statuses, 1)]
        (bundle / 'manifest.json').write_text(json.dumps({'schema': 1, 'completed': True}))
        (bundle / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
        destination = ROOT / 'null-call-status.log'
        report = export(bundle, destination)
        reloaded = summary(destination)
        for value in (report, reloaded):
            self.assertEqual([event['null_call_return_status'] for event in value['snapshots']], statuses)
            self.assertTrue(all(event['frames'] == [{'address': '0x0'}] for event in value['snapshots']))

    def test_wait_events_do_not_displace_other_providers(self):
        bundle = ROOT / 'provider-balance'
        bundle.mkdir()
        events = [{'seq': provider, 'kind': 'provider', 'data': {
            'provider': provider, 'event': 'failure', 'hresult': '0x80070005',
            'path': str(ROOT / 'private'),
        }} for provider in (1, 2, 4)]
        events.extend({'seq': seq, 'kind': 'provider', 'data': {
            'provider': 8, 'event': 'WaitBegin',
        }} for seq in range(5, 3005))
        (bundle / 'manifest.json').write_text(json.dumps({'schema': 1}))
        (bundle / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
        destination = ROOT / 'provider-balance.log'
        report = export(bundle, destination)
        self.assertEqual(len(report['providers']), 2000)
        self.assertEqual(report['provider_events_omitted'], 1003)
        self.assertEqual(report['providers'][:3], [dict(event, data=dict(event['data'], path='[redacted]')) for event in events[:3]])
        self.assertEqual(report['providers'][-1]['seq'], 3004)
        self.assertEqual([event['seq'] for event in report['providers']], sorted(event['seq'] for event in report['providers']))
        self.assertNotIn(str(ROOT), destination.read_text())

    def test_earlier_failures_survive_later_successes(self):
        from session import summarize
        failures = [
            {'provider': 2, 'hresult': '0x80004005'},
            {'provider': 2, 'hresult': -2147467259},
            {'provider': 2, 'success': False},
        ]
        events = [{'seq': seq, 'kind': 'provider', 'data': data}
                  for seq, data in enumerate(failures)]
        events.extend({'seq': seq, 'kind': 'provider', 'data': {
            'provider': 2, 'hresult': '0x00000000',
        }} for seq in range(3, 3003))
        report = summarize({'schema': 1}, events)
        self.assertEqual(report['providers'][:3], events[:3])
        self.assertEqual(report['providers'][-1], events[-1])
        self.assertEqual(len(report['providers']), 2000)
        self.assertEqual(report['provider_events_omitted'], 1003)

    def test_pending_and_invalid_statuses_do_not_displace_recent_events(self):
        from session import summarize
        for status in ('0x8000000a', '0x00000001', 'invalid', None):
            with self.subTest(status=status):
                events = [{'seq': seq, 'kind': 'provider', 'data': {
                    'provider': 1, 'hresult': status if seq == 0 else '0x00000000',
                }} for seq in range(2001)]
                report = summarize({'schema': 1}, events)
                self.assertEqual(report['providers'], events[1:])

    def test_provider_limit_is_shared_across_busy_providers(self):
        bundle = ROOT / 'busy-providers'
        bundle.mkdir()
        events = [{'seq': seq, 'kind': 'provider', 'data': {
            'provider': (2, 4, 8)[seq // 3000], 'event': 'fixture',
        }} for seq in range(9000)]
        (bundle / 'manifest.json').write_text(json.dumps({'schema': 1}))
        (bundle / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
        report = export(bundle, ROOT / 'busy-providers.log')
        counts = [sum(event['data']['provider'] == provider for event in report['providers']) for provider in (2, 4, 8)]
        self.assertEqual(len(report['providers']), 2000)
        self.assertLessEqual(max(counts) - min(counts), 1)
        self.assertEqual(report['provider_events_omitted'], 7000)
        self.assertEqual(report['providers'][-1]['seq'], 8999)

    def test_provider_selection_handles_the_limit_and_empty_sessions(self):
        for count in (0, 1, 1999, 2000, 2001):
            with self.subTest(count=count):
                bundle = ROOT / ('provider-limit-' + str(count))
                bundle.mkdir()
                events = [{'seq': seq, 'kind': 'provider', 'data': {
                    'provider': 8, 'event': 'WaitBegin',
                }} for seq in range(count)]
                (bundle / 'manifest.json').write_text(json.dumps({'schema': 1}))
                (bundle / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
                report = export(bundle, ROOT / ('provider-limit-' + str(count) + '.log'))
                self.assertEqual(report['providers'], events[-2000:])
                self.assertEqual(report['provider_events_omitted'], max(0, count - 2000))

    def test_failed_capture_exports_partial_history_without_raw_memory(self):
        prefix = ROOT / 'failure-prefix'
        prefix.mkdir()
        target = ROOT / 'target.exe'
        target.write_bytes(b'fixture')
        logs = prefix / 'logs/runs'
        events = [{'kind': 'process_create', 'pid': 1, 'tid': 2, 'path': str(target)},
                  {'kind': 'exception', 'pid': 1, 'tid': 2, 'first_chance': True, 'code': '0xc0000005'},
                  {'kind': 'memory', 'pid': 1, 'tid': 2, 'data': 'PRIVATE_MEMORY'},
                  {'kind': 'dump', 'pid': 1, 'tid': 2, 'path': str(ROOT / 'private.dmp'), 'data': 'PRIVATE_DUMP'}]
        def capture(wine, prefix, bundle, **options):
            bundle.mkdir(mode=0o700)
            (bundle / 'manifest.json').write_text(json.dumps({'schema': 1, 'completed': False, 'target': str(target), 'modules': {}, 'unix_modules': {}}))
            (bundle / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
            for event in events:
                options['observer'](event)
            live = next(logs.glob('*.running.log')).read_text()
            self.assertNotIn('PRIVATE_MEMORY', live)
            self.assertNotIn('PRIVATE_DUMP', live)
            self.assertNotIn(str(ROOT), live)
            raise RuntimeError('private path: ' + str(ROOT))
        with patch('tracing.capture', side_effect=capture):
            with self.assertRaises(RuntimeError):
                trace('unused', prefix, logs, [str(target)])
        self.assertFalse(list(logs.glob('*.running.log')))
        report = next(logs.glob('*.log'))
        content = report.read_text()
        self.assertNotIn('PRIVATE_MEMORY', content)
        self.assertNotIn('PRIVATE_DUMP', content)
        self.assertNotIn(str(ROOT), content)
        value = json.loads(content)
        self.assertFalse(value['manifest']['completed'])
        self.assertEqual(value['manifest']['capture_error_type'], 'RuntimeError')
        self.assertTrue(any(item['kind'] == 'exception' and item['first_chance'] for item in value['timeline']))
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)

    def test_live_byte_limit_is_marked_and_partial_log_survives_setup_failure(self):
        prefix = ROOT / 'limit-prefix'
        prefix.mkdir()
        target = ROOT / 'limit.exe'
        target.write_bytes(b'fixture')
        logs = prefix / 'logs/runs'
        def capture(wine, prefix, bundle, **options):
            options['observer']({'kind': 'fixture', 'data': 'x' * (16 * 1024 * 1024 + 1)})
            raise RuntimeError('setup failed')
        with patch('tracing.capture', side_effect=capture):
            with self.assertRaises(RuntimeError):
                trace('unused', prefix, logs, [str(target)])
        report = next(logs.glob('*.running.log'))
        rows = [json.loads(line) for line in report.read_text().splitlines()]
        self.assertLess(report.stat().st_size, 4096)
        self.assertTrue(any(item.get('kind') == 'capture_limit' for item in rows))
        self.assertTrue(any(item.get('kind') == 'capture_error' for item in rows))
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main(verbosity=2)
