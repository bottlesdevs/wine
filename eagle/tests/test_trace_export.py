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


class TraceExports(unittest.TestCase):
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
