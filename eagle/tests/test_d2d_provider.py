import json
import os
from pathlib import Path
import subprocess
import time
import unittest

ROOT = Path(os.environ['EAGLE_D2D_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])


class Direct2DProvider(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hold_log = (ROOT / 'desktop-holder.log').open('w')
        env = dict(os.environ, WINEPREFIX=str((ROOT / 'prefix').resolve()), WINEDEBUG='-all')
        cls.holder = subprocess.Popen([str(CANDIDATE / 'bin/wine'), str(ROOT / 'target.exe'), 'hold'],
                                      env=env, stdout=cls.hold_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and cls.holder.poll() is None:
            if 'D2D_PROVIDER_OK' in (ROOT / 'desktop-holder.log').read_text(errors='replace'):
                return
            time.sleep(0.05)
        cls.holder.terminate();cls.holder.wait(timeout=10);cls.hold_log.close()
        raise AssertionError('owned Direct2D desktop holder did not initialize')

    @classmethod
    def tearDownClass(cls):
        cls.holder.terminate();cls.holder.wait(timeout=10);cls.hold_log.close()

    def capture(self, name, profile, extra=(), arguments=()):
        bundle = ROOT / name
        command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                   '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile,
                   '--timeout', '120', *extra, str(ROOT / 'target.exe'), *arguments]
        result = subprocess.run(command, capture_output=True, text=True, timeout=150)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        events = [json.loads(line) for line in (bundle / 'events.jsonl').read_text().splitlines()]
        self.assertEqual(next(event['code'] for event in events if event['kind'] == 'process_exit'), 0)
        manifest = json.loads((bundle / 'manifest.json').read_text())
        expected = os.environ.get('EAGLE_D2D_SHA256')
        if expected:
            self.assertTrue(any(event['kind'] == 'module_load' and event.get('path', '').lower().endswith('d2d1.dll')
                                and event.get('identity', {}).get('sha256') == expected for event in events))
        self.assertTrue(manifest['completed'])
        self.assertEqual(manifest['dropped_events'], 0)
        return events

    def test_results_tags_disabled_control_and_hresult_snapshot(self):
        events = self.capture('off', 'crash')
        self.assertFalse(any(event['kind'] == 'provider' for event in events))
        events = self.capture('on', 'd2d')
        providers = [event for event in events if event['kind'] == 'provider']
        self.assertEqual([event['data']['event'] for event in providers],
                         ['d2d.flush', 'd2d.end_draw', 'd2d.end_draw', 'd2d.end_draw'])
        self.assertTrue(all(event['data']['provider'] == 16 for event in providers))
        self.assertEqual([event['data']['hresult'] for event in providers],
                         ['0x88990001', '0x00000000', '0x88990001', '0x00000000'])
        for index, tags in ((0, ('0x123456789abcdef0', '0xfedcba9876543210')),
                            (2, ('0xfedcba9876543210', '0x123456789abcdef0'))):
            self.assertEqual((providers[index]['data']['tag1'], providers[index]['data']['tag2']), tags)
        self.assertTrue(all(int(event['frame']['address'], 16) == int(event['data']['caller'], 16) for event in providers))
        self.assertEqual([event['frame'].get('symbol') for event in providers],
                         ['ID2D1DeviceContext_Flush', 'ID2D1DeviceContext_EndDraw',
                          'ID2D1DeviceContext_EndDraw', 'ID2D1DeviceContext_EndDraw'])
        self.assertTrue(all(event['frame'].get('line', 0) > 0 for event in providers))
        events = self.capture('trigger', 'd2d', ['--on-hresult', '0x88990001', '--trigger-action', 'snapshot'])
        self.assertEqual(len([event for event in events if event['kind'] == 'trigger']), 2)
        self.assertTrue(any(event['kind'] == 'snapshot' for event in events))

    def test_automatic_trace_includes_draw_results(self):
        result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'),
                                 '--prefix', str(ROOT / 'prefix'), '--logs', str((ROOT / 'prefix').resolve() / 'logs/runs'),
                                 '--', str(ROOT / 'target.exe')], capture_output=True, text=True, timeout=150)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        report = json.loads(Path(json.loads(result.stdout)['data']['log']).read_text())
        self.assertTrue(report['manifest']['completed'])
        self.assertEqual(report['manifest']['profile'], 'trace')
        providers = [event['data'] for event in report['providers'] if event['data']['provider'] == 16]
        self.assertEqual([event['hresult'] for event in providers],
                         ['0x88990001', '0x00000000', '0x88990001', '0x00000000'])
        self.assertEqual(providers[0]['tag1'], '0x123456789abcdef0')
        (ROOT / 'automatic-trace-report.json').write_text(json.dumps(report, indent=2) + '\n')

    def test_budget_is_explicit_and_stops_events(self):
        events = self.capture('budget', 'd2d', arguments=['budget'])
        providers = [event['data'] for event in events if event['kind'] == 'provider']
        self.assertEqual(len(providers), 4097)
        self.assertEqual(providers[-1], {'provider': 16, 'event': 'ObserverBudgetExceeded', 'limit': 4096})


if __name__ == '__main__':
    unittest.main()
