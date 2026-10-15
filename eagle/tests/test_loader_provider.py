import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ['EAGLE_LOADER_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])


class LoaderProvider(unittest.TestCase):
    def capture(self, name, profile, extra=(), arguments=()):
        bundle = ROOT / name
        output = ROOT / (name + '-state.txt')
        command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                   '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile,
                   '--timeout', '120', *extra, str(ROOT / 'target.exe'),
                   str(ROOT / 'private-path-sentinel/EagleLoaderFixture.dll'), str(output), *arguments]
        result = subprocess.run(command, capture_output=True, text=True, timeout=150)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        events = [json.loads(line) for line in (bundle / 'events.jsonl').read_text().splitlines()]
        pid = next(event['pid'] for event in events if event['kind'] == 'process_create')
        self.assertEqual(next(event['code'] for event in events if event['kind'] == 'process_exit' and event['pid'] == pid), 0)
        manifest = json.loads((bundle / 'manifest.json').read_text())
        self.assertTrue(manifest['completed'])
        self.assertEqual(manifest['dropped_events'], 0)
        expected = os.environ.get('EAGLE_LOADER_SHA256')
        if expected:
            self.assertTrue(any(event['kind'] == 'module_load' and event.get('path', '').lower().endswith('kernelbase.dll')
                                and event.get('identity', {}).get('sha256') == expected for event in events))
        return events, output.read_text()

    def test_disabled_enabled_results_names_ordinals_and_state(self):
        off, before = self.capture('off', 'crash')
        self.assertFalse(any(event['kind'] == 'provider' for event in off))
        events, after = self.capture('on', 'loader')
        self.assertEqual(before, after)
        providers = [event for event in events if event['kind'] == 'provider']
        rows = [event['data'] for event in providers if event['data']['provider'] == 32]
        self.assertTrue(rows)
        self.assertTrue(all(row['provider'] == 32 for row in rows))
        self.assertFalse(any('private-path-sentinel' in json.dumps(row) for row in rows))
        missing = next(row for row in rows if row['name'] == 'EagleMissingFixture.dll')
        self.assertEqual(missing['hresult'], '0x8007007e')
        self.assertEqual(missing['win32_error'], 126)
        self.assertFalse(missing['success'])
        self.assertEqual(missing['flags'], 0x800)
        named = next(row for row in rows if row['event'] == 'loader.GetProcAddress' and row['name'] == 'EagleLoaderValue')
        named_results = [row for row in rows if row['event'] == 'loader.GetProcAddress' and row['name'] == 'EagleLoaderValue']
        self.assertEqual(len(named_results), 2)
        self.assertEqual(named_results[0]['address'], named_results[1]['address'])
        self.assertTrue(named['success'])
        self.assertNotEqual(int(named['address'], 16), 0)
        ordinal = next(row for row in rows if row['event'] == 'loader.GetProcAddress' and row['ordinal'] == 9)
        self.assertTrue(ordinal['success'])
        self.assertFalse(ordinal['name_available'])
        self.assertTrue(any(event['data']['provider'] == 64 and event['data']['event'] == 'loader.LdrGetProcedureAddress'
                            and event['data']['ordinal'] == 9 and event['data']['success']
                            and not event['data']['name_available'] for event in providers))
        quoted = next(row for row in rows if row['name'] == 'EagleMissing?Quote')
        self.assertTrue(quoted['name_sanitized'])
        self.assertEqual(quoted['win32_error'], 127)
        truncated = next(row for row in rows if row['name'] == 'X' * 127)
        self.assertTrue(truncated['name_truncated'])
        self.assertTrue(truncated['name_available'])
        self.assertTrue(any(row['event'] == 'loader.GetProcAddress' and not row['name_available']
                            and row['name_truncated'] for row in rows))
        packaged = next(row for row in rows if row['event'] == 'loader.LoadPackagedLibrary')
        self.assertEqual(packaged['win32_error'], 15700)
        self.assertTrue(any(event['data']['event'] == 'loader.LoadLibraryExW' and event.get('frame', {}).get('symbol') == 'main'
                            and event['frame'].get('line', 0) > 0 for event in providers))
        self.assertTrue(any(event['kind'] == 'module_unload' for event in events))

    def test_hresult_snapshots_and_budget_marker(self):
        events, _ = self.capture('trigger', 'loader', ['--on-hresult', '0x8007007f', '--trigger-action', 'snapshot'])
        failures = [event for event in events if event['kind'] == 'provider' and event['data'].get('hresult') == '0x8007007f']
        self.assertGreaterEqual(len(failures), 3)
        self.assertEqual(len([event for event in events if event['kind'] == 'trigger']), len(failures))
        self.assertEqual(len([event for event in events if event['kind'] == 'snapshot']), len(failures))
        self.assertTrue(all(any(frame.get('symbol') == 'main' for frame in event.get('frames', []))
                            for event in events if event['kind'] == 'snapshot'))
        events, _ = self.capture('budget', 'loader', arguments=['budget'])
        rows = [event['data'] for event in events if event['kind'] == 'provider' and event['data']['provider'] == 32]
        self.assertEqual(len(rows), 4097)
        self.assertEqual(rows[-1], {'provider': 32, 'event': 'ObserverBudgetExceeded', 'limit': 4096})

    def test_automatic_trace_includes_loader_outcomes(self):
        output = ROOT / 'trace-state.txt'
        result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'),
                                 '--prefix', str(ROOT / 'prefix'), '--logs', str((ROOT / 'prefix').resolve() / 'logs/runs'),
                                 '--', str(ROOT / 'target.exe'), str(ROOT / 'private-path-sentinel/EagleLoaderFixture.dll'),
                                 str(output)], capture_output=True, text=True, timeout=150)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        report = json.loads(Path(json.loads(result.stdout)['data']['log']).read_text())
        self.assertTrue(report['manifest']['completed'])
        self.assertTrue(any(event['data'].get('name') == 'EagleMissingFixture.dll' and event['data']['provider'] == 32
                            for event in report['providers']))
        (ROOT / 'automatic-trace-report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    unittest.main()
