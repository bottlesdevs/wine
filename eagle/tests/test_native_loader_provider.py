import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ['EAGLE_NATIVE_LOADER_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
BITS = int(os.environ['EAGLE_NATIVE_LOADER_BITS'])


class NativeLoaderProvider(unittest.TestCase):
    def capture(self, name, mode, profile='loader', extra=()):
        bundle = ROOT / name
        output = ROOT / (name + '-state.txt')
        result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                                 '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile,
                                 '--timeout', '120', *extra, str(ROOT / 'target.exe'),
                                 str(ROOT / 'EagleParentFixture.dll'), str(output), mode],
                                capture_output=True, text=True, timeout=150)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        events = [json.loads(line) for line in (bundle / 'events.jsonl').read_text().splitlines()]
        pid = next(event['pid'] for event in events if event['kind'] == 'process_create')
        self.assertEqual(next(event['code'] for event in events if event['kind'] == 'process_exit' and event['pid'] == pid), 0)
        manifest = json.loads((bundle / 'manifest.json').read_text())
        self.assertTrue(manifest['completed'])
        self.assertEqual(manifest['dropped_events'], 0)
        architecture = 'x86_64' if BITS == 64 else 'i386'
        expected = hashlib.sha256((CANDIDATE / f'lib/wine/{architecture}-windows/ntdll.dll').read_bytes()).hexdigest()
        self.assertTrue(any(event['kind'] == 'module_load' and event.get('path', '').lower().endswith('ntdll.dll')
                            and event.get('identity', {}).get('sha256') == expected for event in events))
        return events, output.read_text()

    def paired(self, mode):
        off, before = self.capture(mode + '-off', mode, 'crash')
        events, after = self.capture(mode + '-on', mode)
        self.assertFalse(any(event['kind'] == 'provider' for event in off))
        self.assertEqual(before, after)
        return [event['data'] for event in events if event['kind'] == 'provider' and event['data']['provider'] == 64]

    def test_missing_dependency_native_calls_and_early_path_failure(self):
        rows = self.paired('missing')
        self.assertTrue(any(row['event'] == 'loader.DependencyFailure' and row['name'] == 'EagleDependencyFixture.dll'
                            and row['ntstatus'] == '0xc0000135' and row['win32_error'] == 126 for row in rows))
        self.assertTrue(any(row['event'] == 'loader.LdrLoadDll' and row['name'] == 'EagleNativeMissingFixture.dll'
                            and row['ntstatus'] == '0xc0000135' for row in rows))
        self.assertTrue(any(row['event'] == 'loader.LdrGetProcedureAddress' and row['name'] == 'EagleNativeMissingExport'
                            and row['ntstatus'] == '0xc000007a' and row['win32_error'] == 127 for row in rows))
        self.assertTrue(any(row['event'] == 'loader.LdrGetProcedureAddress' and row['ordinal'] == 65535
                            and not row['name_available'] and row['ntstatus'] == '0xc000007a' for row in rows))
        self.assertTrue(any(row['event'] == 'loader.LdrLoadDll' and row['name'] == 'EagleInvalidSearchFlags.dll'
                            and row['ntstatus'] == '0xc000000d' and row['hresult'] == '0x80070057' for row in rows))
        self.assertTrue(any(row['event'] == 'loader.LdrUnloadDll' and not row['success']
                            and row['ntstatus'] == '0xc0000135' for row in rows))

    def test_success_name_bounds_and_basename_privacy(self):
        rows = self.paired('names')
        self.assertFalse(any('private-path-sentinel' in json.dumps(row) for row in rows))
        self.assertTrue(any(row.get('name') == 'EagleMissing?Quote' and row['name_sanitized'] for row in rows))
        self.assertTrue(any(row.get('name') == 'X' * 127 and row['name_truncated'] and row['name_available'] for row in rows))
        self.assertTrue(any(row['event'] == 'loader.LdrGetProcedureAddress' and not row['name_available'] for row in rows))
        self.assertTrue(any(row.get('name') == 'EagleBoundsMissing.dll' for row in rows))
        self.assertTrue(any(row['event'] == 'loader.LdrLoadDll' and row['success'] for row in rows))
        self.assertTrue(any(row['event'] == 'loader.LdrGetProcedureAddress' and row.get('name') == 'GetCurrentThreadId'
                            and row['success'] for row in rows))
        self.assertTrue(any(row['event'] == 'loader.LdrUnloadDll' and row['success'] for row in rows))

    def test_new_thread_recursion_state_is_initialized(self):
        rows = self.paired('threads')
        observed = {row.get('name') for row in rows if row['event'] == 'loader.LdrLoadDll'}
        self.assertTrue(all('EagleThreadMissing%02d.dll' % i in observed for i in range(16)))

    def test_independent_native_budget_and_post_budget_api_state(self):
        rows = self.paired('budget')
        self.assertEqual(len(rows), 4097)
        self.assertEqual(rows[-1], {'provider': 64, 'event': 'ObserverBudgetExceeded', 'limit': 4096})

    def test_native_hresult_triggers_resolve_fixture_source(self):
        events, _ = self.capture('trigger', 'missing', extra=['--on-hresult', '0x80070057', '--trigger-action', 'snapshot'])
        failures = [event for event in events if event['kind'] == 'provider' and event['data'].get('hresult') == '0x80070057']
        self.assertEqual(len(failures), 1)
        self.assertEqual(len([event for event in events if event['kind'] == 'trigger']), 1)
        snapshots = [event for event in events if event['kind'] == 'snapshot']
        self.assertEqual(len(snapshots), 1)
        self.assertTrue(any(frame.get('symbol') == 'main' and frame.get('line', 0) > 0 for frame in snapshots[0].get('frames', [])))

    def test_automatic_trace_includes_native_loader(self):
        output = ROOT / 'automatic-state.txt'
        result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'),
                                 '--prefix', str(ROOT / 'prefix'), '--logs', str((ROOT / 'prefix').resolve() / 'logs/runs'),
                                 '--', str(ROOT / 'target.exe'), str(ROOT / 'EagleParentFixture.dll'), str(output), 'missing'],
                                capture_output=True, text=True, timeout=150)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        report = json.loads(Path(json.loads(result.stdout)['data']['log']).read_text())
        self.assertTrue(report['manifest']['completed'])
        self.assertTrue(any(event['data'].get('provider') == 64 and event['data'].get('name') == 'EagleDependencyFixture.dll'
                            for event in report['providers']))
        (ROOT / 'automatic-trace-report.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    unittest.main()
