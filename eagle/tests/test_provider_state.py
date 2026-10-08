import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ['EAGLE_STATE_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])


class ProviderState(unittest.TestCase):
    def test_enabled_disabled_and_unreadable_guid_preserve_thread_state(self):
        for profile in ('process', 'trace'):
            bundle = ROOT / profile
            output = ROOT / f'{profile}.txt'
            logs = (ROOT / 'prefix').resolve() / 'logs/runs'
            before = set(logs.glob('*.session'))
            command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                       '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile,
                       '--timeout', '30', str(ROOT / 'target.exe'), 'Z:' + str(output.resolve()).replace('/', '\\')]
            if profile == 'trace':
                command = [str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'),
                           '--prefix', str(ROOT / 'prefix'), '--logs', str(logs), '--',
                           str(ROOT / 'target.exe'), 'Z:' + str(output.resolve()).replace('/', '\\')]
            result = subprocess.run(command, capture_output=True, text=True, timeout=50)
            self.assertEqual(result.returncode, 0, result.stderr[-4000:])
            if profile == 'trace':
                sessions = list(set(logs.glob('*.session')) - before)
                self.assertEqual(len(sessions), 1)
                bundle = sessions[0]
            events = [json.loads(line) for line in (bundle / 'events.jsonl').read_text().splitlines()]
            pid = next(item['pid'] for item in events if item['kind'] == 'process_create' and item['path'].lower().endswith('target.exe'))
            self.assertEqual(next(item['code'] for item in events if item['kind'] == 'process_exit' and item['pid'] == pid), 0)
            manifest = json.loads((bundle / 'manifest.json').read_text())
            self.assertTrue(manifest['completed'])
            self.assertFalse(manifest.get('timeout'))
            self.assertEqual(manifest['dropped_events'], 0)
            rows = [line.split() for line in output.read_text().splitlines()]
            self.assertEqual(len(rows), 8)
            for i, row in enumerate(rows):
                self.assertEqual(row, [str(i), '12345678', '12345678', 'c0000022', 'c0000022'])
            providers = [item['data'] for item in events if item['kind'] == 'provider']
            if profile == 'process':
                self.assertFalse(providers)
            else:
                self.assertEqual(len([item for item in providers if item['event'] == 'state.probe']), 6)
                self.assertTrue(any(item['event'] == 'WaitBegin' for item in providers))


if __name__ == '__main__':
    unittest.main(verbosity=2)
