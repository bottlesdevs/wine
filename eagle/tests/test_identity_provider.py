import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ['EAGLE_IDENTITY_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])


class IdentityProvider(unittest.TestCase):
    def test_observer_controls_correlation_and_thread_state(self):
        for profile in ('crash', 'winrt', 'trace'):
            output = ROOT / (profile + '.txt')
            bundle = ROOT / profile
            command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                       '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--timeout', '30',
                       '--profile', profile, str(ROOT / 'target.exe'), 'Z:' + str(output).replace('/', '\\')]
            if profile == 'trace':
                logs = ROOT / 'prefix/logs/runs'
                before = set(logs.glob('*.session'))
                command = [str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'),
                           '--prefix', str(ROOT / 'prefix'), '--logs', str(logs), '--',
                           str(ROOT / 'target.exe'), 'Z:' + str(output).replace('/', '\\')]
            result = subprocess.run(command, capture_output=True, text=True, timeout=50)
            self.assertEqual(result.returncode, 0, result.stderr[-4000:])
            fields = output.read_text().split()
            self.assertEqual(fields[2], '0')
            if profile == 'trace':
                sessions = set(logs.glob('*.session')) - before
                self.assertEqual(len(sessions), 1)
                bundle = sessions.pop()
            events = [json.loads(line) for line in (bundle / 'events.jsonl').read_text().splitlines()]
            values = [event['data'] for event in events if event['kind'] == 'provider' and event['data']['event'] == 'identity.stage']
            self.assertEqual(len(values), 0 if profile == 'crash' else 7)
            self.assertEqual(next(event['code'] for event in events if event['kind'] == 'process_exit' and event['pid'] == int(fields[1])), 0)
            if values:
                self.assertEqual([value['stage'] for value in values if value['request_id'] == 41], ['begin', 'transport', 'response', 'complete'])
                self.assertEqual([value['stage'] for value in values if value['request_id'] == 42], ['begin', 'transport', 'complete'])
                self.assertEqual(values[-1]['hresult'], '0x80070005')
                self.assertTrue(all(set(value) == {'provider', 'event', 'hresult', 'request_id', 'operation', 'transport', 'stage', 'caller'} for value in values))


if __name__ == '__main__':
    unittest.main()
