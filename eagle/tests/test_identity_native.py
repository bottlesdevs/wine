import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ['EAGLE_IDENTITY_BRIDGE_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
BITS = int(os.environ['EAGLE_IDENTITY_BRIDGE_BITS'])


class IdentityNative(unittest.TestCase):
    def capture(self, name, profile, invalid=False, token=None):
        root = ROOT / name;root.mkdir()
        marker = root / 'result.txt'
        bundle = root / 'session'
        environment = dict(os.environ, DBUS_SESSION_BUS_ADDRESS='unix:path=' + str(root / 'no-bus'))
        environment.pop('SODA_IDENTITY_BRIDGE_SOCKET', None)
        command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                   '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile,
                   '--timeout', '30', str(ROOT / 'target.exe'), 'Z:' + str(marker).replace('/', '\\')]
        if invalid:command.append('invalid')
        if token:command.append(token)
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=50)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        fields = marker.read_text().split()
        expected = '80070057' if invalid else '80070426'
        self.assertEqual((fields[1], fields[2], fields[3]), ('5' if token == 'interactive' else '3', expected, '0'))
        events = [json.loads(line) for line in (bundle / 'events.jsonl').read_text().splitlines()]
        self.assertEqual(next(event['code'] for event in events if event['kind'] == 'process_exit' and event['pid'] == int(fields[0])), 0)
        architecture = 'x86_64' if BITS == 64 else 'i386'
        module = CANDIDATE / f'lib/wine/{architecture}-windows/windows.security.authentication.onlineid.dll'
        expected_hash = hashlib.sha256(module.read_bytes()).hexdigest()
        loaded = next(event for event in events if event['kind'] == 'module_load' and event.get('path', '').lower().endswith('windows.security.authentication.onlineid.dll'))
        self.assertEqual(loaded['identity']['sha256'], expected_hash)
        providers = json.loads((CANDIDATE / 'share/eagle/providers.json').read_text())
        self.assertEqual(providers['provider_sha256'][architecture + '/windows.security.authentication.onlineid'], expected_hash)
        stages = [event['data'] for event in events if event['kind'] == 'provider' and event['data'].get('event') == 'identity.stage']
        expected_stages = [] if profile == 'crash' else ['begin', 'complete'] if invalid else ['begin', 'cache', 'cache', 'complete']
        if token:
            expected_stages = ['begin', 'cache', 'cache', 'complete'] if token == 'silent' else ['begin', 'cache', 'begin', 'cache', 'cache', 'complete', 'cache', 'complete']
        self.assertEqual([value['stage'] for value in stages], expected_stages)
        if stages:
            self.assertTrue(all(value['transport'] == 'native' for value in stages))
            expected_operations = {'get_token', 'authorize'} if token == 'interactive' else {'get_token'} if token else {'list_accounts'}
            self.assertEqual({value['operation'] for value in stages}, expected_operations)
            for operation in expected_operations:
                group = [value for value in stages if value['operation'] == operation]
                self.assertEqual(len({value['request_id'] for value in group}), 1)
                self.assertEqual((group[0]['stage'], group[-1]['stage']), ('begin', 'complete'))
                self.assertEqual(group[-1]['hresult'], '0x' + expected)
            self.assertEqual(stages[-1]['hresult'], '0x' + expected)

    def test_native_keyring_failure_and_invalid_client(self):
        self.capture('n-off', 'crash')
        self.capture('n-cache', 'winrt')
        self.capture('n-invalid', 'winrt', invalid=True)
        self.capture('n-silent', 'winrt', token='silent')
        self.capture('n-auth', 'winrt', token='interactive')


if __name__ == '__main__':
    unittest.main()
