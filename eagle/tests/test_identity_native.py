import base64
import hashlib
import json
import os
import select
from pathlib import Path
import subprocess
import time
import unittest

ROOT = Path(os.environ['EAGLE_IDENTITY_BRIDGE_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
BITS = int(os.environ['EAGLE_IDENTITY_BRIDGE_BITS'])


class IdentityNative(unittest.TestCase):
    def capture(self, name, profile, invalid=False, token=None, bus=None, success=False, record=False, wrong=False):
        root = ROOT / name;root.mkdir()
        marker = root / 'result.txt'
        bundle = root / 'session'
        environment = dict(os.environ, DBUS_SESSION_BUS_ADDRESS=bus or 'unix:path=' + str(root / 'no-bus'))
        environment.pop('SODA_IDENTITY_BRIDGE_SOCKET', None)
        command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                   '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile,
                   '--timeout', '30', str(ROOT / 'target.exe'), 'Z:' + str(marker).replace('/', '\\')]
        if invalid:command.append('invalid')
        if token:command.append(token)
        if record:command.append('record')
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=50)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        fields = marker.read_text().split()
        expected = '00000000' if success else '80070005' if wrong else '80070057' if invalid else '80070426'
        self.assertEqual((fields[1], fields[2], fields[3]), ('0' if success else '5' if token == 'interactive' else '3', expected, '1' if record else '0'))
        manifest = json.loads((bundle / 'manifest.json').read_text())
        self.assertTrue(manifest['completed'])
        self.assertEqual(manifest['collector_exit'], 0)
        self.assertEqual(manifest['dropped_events'], 0)
        raw = (bundle / 'events.jsonl').read_text()
        events = [json.loads(line) for line in raw.splitlines()]
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
        for sentinel in ('fixture-user@example.invalid', 'fixture-account-id', 'fixture-refresh-not-a-token'):
            self.assertNotIn(sentinel, raw)
        claims = {'aud': '11111111-1111-1111-1111-111111111111', 'oid': 'fixture-account-id',
                  'preferred_username': 'fixture-user@example.invalid', 'name': 'Fixture Account', 'tid': 'fixture-tenant'}
        for audience in ('11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'):
            claims['aud'] = audience
            encoded = base64.urlsafe_b64encode(json.dumps(claims, separators=(',', ':')).encode()).decode().rstrip('=')
            self.assertNotIn(encoded, raw)
        if bus and profile != 'crash':
            self.assertEqual([value['hresult'] for value in stages],
                             ['0x8000000a', '0x8000000a', '0x00000000' if success or wrong else '0x80070426', '0x' + expected])
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

    def test_native_storage_service_controls(self):
        fixture = Path(os.environ['EAGLE_IDENTITY_SECRET_SERVICE'])
        for index, mode in enumerate(('empty', 'denied', 'record', 'wrong-audience')):
            root = ROOT / ('s' + str(index));root.mkdir(mode=0o700)
            path = root / 'b.sock'
            with (root / 'bus.log').open('w') as bus_log, (root / 'service.log').open('w') as service_log:
                bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--nopidfile',
                                        '--address=unix:path=' + str(path), '--print-address=1'],
                                       stdout=subprocess.PIPE, stderr=bus_log, text=True)
                try:
                    self.assertTrue(select.select([bus.stdout], [], [], 5)[0])
                    address = bus.stdout.readline().strip()
                    self.assertTrue(address.startswith('unix:path=' + str(path)))
                    path.chmod(0o600)
                    service = subprocess.Popen([str(fixture), str(root / 'ready'), str(root / 'calls.log'), mode],
                                               env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=address),
                                               stdout=service_log, stderr=subprocess.STDOUT)
                    try:
                        deadline = time.monotonic() + 5
                        while not (root / 'ready').exists() and service.poll() is None and time.monotonic() < deadline:
                            time.sleep(0.05)
                        self.assertIsNone(service.poll())
                        self.assertEqual((root / 'ready').read_text(), 'ready\n')
                        if mode == 'empty':
                            self.capture('s-off', 'crash', bus=address, success=True)
                            self.capture('s-empty', 'winrt', bus=address, success=True)
                        elif mode == 'denied':
                            self.capture('s-denied', 'winrt', bus=address)
                        elif mode == 'record':
                            self.capture('s-rec-off', 'crash', bus=address, success=True, record=True)
                            self.capture('s-record', 'winrt', bus=address, success=True, record=True)
                        else:
                            self.capture('s-wrong', 'winrt', bus=address, wrong=True)
                        self.assertIsNone(service.poll())
                        calls = (root / 'calls.log').read_text().splitlines()
                        self.assertEqual(calls.count('SearchItems'), 2 if mode in ('empty', 'record') else 1, calls)
                        self.assertTrue(set(calls) <= {'SearchItems', 'Unlock', 'OpenSession', 'GetSecret', 'GetSecrets', 'Close'}, calls)
                        if mode in ('record', 'wrong-audience'):
                            self.assertTrue(set(calls) & {'GetSecret', 'GetSecrets'}, calls)
                    finally:
                        if service.poll() is None:service.terminate()
                        service.wait(timeout=10)
                finally:
                    if bus.poll() is None:bus.terminate()
                    bus.wait(timeout=10)
                    bus.stdout.close()

    def test_native_keyring_failure_and_invalid_client(self):
        self.capture('n-off', 'crash')
        self.capture('n-cache', 'winrt')
        self.capture('n-invalid', 'winrt', invalid=True)
        self.capture('n-silent', 'winrt', token='silent')
        self.capture('n-auth', 'winrt', token='interactive')


if __name__ == '__main__':
    unittest.main()
