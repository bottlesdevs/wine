import base64
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import time
import unittest

ROOT = Path(os.environ['EAGLE_IDENTITY_HTTP_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
BITS = int(os.environ['EAGLE_IDENTITY_BRIDGE_BITS'])


class IdentityHttp(unittest.TestCase):
    def capture(self, name, mode, storage, error):
        root = ROOT / name;root.mkdir(mode=0o700)
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
                service = subprocess.Popen([os.environ['EAGLE_IDENTITY_SECRET_SERVICE'], str(root / 'ready'),
                                            str(root / 'calls.log'), storage],
                                           env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=address),
                                           stdout=service_log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 5
                    while not (root / 'ready').exists() and service.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertIsNone(service.poll())
                    self.assertEqual((root / 'ready').read_text(), 'ready\n')
                    marker = root / 'result.txt'
                    bundle = root / 'session'
                    environment = dict(os.environ, DBUS_SESSION_BUS_ADDRESS=address,
                                       EAGLE_FIXTURE_HTTP_MODE=mode,
                                       EAGLE_FIXTURE_HTTP_LOG='Z:' + str(root / 'http.log').replace('/', '\\'))
                    environment.pop('SODA_IDENTITY_BRIDGE_SOCKET', None)
                    environment.pop('_NT_SYMBOL_PATH', None)
                    environment['WINEDLLOVERRIDES'] = environment.get('WINEDLLOVERRIDES', '') + ';winhttp=n'
                    command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                               '--prefix', str(ROOT / 'prefix'), '--session', str(bundle),
                               '--profile', 'crash' if name == 'off' else 'winrt', '--timeout', '30',
                               str(ROOT / 'target.exe'), 'Z:' + str(marker).replace('/', '\\'),
                               'refresh-interactive' if name == 'auth' else 'refresh']
                    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=50)
                    self.assertEqual(result.returncode, 0, result.stderr[-4000:])
                    fields = marker.read_text().split()
                    self.assertEqual(fields[1:], ['0', '00000000', '1'] if error == '00000000' else ['3', error, '0'])
                    manifest = json.loads((bundle / 'manifest.json').read_text())
                    self.assertTrue(manifest['completed'])
                    self.assertEqual(manifest['collector_exit'], 0)
                    self.assertEqual(manifest['dropped_events'], 0)
                    raw = (bundle / 'events.jsonl').read_text()
                    events = [json.loads(line) for line in raw.splitlines()]
                    self.assertEqual(next(event['code'] for event in events if event['kind'] == 'process_exit' and event['pid'] == int(fields[0])), 0)
                    architecture = 'x86_64' if BITS == 64 else 'i386'
                    modules = {'winhttp.dll': ROOT / 'winhttp.dll',
                               'windows.security.authentication.onlineid.dll': CANDIDATE / f'lib/wine/{architecture}-windows/windows.security.authentication.onlineid.dll'}
                    for name_on_disk, image in modules.items():
                        loaded = next(event for event in events if event['kind'] == 'module_load' and event['pid'] == int(fields[0]) and event.get('path', '').lower().endswith(name_on_disk))
                        self.assertEqual(loaded['identity']['sha256'], hashlib.sha256(image.read_bytes()).hexdigest())
                    stages = [event['data'] for event in events if event['kind'] == 'provider' and event['data'].get('event') == 'identity.stage']
                    expected = ['begin', 'cache', 'cache', 'request', 'request']
                    if name in ('ok', 'off', 'auth', 'bad', 'save'):expected += ['response']
                    if name in ('ok', 'off', 'auth', 'save'):expected += ['persist', 'persist']
                    expected += ['complete']
                    token = [value for value in stages if value['operation'] == 'get_token']
                    self.assertEqual([value['stage'] for value in token], [] if name == 'off' else expected)
                    results = ['0x8000000a', '0x8000000a', '0x00000000', '0x8000000a',
                               '0x' + error if name in ('to', 'big') else '0x00000000']
                    if name in ('ok', 'off', 'auth', 'bad', 'save'):
                        results += ['0x' + error if name == 'bad' else '0x00000000']
                    if name in ('ok', 'off', 'auth', 'save'):
                        results += ['0x8000000a', '0x' + error if name == 'save' else '0x00000000']
                    results += ['0x' + error]
                    self.assertEqual([value['hresult'] for value in token], [] if name == 'off' else results)
                    if stages:
                        self.assertTrue(all(value['transport'] == 'native' for value in stages))
                        self.assertEqual(token[-1]['hresult'], '0x' + error)
                        self.assertEqual(len({value['request_id'] for value in token}), 1)
                        authorize = [value for value in stages if value['operation'] == 'authorize']
                        self.assertEqual([value['stage'] for value in authorize], ['begin', 'cache', 'cache', 'complete'] if name == 'auth' else [])
                        if authorize:
                            self.assertEqual([value['hresult'] for value in authorize],
                                             ['0x8000000a', '0x8000000a', '0x00000000', '0x00000000'])
                            self.assertNotEqual(authorize[0]['request_id'], token[0]['request_id'])
                    else:self.assertEqual(name, 'off')
                    calls = (root / 'calls.log').read_text().splitlines()
                    self.assertEqual('StoreMatched' in calls, name in ('ok', 'off', 'auth', 'save'))
                    self.assertNotIn('StoreMismatch', calls)
                    self.assertIn('SendRequest', (root / 'http.log').read_text().splitlines())
                    for sentinel in ('fixture-access-not-a-token', 'fixture-refresh-not-a-token',
                                     'fixture-next-refresh-not-a-token', 'fixture-user@example.invalid', 'fixture-account-id'):
                        self.assertNotIn(sentinel, raw)
                    claims = {'aud': '11111111-1111-1111-1111-111111111111', 'oid': 'fixture-account-id',
                              'preferred_username': 'fixture-user@example.invalid', 'name': 'Fixture Account', 'tid': 'fixture-tenant'}
                    encoded = base64.urlsafe_b64encode(json.dumps(claims, separators=(',', ':')).encode()).decode().rstrip('=')
                    self.assertNotIn(encoded, raw)
                    self.assertIsNone(service.poll())
                finally:
                    if service.poll() is None:service.terminate()
                    service.wait(timeout=10)
            finally:
                if bus.poll() is None:bus.terminate()
                bus.wait(timeout=10)
                bus.stdout.close()

    def test_native_request_response_and_persistence(self):
        destination = ROOT / 'prefix/drive_c/windows' / ('system32' if BITS == 64 else 'syswow64') / 'winhttp.dll'
        self.assertTrue(destination.parent.resolve().is_relative_to((ROOT / 'prefix').resolve()))
        link = os.readlink(destination) if destination.is_symlink() else None
        backup = ROOT / 'original-winhttp.dll'
        if link is not None:destination.unlink()
        elif destination.exists():destination.rename(backup)
        try:
            shutil.copy2(ROOT / 'winhttp.dll', destination)
            for name, mode, storage, error in [('off', 'success', 'record', '00000000'),
                                             ('ok', 'success', 'record', '00000000'),
                                             ('auth', 'success', 'record', '00000000'),
                                             ('to', 'timeout', 'record', '80072ee2'),
                                             ('http', 'http-error', 'record', '80070005'),
                                             ('bad', 'bad-response', 'record', '80070057'),
                                             ('big', 'oversized', 'record', '800700df'),
                                             ('save', 'success', 'store-error', '80070426')]:
                self.capture(name, mode, storage, error)
        finally:
            destination.unlink(missing_ok=True)
            if link is not None:destination.symlink_to(link)
            elif backup.exists():backup.rename(destination)


if __name__ == '__main__':
    unittest.main()
