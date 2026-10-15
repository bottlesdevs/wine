import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import time
import unittest

ROOT = Path(os.environ['EAGLE_IDENTITY_HTTP_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
BITS = int(os.environ['EAGLE_IDENTITY_BRIDGE_BITS'])


class IdentityForce(unittest.TestCase):
    def capture(self, forced):
        root = ROOT / ('force-login' if forced else 'force-default');root.mkdir(mode=0o700)
        path = root / 'b.sock'
        bus = service = None
        try:
            with (root / 'bus.log').open('w') as bus_log, (root / 'service.log').open('w') as service_log:
                bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--nopidfile',
                                        '--address=unix:path=' + str(path), '--print-address=1'],
                                       stdout=subprocess.PIPE, stderr=bus_log, text=True)
                self.assertTrue(select.select([bus.stdout], [], [], 5)[0])
                address = bus.stdout.readline().strip()
                self.assertTrue(address.startswith('unix:path=' + str(path)));path.chmod(0o600)
                environment = dict(os.environ, DBUS_SESSION_BUS_ADDRESS=address,
                                   EAGLE_FIXTURE_HTTP_MODE='success',
                                   EAGLE_FIXTURE_HTTP_LOG='Z:' + str(root / 'http.log').replace('/', '\\'))
                environment.pop('SODA_IDENTITY_BRIDGE_SOCKET', None)
                environment.pop('_NT_SYMBOL_PATH', None)
                environment['WINEDLLOVERRIDES'] = environment.get('WINEDLLOVERRIDES', '') + ';winhttp=n'
                service = subprocess.Popen([os.environ['EAGLE_IDENTITY_SECRET_SERVICE'], str(root / 'ready'),
                                            str(root / 'calls.log'), 'record'], env=environment,
                                           stdout=service_log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 5
                while not (root / 'ready').exists() and service.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual((root / 'ready').read_text(), 'ready\n')
                marker = root / 'result.txt';bundle = root / 'session'
                command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                           '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', 'winrt',
                           '--timeout', '30', str(ROOT / 'target.exe'),
                           'Z:' + str(marker).replace('/', '\\'), 'forced' if forced else 'interactive']
                result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=50)
                self.assertEqual(result.returncode, 0, result.stderr[-4000:])
                fields = marker.read_text().split()
                self.assertEqual(fields[1:], ['5', '80070057', '0'] if forced else ['0', '00000000', '1'])
                calls = (root / 'calls.log').read_text().splitlines()
                self.assertEqual(any(method in calls for method in ('GetSecret', 'GetSecrets')), not forced)
                self.assertEqual('CreateItem' in calls, not forced)
                http = (root / 'http.log').read_text().splitlines()
                self.assertEqual('SendRequest' in http, not forced)
                raw = (bundle / 'events.jsonl').read_text()
                events = [json.loads(line) for line in raw.splitlines()]
                pid = int(fields[0])
                self.assertEqual(next(event['code'] for event in events if event['kind'] == 'process_exit' and event['pid'] == pid), 0)
                architecture = 'x86_64' if BITS == 64 else 'i386'
                for name, image in {'winhttp.dll': ROOT / 'winhttp.dll',
                                    'windows.security.authentication.onlineid.dll': CANDIDATE / f'lib/wine/{architecture}-windows/windows.security.authentication.onlineid.dll'}.items():
                    loaded = next(event for event in events if event['kind'] == 'module_load' and event['pid'] == pid and event.get('path', '').lower().endswith(name))
                    self.assertEqual(loaded['identity']['sha256'], hashlib.sha256(image.read_bytes()).hexdigest())
                stages = [event['data'] for event in events if event['kind'] == 'provider' and event['data'].get('event') == 'identity.stage']
                if forced:
                    self.assertEqual({value['operation'] for value in stages}, {'authorize'})
                    self.assertNotIn('cache', [value['stage'] for value in stages])
                self.assertEqual(stages[-1]['hresult'], '0x80070057' if forced else '0x00000000')
                for sentinel in ('fixture-access-not-a-token', 'fixture-refresh-not-a-token', 'fixture-user@example.invalid'):
                    self.assertNotIn(sentinel, raw)
        finally:
            for child in (service, bus):
                if child is not None:
                    if child.poll() is None:child.terminate()
                    child.wait(timeout=10)
            if bus is not None:bus.stdout.close()

    def test_forced_login_does_not_refresh_cached_credentials(self):
        self.capture(False)
        self.capture(True)


if __name__ == '__main__':
    unittest.main()
