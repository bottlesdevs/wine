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

ROOT = Path(os.environ['EAGLE_IDENTITY_PROMPT_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
BITS = int(os.environ['EAGLE_IDENTITY_BRIDGE_BITS'])


def winpath(path):
    return 'Z:' + str(path).replace('/', '\\')


class IdentityPrompt(unittest.TestCase):
    def stop(self, prefix, environment):
        environment = dict(environment, WINEPREFIX=str(prefix))
        subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-k'], env=environment,
                       capture_output=True, timeout=15)
        result = subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-w'], env=environment,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def wait_file(self, path, process, seconds=30):
        deadline = time.monotonic() + seconds
        while not path.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(path.exists(), (str(path), process.poll()))

    def capture(self, name, action):
        root = ROOT / name;root.mkdir(mode=0o700)
        prefix = root / 'prefix'
        environment = dict(os.environ, WINEPREFIX=str(prefix), DBUS_SESSION_BUS_ADDRESS='unix:path=' + str(root / 'no-bus'),
                           EAGLE_FIXTURE_HTTP_MODE='device', EAGLE_FIXTURE_HTTP_LOG=winpath(root / 'http.log'),
                           EAGLE_FIXTURE_PROMPT_READY=winpath(root / 'window-ready'),
                           EAGLE_FIXTURE_PROMPT_CLICK=winpath(root / 'click'),
                           EAGLE_FIXTURE_PROMPT_FINISH=winpath(root / 'finish'),
                           EAGLE_FIXTURE_PROMPT_ACTION=action,
                           EAGLE_FIXTURE_URI_EXE=winpath(ROOT / 'uri.exe'),
                           EAGLE_FIXTURE_URI_LOG=winpath(root / 'uri.log'))
        environment.pop('SODA_IDENTITY_BRIDGE_SOCKET', None)
        environment.pop('_NT_SYMBOL_PATH', None)
        environment['WINEDLLOVERRIDES'] = environment.get('WINEDLLOVERRIDES', '') + ';winhttp=n;winebrowser.exe=d;winemenubuilder.exe=d'
        bus = service = process = shell = None
        try:
            subprocess.run(['cp', '-a', '--reflink=auto', str((ROOT / 'prefix').resolve()), str(prefix)],
                           check=True, capture_output=True, timeout=60)
            folder = 'system32' if BITS == 64 else 'syswow64'
            destination = prefix / 'drive_c/windows' / folder / 'winhttp.dll'
            self.assertTrue(destination.parent.resolve().is_relative_to(prefix.resolve()))
            destination.unlink(missing_ok=True)
            shutil.copy2(ROOT / 'winhttp.dll', destination)
            with (root / 'shell.log').open('w') as shell_log, (root / 'bus.log').open('w') as bus_log, \
                 (root / 'service.log').open('w') as service_log, (root / 'stdout.log').open('w') as stdout, \
                 (root / 'stderr.log').open('w') as stderr:
                shell = subprocess.Popen([str(CANDIDATE / 'bin/wine'), 'explorer.exe', '/desktop'],
                                         env=environment, stdout=shell_log, stderr=subprocess.STDOUT)
                time.sleep(2)
                self.assertIsNone(shell.poll())
                path = root / 'b.sock'
                bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--nopidfile',
                                        '--address=unix:path=' + str(path), '--print-address=1'],
                                       stdout=subprocess.PIPE, stderr=bus_log, text=True)
                self.assertTrue(select.select([bus.stdout], [], [], 5)[0])
                address = bus.stdout.readline().strip()
                self.assertTrue(address.startswith('unix:path=' + str(path)))
                path.chmod(0o600)
                environment['DBUS_SESSION_BUS_ADDRESS'] = address
                service = subprocess.Popen([os.environ['EAGLE_IDENTITY_SECRET_SERVICE'], str(root / 'ready'),
                                            str(root / 'calls.log'), 'device'], env=environment,
                                           stdout=service_log, stderr=subprocess.STDOUT)
                self.wait_file(root / 'ready', service, 5)
                self.assertEqual((root / 'ready').read_text(), 'ready\n')
                marker = root / 'result.txt';bundle = root / 'session'
                command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                           '--prefix', str(prefix), '--session', str(bundle),
                           '--profile', 'crash' if name == 'off' else 'winrt', '--timeout', '45',
                           str(ROOT / 'target.exe'), winpath(marker), 'device']
                process = subprocess.Popen(command, env=environment, stdout=stdout, stderr=stderr)
                self.wait_file(root / 'window-ready', process)
                (root / 'click').write_text('acknowledge owned dialog\n')
                self.wait_file(marker, process)
                expected = ['2', '80004004', '0'] if action == 'async' else ['1', '800704c7', '0'] if action == 'cancel' else ['0', '00000000', '1']
                fields = marker.read_text().split()
                self.assertEqual(fields[1:], expected + ['1', '1', '1'])
                if name != 'off':
                    deadline = time.monotonic() + 10
                    completed = False
                    while time.monotonic() < deadline and not completed:
                        for line in (root / 'stderr.log').read_text().splitlines():
                            try:event = json.loads(line).get('data', {}).get('data', {})
                            except json.JSONDecodeError:continue
                            if event.get('operation') == 'authorize' and event.get('stage') == 'complete':
                                completed = True
                        if not completed:time.sleep(0.05)
                    self.assertTrue(completed, 'native authorization completion missing')
                if action == 'ok':self.wait_file(root / 'uri.log', process, 10)
                (root / 'finish').write_text('native completion observed\n')
                self.assertEqual(process.wait(timeout=25), 0)
            manifest = json.loads((bundle / 'manifest.json').read_text())
            self.assertTrue(manifest['completed'])
            self.assertEqual(manifest['collector_exit'], 0)
            self.assertEqual(manifest['dropped_events'], 0)
            raw = (bundle / 'events.jsonl').read_text()
            events = [json.loads(line) for line in raw.splitlines()];pid = int(fields[0])
            self.assertEqual(next(event['code'] for event in events if event['kind'] == 'process_exit' and event['pid'] == pid), 0)
            architecture = 'x86_64' if BITS == 64 else 'i386'
            modules = {'winhttp.dll': ROOT / 'winhttp.dll',
                       'windows.security.authentication.onlineid.dll': CANDIDATE / f'lib/wine/{architecture}-windows/windows.security.authentication.onlineid.dll'}
            for name_on_disk, image in modules.items():
                loaded = next(event for event in events if event['kind'] == 'module_load' and event['pid'] == pid and event.get('path', '').lower().endswith(name_on_disk))
                self.assertEqual(loaded['identity']['sha256'], hashlib.sha256(image.read_bytes()).hexdigest())
            records = [event for event in events if event['kind'] == 'provider' and event['data'].get('event') == 'identity.stage']
            stages = [event['data'] for event in records]
            successful = action == 'ok'
            if name == 'off':self.assertEqual(stages, [])
            else:
                self.assertTrue(all(event['pid'] == pid for event in records))
                self.assertTrue(all(value['transport'] == 'native' for value in stages))
                for value in stages:
                    self.assertEqual(set(value), {'provider', 'event', 'hresult', 'request_id', 'operation', 'transport', 'stage', 'caller'})
                token = [value for value in stages if value['operation'] == 'get_token']
                authorize = [value for value in stages if value['operation'] == 'authorize']
                self.assertEqual([(value['stage'], value['hresult']) for value in token],
                                 [('begin', '0x8000000a'), ('cache', '0x8000000a'), ('cache', '0xd0000034'), ('complete', '0xd0000034')])
                result = '0x00000000' if successful else '0x800704c7'
                expected = [('begin', '0x8000000a'), ('cache', '0x8000000a'), ('cache', '0xd0000034'),
                            ('request', '0x8000000a'), ('request', '0x00000000'), ('prompt', '0x8000000a'), ('prompt', result)]
                if successful:
                    expected += [('request', '0x8000000a'), ('request', '0x00000000'), ('response', '0x00000000'),
                                 ('persist', '0x8000000a'), ('persist', '0x00000000')]
                expected += [('complete', result)]
                self.assertEqual([(value['stage'], value['hresult']) for value in authorize], expected)
                self.assertEqual(len({value['request_id'] for value in token}), 1)
                self.assertEqual(len({value['request_id'] for value in authorize}), 1)
                self.assertNotEqual(token[0]['request_id'], authorize[0]['request_id'])
            calls = (root / 'calls.log').read_text().splitlines();http = (root / 'http.log').read_text().splitlines()
            self.assertEqual('StoreMatched' in calls, successful)
            self.assertNotIn('StoreMismatch', calls)
            self.assertEqual(http.count('DeviceRequest'), 1)
            self.assertEqual(http.count('TokenRequest'), int(successful))
            self.assertEqual((root / 'uri.log').exists(), successful)
            if successful:self.assertEqual((root / 'uri.log').read_text(), 'fixture URI acknowledged\n')
            for sentinel in ('FIXTURE-1234', 'fixture-device-secret', 'fixture-access-not-a-token',
                             'fixture-next-refresh-not-a-token', 'fixture-user@example.invalid'):
                self.assertNotIn(sentinel, raw)
                self.assertNotIn(base64.b64encode(sentinel.encode()).decode().rstrip('='), raw)
        finally:
            if process is not None and process.poll() is None:
                process.terminate();process.wait(timeout=10)
            if prefix.exists():self.stop(prefix, environment)
            for child in (shell, service, bus):
                if child is not None:
                    if child.poll() is None:child.terminate()
                    child.wait(timeout=10)
            if bus is not None:bus.stdout.close()
            if prefix.exists():
                self.assertEqual(prefix.parent, root)
                self.assertFalse(prefix.is_symlink())
                shutil.rmtree(prefix)

    def test_prompt(self):
        self.stop(ROOT / 'prefix', os.environ)
        for name, action in [('ok', 'ok'), ('off', 'ok'), ('cancel', 'cancel'), ('async', 'async')]:
            with self.subTest(name=name):self.capture(name, action)


if __name__ == '__main__':
    unittest.main()
