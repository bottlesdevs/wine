import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import unittest

ROOT = Path(os.environ['EAGLE_IDENTITY_BRIDGE_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
BITS = int(os.environ['EAGLE_IDENTITY_BRIDGE_BITS'])


class IdentityBridge(unittest.TestCase):
    def capture(self, name, profile, status, wrong_id=False):
        root = ROOT / name;root.mkdir()
        path = root / 'b.sock'
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(path));path.chmod(0o600);server.listen(1);server.settimeout(0.2)
        self.addCleanup(path.unlink)
        halt = threading.Event()
        requests, errors = [], []

        def serve():
            try:
                while not halt.is_set():
                    try:
                        connection, _ = server.accept();break
                    except socket.timeout:
                        continue
                else:
                    return
                with connection:
                    connection.settimeout(10)
                    def read(size):
                        data = bytearray()
                        while len(data) < size:
                            part = connection.recv(size - len(data))
                            if not part:
                                raise ValueError('truncated test bridge request')
                            data.extend(part)
                        return data
                    magic, version, opcode, request_id, size, _ = struct.unpack('<IHHIIi', read(20))
                    if (magic, version, opcode) != (0x31424953, 1, 5) or size > 1048576:
                        raise ValueError('unexpected test bridge request')
                    read(size)
                    requests.append(request_id)
                    payload = struct.pack('<HHII', 22, 0, 4, 0) if status == 0 else b''
                    connection.sendall(struct.pack('<IHHIIi', magic, version, opcode | 0x8000,
                                                   request_id + int(wrong_id), len(payload), status) + payload)
            except Exception as error:
                errors.append(str(error))

        thread = threading.Thread(target=serve)
        thread.start()
        marker = root / 'result.txt'
        bundle = root / 'session'
        try:
            command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'),
                       '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile,
                       '--timeout', '30', str(ROOT / 'target.exe'), 'Z:' + str(marker).replace('/', '\\')]
            result = subprocess.run(command, env=dict(os.environ, SODA_IDENTITY_BRIDGE_SOCKET=str(path)),
                                    capture_output=True, text=True, timeout=50)
        finally:
            halt.set();thread.join(timeout=12)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        self.assertFalse(errors)
        self.assertEqual(len(requests), 1)
        fields = marker.read_text().split()
        expected = (0, '00000000') if status == 0 and not wrong_id else (3, '80070057' if wrong_id else '80070005')
        self.assertEqual((int(fields[1]), fields[2]), expected)
        self.assertEqual(fields[3], '0')
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
        expected_stages = [] if profile == 'crash' else ['begin', 'transport', 'complete'] if wrong_id else ['begin', 'transport', 'response', 'complete']
        self.assertEqual([value['stage'] for value in stages], expected_stages)
        if stages:
            self.assertTrue(all(value['operation'] == 'list_accounts' and value['request_id'] == stages[0]['request_id'] for value in stages))
            self.assertEqual(stages[-1]['hresult'], '0x' + expected[1])

    def test_linked_dll_api_controls_and_stage_results(self):
        self.capture('off', 'crash', 0)
        self.capture('success', 'winrt', 0)
        self.capture('error', 'winrt', 4)
        self.capture('malformed', 'winrt', 0, wrong_id=True)


if __name__ == '__main__':
    unittest.main()
