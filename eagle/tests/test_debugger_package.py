import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from protocol import read_message, write_message


class DebuggerPackageTests(unittest.TestCase):
    def test_provider_dlls_leave_executable_tls_unchanged(self):
        for architecture in ('i386', 'x86_64'):
            for module in ('kernelbase', 'combase', 'dwrite'):
                path = PACKAGE / f'lib/wine/{architecture}-windows/{module}.dll'
                with self.subTest(architecture=architecture, module=module):
                    data = path.read_bytes()
                    self.assertEqual(data[:2], b'MZ')
                    offset = struct.unpack_from('<I', data, 0x3c)[0]
                    self.assertEqual(data[offset:offset + 4], b'PE\0\0')
                    optional = offset + 24
                    magic = struct.unpack_from('<H', data, optional)[0]
                    self.assertIn(magic, (0x10b, 0x20b))
                    directories = optional + (96 if magic == 0x10b else 112)
                    tls = struct.unpack_from('<II', data, directories + 9 * 8)
                    self.assertEqual(tls, (0, 0), 'provider DLL must not allocate compiler TLS before the executable')

    def test_available_commands_match_release_scope(self):
        executable = str(PACKAGE / 'bin/eagle')
        result = subprocess.run([executable, 'capabilities'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)['data']
        self.assertEqual(data['debug_architectures'], ['x86', 'x86_64'])
        self.assertIsNone(data['static_analyzer'])
        self.assertFalse(data['analysis']['available'])
        result = subprocess.run([executable, '--help'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('trace', result.stdout)
        self.assertNotIn('analyze', result.stdout)
        self.assertNotIn('security-scan', result.stdout)

    def test_unavailable_requests_leave_backend_responsive(self):
        with subprocess.Popen([str(PACKAGE / 'bin/eagle'), 'serve'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
            try:
                write_message(process.stdin, {'id': 1, 'method': 'initialize', 'params': {'schema': 1}})
                self.assertFalse(read_message(process.stdout)['result']['analysis']['available'])
                for request_id, method in ((2, 'analyze'), (3, 'security-scan')):
                    write_message(process.stdin, {'id': request_id, 'method': method, 'params': {'path': '/missing'}})
                    response = read_message(process.stdout)
                    self.assertEqual(response['id'], request_id)
                    self.assertEqual(response['error']['code'], -32602)
                write_message(process.stdin, {'id': 4, 'method': 'capabilities'})
                self.assertEqual(read_message(process.stdout)['id'], 4)
                write_message(process.stdin, {'id': 5, 'method': 'shutdown'})
                self.assertEqual(read_message(process.stdout)['id'], 5)
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    def test_both_architecture_identities_work_without_analyzer(self):
        for bits, machine in ((32, 0x14c), (64, 0x8664)):
            result = subprocess.run([str(PACKAGE / 'bin/eagle'), 'symbols', str(Path(os.environ['EAGLE_TEST_ROOT']) / f'target{bits}.exe')], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['data']['machine'], machine)


if __name__ == '__main__':
    unittest.main()
