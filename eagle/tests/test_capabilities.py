import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from protocol import read_message, write_message


class Capabilities(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.package = Path(directory.name) / 'package'
        shutil.copytree(PACKAGE, self.package, copy_function=os.link)
        self.command = [sys.executable, '-S', str(self.package / 'lib/eagle/eagle')]

    def capabilities(self):
        result = subprocess.run(self.command + ['capabilities'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)['data']

    def test_advertises_only_packaged_collectors(self):
        native = self.package / 'lib/eagle/native'
        for bits, expected in ((32, ['x86_64']), (64, [])):
            (native / f'eagle-debug{bits}.exe').unlink()
            data = self.capabilities()
            self.assertEqual(data['debug_architectures'], expected)
            self.assertEqual(bool(data['debug']), bool(expected))
            self.assertEqual(bool(data['capture_profiles']), bool(expected))
            self.assertEqual(bool(data['provider_profiles']), bool(expected))
            self.assertEqual('Win32 debug engine' in data['native_components'], bool(expected))
            self.assertEqual(data['native_static_analyzer'], True)
        self.assertIsNone(data['condition_language'])
        (native / 'eagle-debug32.exe').mkdir()
        self.assertEqual(self.capabilities()['debug_architectures'], [])

    def test_x86_only_and_complete_packages(self):
        self.assertEqual(self.capabilities()['debug_architectures'], ['x86', 'x86_64'])
        (self.package / 'lib/eagle/native/eagle-debug64.exe').unlink()
        self.assertEqual(self.capabilities()['debug_architectures'], ['x86'])

    def test_debugger_only_package_keeps_analysis_unavailable(self):
        for name in ('analysis.json', 'native/eagle-yara'):
            (self.package / 'lib/eagle' / name).unlink()
        data = self.capabilities()
        self.assertFalse(data['native_static_analyzer'])
        self.assertFalse(data['analysis']['available'])
        self.assertIsNone(data['static_analyzer'])
        self.assertEqual(data['debug_architectures'], ['x86', 'x86_64'])
        result = subprocess.run(self.command + ['--help'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('analyze', result.stdout)
        self.assertNotIn('security-scan', result.stdout)
        stream = io.BytesIO()
        for identifier, method in enumerate(('initialize', 'analyze', 'security-scan', 'capabilities', 'shutdown'), 1):
            params = {'schema': 1} if method == 'initialize' else {'path': '/missing'}
            write_message(stream, {'id': identifier, 'method': method, 'params': params})
        result = subprocess.run(self.command + ['serve'], input=stream.getvalue(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = io.BytesIO(result.stdout)
        self.assertEqual(read_message(replies)['result'], data)
        for identifier in (2, 3):
            response = read_message(replies)
            self.assertEqual(response['id'], identifier)
            self.assertEqual(response['error']['code'], -32602)
        self.assertEqual(read_message(replies)['result'], data)
        self.assertEqual(read_message(replies)['id'], 5)

    def test_stdio_matches_cli_for_analyzer_without_collectors(self):
        for bits in (32, 64):
            (self.package / f'lib/eagle/native/eagle-debug{bits}.exe').unlink()
        stream = io.BytesIO()
        for identifier, method, params in ((1, 'initialize', {'schema': 1}), (2, 'capabilities', {}), (3, 'shutdown', {})):
            write_message(stream, {'id': identifier, 'method': method, 'params': params})
        result = subprocess.run(self.command + ['serve'], input=stream.getvalue(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = io.BytesIO(result.stdout)
        expected = self.capabilities()
        self.assertEqual(read_message(replies)['result'], expected)
        self.assertEqual(read_message(replies)['result'], expected)
        self.assertEqual(read_message(replies)['id'], 3)


if __name__ == '__main__':
    unittest.main()
