import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from protocol import read_message, write_message


class AnalyzerPackage(unittest.TestCase):
    def test_native_analysis_has_no_windows_collector_claim(self):
        result = subprocess.run([str(PACKAGE / 'bin/eagle'), 'capabilities'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)['data']
        self.assertTrue(data['native_static_analyzer'])
        self.assertEqual(data['debug_architectures'], [])
        for name in ('debug', 'capture_profiles', 'provider_profiles'):
            self.assertFalse(data[name])
        self.assertNotIn('Win32 debug engine', data['native_components'])
        self.assertEqual(list((PACKAGE / 'lib/eagle/native').glob('eagle-debug*.exe')), [])

    def test_stdio_retains_native_analysis_without_collectors(self):
        stream = io.BytesIO()
        for identifier, method in ((1, 'initialize'), (2, 'capabilities'), (3, 'shutdown')):
            write_message(stream, {'id': identifier, 'method': method, 'params': {'schema': 1}})
        result = subprocess.run([str(PACKAGE / 'bin/eagle'), 'serve'], input=stream.getvalue(),
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = io.BytesIO(result.stdout)
        for identifier in (1, 2):
            reply = read_message(replies)
            self.assertEqual(reply['id'], identifier)
            self.assertTrue(reply['result']['analysis']['available'])
            self.assertEqual(reply['result']['debug_architectures'], [])
        self.assertEqual(read_message(replies)['id'], 3)

    def test_provenance_records_only_built_tools_and_payloads(self):
        data = json.loads((PACKAGE / 'share/eagle/build.json').read_text())
        self.assertEqual(set(data['tools']), {'g++'})
        self.assertFalse(any('eagle-debug' in name for name in data['files']))


if __name__ == '__main__':
    unittest.main()
