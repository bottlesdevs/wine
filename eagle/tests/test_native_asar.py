import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(os.environ['EAGLE_TEST_ROOT'])
PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.analyzer import EagleManager
from engine.native import extract_asar
from engine.runtime import Paths


class NativeAsar(unittest.TestCase):
    def archive(self, name, entries, payload, aligned=True):
        path = ROOT / (name + '.asar')
        header = json.dumps({'files': entries}, separators=(',', ':')).encode()
        padding = (-len(header)) % 4 if aligned else 0
        pickle_size = len(header) + padding + 8 if aligned else 0
        path.write_bytes(struct.pack('<4I', 4 if aligned else 0, pickle_size, len(header) + padding + 4, len(header)) + header + b'\x00' * padding + payload)
        return path

    def output(self, name):
        path = ROOT / name
        path.mkdir(mode=0o700)
        return path

    def test_standard_pickle_padding_and_legacy_layout(self):
        payload = b'console.log("eagle");\n' + b'{"main":"app.js"}'
        size = payload.index(b'{')
        entries = {'src': {'files': {'app.js': {'offset': '0', 'size': size}}}, 'package.json': {'offset': str(size), 'size': len(payload)-size}, 'skip.png': {'offset': '0', 'size': size}}
        for aligned in (True, False):
            label = 'aligned' if aligned else 'legacy'
            archive = self.archive(label, entries, payload, aligned)
            output = self.output(label + '-output')
            files = extract_asar(archive, output)
            self.assertEqual([Path(file).relative_to(output).as_posix() for file in files], ['src/app.js', 'package.json'])
            self.assertEqual((output / 'src/app.js').read_bytes(), payload[:size])
            self.assertEqual((output / 'package.json').read_bytes(), payload[size:])
            self.assertFalse((output / 'skip.png').exists())

    def test_invalid_entries_and_truncated_headers_fail(self):
        cases = [('traversal', {'../outside.js': {'offset': '0', 'size': 1}}, b'x'), ('absolute', {'/outside.js': {'offset': '0', 'size': 1}}, b'x'), ('backslash', {'dir\\outside.js': {'offset': '0', 'size': 1}}, b'x'), ('bounds', {'app.js': {'offset': '9', 'size': 1}}, b'x'), ('negative', {'app.js': {'offset': '-1', 'size': 1}}, b'x'), ('limit', {'app.js': {'offset': '0', 'size': 64*1024*1024+1}}, b'x')]
        for label, entries, payload in cases:
            with self.subTest(label=label):
                archive = self.archive(label, entries, payload)
                with self.assertRaises(ValueError):
                    extract_asar(archive, self.output(label + '-output'))
        archive = ROOT / 'truncated.asar'
        archive.write_bytes(b'\x00' * 12)
        with self.assertRaisesRegex(ValueError, 'truncated'):
            extract_asar(archive, self.output('truncated-output'))
        self.assertFalse((ROOT / 'outside.js').exists())

    def test_null_paths_and_invalid_number_types(self):
        cases = [
            ('null-name', {'app.js\0hidden': {'offset': '0', 'size': 1}}),
            ('null-offset', {'app.js': {'offset': '0\0hidden', 'size': 1}}),
            ('boolean', {'app.js': {'offset': False, 'size': 1}}),
            ('float', {'app.js': {'offset': 0.0, 'size': 1}}),
            ('array', {'app.js': {'offset': [], 'size': 1}}),
            ('object', {'app.js': {'offset': {}, 'size': 1}}),
        ]
        for label, entries in cases:
            with self.subTest(label=label):
                archive = self.archive(label, entries, b'x')
                output = self.output(label + '-output')
                with self.assertRaises(ValueError): extract_asar(archive, output)
                self.assertEqual(list(output.iterdir()), [])

    def test_private_output_and_failure_cleanup(self):
        archive = self.archive('cleanup', {'../outside.js': {'offset': '0', 'size': 1}}, b'x')
        before = set(Path(Paths.temp).glob('eagle_asar_*'))
        manager = EagleManager({})
        manager._send_step = lambda *args: None
        self.assertEqual(manager._extract_asar(str(archive)), ([], None))
        self.assertEqual(set(Path(Paths.temp).glob('eagle_asar_*')), before)
        public = self.output('public-output')
        public.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'not private'):
            extract_asar(archive, public)


if __name__ == '__main__':
    unittest.main(verbosity=2)
