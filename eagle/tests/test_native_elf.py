import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from symbols import resolve


class NativeELF(unittest.TestCase):
    def test_build_ids_against_readelf(self):
        root = Path(os.environ['EAGLE_TEST_WINE']).parents[1]
        paths = sorted((root / 'lib/wine/x86_64-unix').glob('*.so'))
        self.assertGreater(len(paths), 10)
        for path in paths:
            with self.subTest(image=path.name):
                actual = subprocess.run([str(PACKAGE / 'lib/eagle/native/eagle-elf'), str(path)], capture_output=True, text=True)
                self.assertEqual(actual.returncode, 0, actual.stderr)
                metadata = json.loads(actual.stdout)
                expected = subprocess.check_output(['readelf', '-n', str(path)], text=True)
                match = re.search(r'Build ID: ([a-f0-9]+)', expected)
                self.assertEqual(metadata['build_id'], match[1] if match else '')
                self.assertEqual(metadata['machine'], 62)

    def test_actual_native_source_symbols(self):
        path = PACKAGE / 'lib/eagle/native/eagle-pe'
        metadata = json.loads(subprocess.check_output([str(PACKAGE / 'lib/eagle/native/eagle-elf'), str(path)], text=True))
        self.assertTrue(metadata['build_id'])
        self.assertTrue(metadata['debug_info'])
        listing = subprocess.check_output(['nm', str(path)], text=True)
        address = next(line.split()[0] for line in listing.splitlines() if line.endswith(' main'))
        result = resolve(path, [hex(int(address, 16) - int(metadata['image_base'], 0))])[0]
        self.assertEqual(result['symbol'], 'main')
        self.assertIn('pe.cpp:', result['source'])

    def test_bad_files_are_rejected(self):
        root = Path(os.environ['EAGLE_TEST_ROOT'])
        for name, payload in [('empty', b''), ('truncated', b'\x7fELF' + bytes(20)), ('outside', b'\x7fELF' + bytes(60))]:
            path = root / (name + '.elf-bad')
            path.write_bytes(payload)
            result = subprocess.run([str(PACKAGE / 'lib/eagle/native/eagle-elf'), str(path)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
