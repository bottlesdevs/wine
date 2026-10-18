import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unittest

ROOT = Path(os.environ['EAGLE_TEST_ROOT'])
PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
BASELINE = Path(os.environ['EAGLE_BASELINE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.native import discover


class NativeDiscovery(unittest.TestCase):
    def fixture(self, name, entries):
        root = ROOT / name
        root.mkdir()
        target = root / 'app.exe'
        shutil.copyfile(os.environ['EAGLE_TARGET_FIXTURE'], target)
        for path, contents in entries.items():
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            if contents is None:
                destination.mkdir(exist_ok=True)
            else:
                destination.write_bytes(contents)
        return target

    def analyze(self, package, target):
        result = subprocess.run([str(package / 'bin/eagle'), 'analyze', str(target)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)['data']

    def test_directory_markers_neighbor_scans_and_sources_match(self):
        payload = b'require("child_process"); execSync("cmd.exe");'
        encoded = json.dumps({'files': {'app.js': {'offset': '0', 'size': len(payload)}}}, separators=(',', ':')).encode()
        archive = struct.pack('<4I', 0, 0, 0, len(encoded)) + encoded + payload
        cases = [('runtime-root', {'app.runtimeconfig.json': b'{}', 'bin/app.deps.json': b'{}'}), ('runtime-bin', {'bin/app.deps.json': b'{}'}), ('engines', {'renpy': None, 'www': None, 'Game.rgss3a': b'', 'app.pck': b''}), ('plugins', {'unityplayer.DLL': b'x', 'app_Data/Plugins/x86_64/fmod.dll': b'x', 'app_Data/Plugins/d3d11.dll': b'x'}), ('electron', {'resources/app.asar': archive})]
        for label, entries in cases:
            with self.subTest(case=label):
                target = self.fixture(label, entries)
                self.assertEqual(self.analyze(PACKAGE, target), self.analyze(BASELINE, target))

    def test_shipping_selection_keeps_actual_pe_architecture(self):
        target = self.fixture('unreal', {'Engine': None, 'Game/Binaries/Win64/app-win64-shipping.exe': b'x'})
        actual, expected = self.analyze(PACKAGE, target), self.analyze(BASELINE, target)
        self.assertEqual(actual['arch'], 'x86_64 (64-bit)')
        self.assertEqual(expected['arch'], 'Win64')
        expected['arch'] = actual['arch']
        self.assertEqual(actual, expected)
        self.assertEqual(actual['messages'][0]['context'], [str(target.parent / 'Game/Binaries/Win64/app-win64-shipping.exe')])

    def test_private_traversal_is_bounded_and_common_directory_is_excluded(self):
        target = self.fixture('deep-plugins', {})
        path = target.parent / 'app_Data/Plugins'
        for _ in range(35):
            path /= 'child'
        path.mkdir(parents=True)
        details = {name: [] for name in ('Runtimes', 'Engines', 'Frameworks', 'Analysed Files')}
        with self.assertRaisesRegex(ValueError, 'traversal limit'):
            discover(target, details)
        home_file = Path.home() / '.bashrc'
        if home_file.is_file():
            result = discover(home_file, details)
            self.assertFalse(result['neighbor_scan_allowed'])
            self.assertEqual(result['neighbors'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
