import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import threading
import time
import unittest

ROOT = Path(os.environ['EAGLE_TEST_ROOT'])
PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from protocol import read_message, write_message
from session import compare, export, read_bundle, windows_path
from symbols import pdb_identity


class SessionContract(unittest.TestCase):
    def test_rpc_launch_is_responsive_and_cancel_detaches(self):
        root = ROOT / 'rpc-cancel'
        marker = ROOT / 'rpc-marker'
        messages = []
        changed = threading.Condition()
        with subprocess.Popen([str(PACKAGE / 'bin/eagle'), 'serve'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as backend:
            def consume():
                while True:
                    value = read_message(backend.stdout)
                    if value is None:
                        return
                    with changed:
                        messages.append(value)
                        changed.notify_all()
            reader = threading.Thread(target=consume, daemon=True)
            reader.start()
            def wait(predicate, timeout=30):
                deadline = time.monotonic() + timeout
                with changed:
                    while time.monotonic() < deadline:
                        for value in messages:
                            if predicate(value):
                                return value
                        changed.wait(max(0, deadline - time.monotonic()))
                self.fail('backend response deadline exceeded')
            try:
                write_message(backend.stdin, {'id': 1, 'method': 'initialize', 'params': {'schema': 1}})
                wait(lambda value: value.get('id') == 1)
                write_message(backend.stdin, {'id': 2, 'method': 'run', 'params': {'wine': os.environ['EAGLE_TEST_WINE'], 'prefix': str(ROOT / 'prefix'), 'session': str(root), 'target': str(ROOT / 'target64.exe'), 'arguments': ['wait', windows_path(marker)], 'interactive': True}})
                wait(lambda value: value.get('event') == 'debug.event' and value['data']['kind'] == 'stopped')
                start = time.monotonic()
                write_message(backend.stdin, {'id': 3, 'method': 'capabilities'})
                self.assertEqual(wait(lambda value: value.get('id') == 3, 2)['result']['schema'], 1)
                self.assertLess(time.monotonic() - start, 2)
                write_message(backend.stdin, {'id': 4, 'method': 'cancel', 'params': {'request_id': 2}})
                self.assertTrue(wait(lambda value: value.get('id') == 4)['result']['requested'])
                self.assertEqual(wait(lambda value: value.get('id') == 2)['error']['code'], -32800)
                manifest, events = read_bundle(root)
                self.assertTrue(manifest['cancelled'])
                self.assertFalse(manifest['completed'])
                self.assertTrue(any(value['kind'] == 'detached' for value in events))
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(marker.read_bytes(), b'alive')
                write_message(backend.stdin, {'id': 5, 'method': 'shutdown'})
                wait(lambda value: value.get('id') == 5)
                self.assertEqual(backend.wait(timeout=5), 0)
            finally:
                if backend.poll() is None:
                    backend.kill()
                    backend.wait(timeout=5)
                reader.join(timeout=5)

    def test_comparison_rejects_different_observer_settings(self):
        baseline = ROOT / 'crash-64-0'
        candidate = ROOT / 'different-observer'
        candidate.mkdir()
        manifest, events = read_bundle(baseline)
        manifest['trigger'] = {'hresult': '0x80040154', 'action': 'dump'}
        (candidate / 'manifest.json').write_text(json.dumps(manifest))
        shutil.copyfile(baseline / 'events.jsonl', candidate / 'events.jsonl')
        self.assertFalse(compare(baseline, candidate)['matching_inputs'])
        self.assertTrue(compare(baseline, ROOT / 'crash-64-1')['matching_inputs'])

    def test_export_removes_paths_and_preserves_host_identities(self):
        root = ROOT / 'crash-64-0'
        manifest, events = read_bundle(root)
        self.assertTrue(manifest['unix_modules'])
        self.assertFalse(manifest['unix_inventory']['host_stacks_captured'])
        report = export(root, ROOT / 'redacted-report.json')
        value = json.dumps(report)
        self.assertNotIn(str(ROOT), value)
        self.assertNotIn(str(ROOT).replace('/', '\\'), value)
        self.assertFalse(report['export']['memory_and_dumps_included'])
        self.assertTrue(report['manifest']['unix_modules'])

    def test_pdb_guid_age_and_truncated_controls(self):
        fixture = Path(os.environ['EAGLE_PDB_FIXTURE'])
        original = fixture.with_suffix('.pdb').read_bytes()
        block_size, free_map, blocks, directory_size, reserved, map_block = struct.unpack_from('<6I', original, 32)
        count = (directory_size + block_size - 1) // block_size
        numbers = struct.unpack_from(f'<{count}I', original, map_block * block_size)
        directory = b''.join(original[number * block_size:(number + 1) * block_size] for number in numbers)[:directory_size]
        streams = struct.unpack_from('<I', directory)[0]
        sizes = struct.unpack_from(f'<{streams}I', directory, 4)
        position = 4 + 4 * streams
        position += (0 if sizes[0] == 0xffffffff else (sizes[0] + block_size - 1) // block_size) * 4
        identity_block = struct.unpack_from('<I', directory, position)[0] * block_size
        expected = pdb_identity(fixture.with_suffix('.pdb'))
        for label, offset in [('age', 8), ('guid', 12)]:
            data = bytearray(original)
            data[identity_block + offset] ^= 1
            mismatch = ROOT / (label + '-mismatch.pdb')
            mismatch.write_bytes(data)
            self.assertNotEqual(pdb_identity(mismatch), expected)
            result = subprocess.run([str(PACKAGE / 'bin/eagle'), 'symbols', str(fixture), '--pdb', str(mismatch)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn('does not match', result.stderr)
        truncated = ROOT / 'truncated.pdb'
        truncated.write_bytes(original[:50])
        with self.assertRaisesRegex(ValueError, 'truncated'):
            pdb_identity(truncated)
        result = subprocess.run([str(PACKAGE / 'bin/eagle'), 'symbols', str(fixture), '--pdb', str(fixture.with_suffix('.pdb'))], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['data']['pdb_matches'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
