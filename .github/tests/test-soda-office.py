import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compose = load('soda-office-compose')
diagnostics = load('soda-office-diagnostics')


class OfficeDiagnostics(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.temp = self.root / 'drive_c/users/owned/AppData/Local/Temp'
        self.temp.mkdir(parents=True)

    def line(self, message, category='Activity', event_id='bjtct'):
        return '\t'.join(('private-time', 'private-user', 'private-thread', 'private-area',
                          category, event_id, 'Verbose', message, 'private-correlation')) + '\n'

    def test_utf16_and_utf8_logs_keep_metadata_without_private_fields(self):
        message = json.dumps({'EventName': 'Office.Text.DWriteAssistant.CreateFontCollection',
                              'Activity': {'Success': False, 'Duration': 19, 'CV': 'private-cv'},
                              'Data': {'Account': 'private@example.invalid', 'Token': 'private-token'}})
        (self.temp / 'owned.log').write_text(self.line(message), encoding='utf-16')
        primary = self.temp / 'Diagnostics/WINWORD/Primary.log'
        primary.parent.mkdir(parents=True)
        primary.write_text(self.line('private printer and document', 'Word Print', '4qjru') + '\0' * 1024)
        os.utime(self.temp / 'owned.log', (10, 10))
        os.utime(primary, (20, 20))
        (self.root / 'system.reg').write_text('[Software\\\\Microsoft\\\\Office\\\\ClickToRun\\\\Configuration] 42\n'
                                               '"VersionToReport"="16.0.20527.20088"\n"Account"="private-account"\n')
        result = diagnostics.collect(self.root)
        self.assertEqual(result['office_version'], '16.0.20527.20088')
        self.assertEqual(result['events'], [
            {'activity': 'Office.Text.DWriteAssistant.CreateFontCollection', 'Success': False, 'Duration': 19},
            {'category': 'Word Print', 'event_id': '4qjru', 'level': 'Verbose'},
        ])
        encoded = json.dumps(result)
        self.assertNotIn('private', encoded)
        self.assertNotIn(str(self.root), encoded)

    def test_old_files_and_external_links_are_not_collected(self):
        old = self.temp / 'old.log'
        old.write_text(self.line('private', 'Word Font'))
        os.utime(old, (1, 1))
        (self.temp / 'linked.log').symlink_to(old)
        outside = self.root / 'outside.log'
        outside.write_text(self.line('private', 'Word Print'))
        (self.temp / 'external.log').symlink_to(outside)
        self.assertEqual(diagnostics.collect(self.root, since=2)['events'], [])

    def test_clicktorun_flat_failure_keeps_codes_without_error_message(self):
        message = json.dumps({'Name': 'Office.ClickToRun.VirtualRegistry.MergeAndStageRegistry',
                              'Success': False, 'Duration': 607245, 'Result.Code': 30117,
                              'Data.ErrorCode': 126, 'Data.ErrorMessage': 'private-path',
                              'CV': 'private-correlation'})
        self.assertEqual(diagnostics.event_metadata(self.line('ActivityEnded ' + message)), {
            'activity': 'Office.ClickToRun.VirtualRegistry.MergeAndStageRegistry',
            'Success': False, 'Duration': 607245, 'result_code': 30117, 'error_code': 126,
        })

    def test_failure_codes_accept_only_integers_in_both_formats(self):
        for code in (126, 'private-token', True, None, {'secret': 'private-token'}):
            for fields in ({'Name': 'Office.Test.Failure', 'Result.Code': code, 'Data.ErrorCode': code},
                           {'EventName': 'Office.Test.Failure', 'Activity': {'Result': {'Code': code}},
                            'Data': {'ErrorCode': code}}):
                with self.subTest(code=code, fields=fields):
                    result = diagnostics.event_metadata(self.line(json.dumps(fields)))
                    expected = {'activity': 'Office.Test.Failure'}
                    if type(code) is int:
                        expected.update(result_code=code, error_code=code)
                    self.assertEqual(result, expected)

    def test_limits_and_invalid_activity_values_remain_explicit(self):
        message = json.dumps({'EventName': 'Office.Text.Sample', 'Activity': {
            'Duration': 10**300, 'Success': 'private-token', 'Count': float('nan')}})
        self.assertEqual(diagnostics.event_metadata(self.line(message)), {'activity': 'Office.Text.Sample'})
        (self.temp / 'owned.log').write_text(self.line('private', 'Word Font') * 8)
        with patch.object(diagnostics, 'EVENT_LIMIT', 2):
            result = diagnostics.collect(self.root)
        self.assertEqual(len(result['events']), 2)
        self.assertEqual(result['events_omitted'], 6)
        with patch.object(diagnostics, 'BYTE_LIMIT', 10):
            self.assertEqual(diagnostics.collect(self.root)['files_truncated'], 1)


class OfficeComposition(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.runner = self.root / 'soda-11.0-36-experimental'
        self.binaries = self.root / 'compiled'
        self.binaries.mkdir()
        files = {}
        for bits, machine in ((32, 0x14c), (64, 0x8664)):
            name = f'lib/eagle/native/eagle-debug{bits}.exe'
            path = self.runner / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'original collector')
            files[name] = {'kind': 'pe', 'size': path.stat().st_size, 'sha256': compose.digest(path)}
            data = bytearray(128)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 0x3c, 64)
            data[64:68] = b'PE\0\0'
            struct.pack_into('<H', data, 68, machine)
            (self.binaries / path.name).write_bytes(data)
        path = self.runner / 'bin/wine'
        path.parent.mkdir()
        path.write_bytes(b'unchanged Wine')
        files['bin/wine'] = {'kind': 'elf', 'size': path.stat().st_size, 'sha256': compose.digest(path)}
        (self.runner / 'share/soda').mkdir(parents=True)
        (self.runner / 'share/soda/files.json').write_text(json.dumps(files))

    def test_only_collectors_change_and_original_files_stay_unchanged(self):
        before = {str(p.relative_to(self.runner)): compose.digest(p) for p in self.runner.rglob('*') if p.is_file()}
        result = compose.compose(self.runner, self.binaries, {'revision': 'a' * 40})
        after = {str(p.relative_to(self.runner)): compose.digest(p) for p in self.runner.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(len(result['replacements']), 2)
        self.assertEqual(result['unchanged_files'], 1)
        candidate = Path(result['runner'])
        self.assertEqual((candidate / 'bin/wine').read_bytes(), b'unchanged Wine')
        self.assertNotEqual((candidate / 'lib/eagle/native/eagle-debug64.exe').read_bytes(), b'original collector')
        self.assertEqual(json.loads((candidate / 'share/soda/office-composition.json').read_text()), result)

    def test_wrong_architecture_or_changed_input_fails_before_copy(self):
        (self.binaries / 'eagle-debug32.exe').write_bytes((self.binaries / 'eagle-debug64.exe').read_bytes())
        with self.assertRaises(AssertionError):
            compose.compose(self.runner, self.binaries, {'revision': 'b' * 40})
        self.assertFalse(list(self.root.glob('*-office-*')))
        (self.runner / 'bin/wine').write_bytes(b'changed Wine')
        with self.assertRaises(AssertionError):
            compose.compose(self.runner, self.binaries, {'revision': 'c' * 40})
        self.assertFalse(list(self.root.glob('*-office-*')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
