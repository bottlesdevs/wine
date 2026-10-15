import collections
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import session
import tracing


class TraceTargets(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.prefix = self.root / "bottle's directory"
        self.drive = self.prefix / 'drive_c'
        self.drive.mkdir(parents=True)
        (self.prefix / 'dosdevices').mkdir()
        (self.prefix / 'dosdevices/c:').symlink_to(self.drive)
        self.cwd = self.root / 'Program Files'
        self.cwd.mkdir()
        self.logs = self.prefix / 'logs/runs'
        self.calls = []

    def fixture(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'owned nonexecuted program fixture')
        return path

    def run_trace(self, arguments, exit_code=0):
        def capture(wine, prefix, bundle, **options):
            self.calls.append(dict(wine=wine, prefix=prefix, **options))
            bundle.mkdir(mode=0o700)
            manifest = dict(schema=1, completed=True, target=str(options['target']), arguments=options['arguments'])
            (bundle / 'manifest.json').write_text(json.dumps(manifest))
            events = [dict(kind='process_create', pid=1, tid=1, path=str(options['target'])),
                      dict(kind='process_create', pid=2, tid=2, path='owned child.exe'),
                      dict(kind='process_exit', pid=1, tid=1, code=exit_code),
                      dict(kind='process_exit', pid=2, tid=2, code=91),
                      dict(kind='finished', pid=0, tid=0)]
            for seq, event in enumerate(events):
                event['seq'] = seq
                options['observer'](event)
            (bundle / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
            return {'counts': dict(collections.Counter(event['kind'] for event in events))}
        with patch.object(tracing, 'capture', side_effect=capture):
            return tracing.trace('owned-unused-launcher', self.prefix, self.logs, arguments, self.cwd)

    def test_relative_case_and_implicit_extension_resolve_in_working_directory(self):
        target = self.fixture(self.cwd / 'APP.EXE')
        for command in ['app.exe', 'APP']:
            self.run_trace([command])
            self.assertEqual(self.calls[-1]['target'], target)

    def test_current_directory_precedes_system32_for_extension_lookup(self):
        target = self.fixture(self.cwd / 'APP.EXE')
        self.fixture(self.drive / 'windows/system32/app.exe')
        self.run_trace(['app'])
        self.assertEqual(self.calls[-1]['target'], target)

    def test_relative_windows_separators_and_directory_case_are_resolved(self):
        target = self.fixture(self.cwd / 'Sub Directory/TOOL.EXE')
        self.run_trace(['sub directory\\tool'])
        self.assertEqual(self.calls[-1]['target'], target)

    def test_system32_fallback_uses_case_insensitive_lookup(self):
        target = self.fixture(self.drive / 'Windows/System32/CMD.EXE')
        self.run_trace(['cmd', '/c', 'owned argument'])
        self.assertEqual(self.calls[-1]['target'], target)
        self.assertEqual(self.calls[-1]['arguments'], ['/c', 'owned argument'])

    def test_explicit_drive_path_preserves_existing_resolution(self):
        target = self.fixture(self.drive / 'Programs/APP.EXE')
        self.run_trace(['c:\\programs\\app.exe'])
        self.assertEqual(self.calls[-1]['target'], target)

    def test_explicit_unix_path_arguments_and_working_directory_are_preserved(self):
        target = self.fixture(self.root / "Other's Apps/real.exe")
        arguments = ['two words', "apostrophe's", 'C:\\data\\notes', '$literal']
        self.run_trace([str(target), *arguments])
        self.assertEqual(self.calls[-1]['target'], target)
        self.assertEqual(self.calls[-1]['arguments'], arguments)
        self.assertEqual(self.calls[-1]['target_cwd'], self.cwd)
        self.assertEqual(self.calls[-1]['prefix'], self.prefix)

    def test_missing_or_ambiguous_targets_fail_before_capture_and_log_creation(self):
        self.fixture(self.cwd / 'APP.EXE')
        self.fixture(self.cwd / 'App.exe')
        for command in ['app.exe', 'missing.exe', str(self.cwd / 'app.exe')]:
            with patch.object(tracing, 'capture') as capture:
                with self.assertRaises(FileNotFoundError):
                    tracing.trace('unused', self.prefix, self.logs, [command], self.cwd)
                capture.assert_not_called()
        self.assertFalse(self.logs.exists())

    def test_child_history_and_root_exit_are_retained_in_the_final_report(self):
        self.fixture(self.cwd / 'APP.EXE')
        result = self.run_trace(['app'], exit_code=37)
        self.assertEqual(result['exit_code'], 37)
        report = Path(result['log'])
        data = json.loads(report.read_text())
        self.assertEqual(data['exits'], [{'pid': 1, 'code': 37}, {'pid': 2, 'code': 91}])
        self.assertEqual(data['counts']['process_create'], 2)
        self.assertTrue(data['manifest']['completed'])
        self.assertTrue(data['export']['review_required'])
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(self.logs.glob('*.running.log')))
        self.assertNotIn(str(self.root), report.read_text())


if __name__ == '__main__':
    unittest.main()
