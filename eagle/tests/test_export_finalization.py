import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import session
from protocol import read_message, write_message
import test_trace_targets as targets


class ExportFinalization(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.bundle = self.root / 'owned.session'
        self.bundle.mkdir()
        (self.bundle / 'manifest.json').write_text(json.dumps(dict(schema=1, target='/private/owned.exe')))
        (self.bundle / 'events.jsonl').write_text('')
        self.destination = self.root / 'final.log'
        self.original = {path.name: path.read_bytes() for path in self.bundle.iterdir()}

    def assert_clean(self):
        self.assertEqual(list(self.root.glob('.eagle-export-*')), [])
        self.assertEqual(self.original, {path.name: path.read_bytes() for path in self.bundle.iterdir()})

    def test_final_name_appears_only_after_complete_private_json_is_flushed(self):
        link = os.link
        observed = []
        def publish(source, destination):
            self.assertFalse(self.destination.exists())
            self.assertEqual(Path(source).parent, self.destination.parent)
            self.assertEqual(Path(source).stat().st_mode & 0o777, 0o600)
            observed.append(json.loads(Path(source).read_text()))
            link(source, destination)
        with patch.object(session.os, 'link', side_effect=publish):
            result = session.export(self.bundle, self.destination)
        self.assertEqual(observed, [result])
        self.assertEqual(json.loads(self.destination.read_text()), result)
        self.assertTrue(result['export']['review_required'])
        self.assertNotIn('/private/', self.destination.read_text())
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o600)
        self.assert_clean()

    def test_partial_write_failure_leaves_no_final_file_and_retry_succeeds(self):
        def full_disk(value, file, **options):
            file.write('{"partial":')
            file.flush()
            raise OSError(errno.ENOSPC, 'owned disk-full fixture')
        with patch.object(session.json, 'dump', side_effect=full_disk):
            with self.assertRaises(OSError):
                session.export(self.bundle, self.destination)
        self.assertFalse(self.destination.exists())
        self.assert_clean()
        self.assertTrue(session.export(self.bundle, self.destination)['export']['review_required'])
        self.assert_clean()

    def test_flush_failure_leaves_no_final_file_or_temporary(self):
        with patch.object(session.os, 'fsync', side_effect=OSError(errno.ENOSPC, 'owned flush failure')):
            with self.assertRaises(OSError):
                session.export(self.bundle, self.destination)
        self.assertFalse(self.destination.exists())
        self.assert_clean()
        session.export(self.bundle, self.destination)

    def test_unsupported_publication_fails_without_partial_destination(self):
        with patch.object(session.os, 'link', side_effect=OSError(errno.EOPNOTSUPP, 'owned filesystem fixture')):
            with self.assertRaises(OSError):
                session.export(self.bundle, self.destination)
        self.assertFalse(self.destination.exists())
        self.assert_clean()

    def test_concurrent_destination_is_never_replaced(self):
        link = os.link
        def compete(source, destination):
            self.destination.write_text('owned competing export')
            link(source, destination)
        with patch.object(session.os, 'link', side_effect=compete):
            with self.assertRaises(FileExistsError):
                session.export(self.bundle, self.destination)
        self.assertEqual(self.destination.read_text(), 'owned competing export')
        self.assert_clean()

    def test_existing_file_and_symlink_contents_and_permissions_are_preserved(self):
        existing = self.root / 'existing'
        existing.write_text('owned existing content')
        existing.chmod(0o640)
        for symlink in (False, True):
            if symlink:
                self.destination.symlink_to(existing)
            else:
                self.destination.write_text('owned destination')
            before = self.destination.read_bytes(), self.destination.lstat().st_mode
            with self.assertRaises(FileExistsError):
                session.export(self.bundle, self.destination)
            self.assertEqual((self.destination.read_bytes(), self.destination.lstat().st_mode), before)
            self.assertEqual(existing.read_text(), 'owned existing content')
            self.assertEqual(existing.stat().st_mode & 0o777, 0o640)
            self.destination.unlink()
            self.assert_clean()

    def test_trace_finalization_failure_keeps_live_log_and_raw_bundle_for_retry(self):
        fixture = targets.TraceTargets()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.fixture(fixture.cwd / 'APP.EXE')
        def full_disk(value, file, **options):
            file.write('{')
            raise OSError(errno.ENOSPC, 'owned disk-full fixture')
        with patch.object(session.json, 'dump', side_effect=full_disk):
            with self.assertRaises(OSError):
                fixture.run_trace(['app'], exit_code=37)
        live, = fixture.logs.glob('*.running.log')
        self.assertTrue(any(json.loads(line).get('kind') == 'process_exit' for line in live.read_text().splitlines()))
        self.assertEqual(list(fixture.logs.glob('.eagle-export-*')), [])
        self.assertEqual(list(fixture.logs.glob('*.log')), [live])
        bundle, = fixture.logs.glob('*.session')
        before = (bundle / 'events.jsonl').read_bytes()
        report = bundle.with_suffix('.log')
        session.export(bundle, report)
        self.assertEqual((bundle / 'events.jsonl').read_bytes(), before)
        self.assertEqual(json.loads(report.read_text())['exits'][0]['code'], 37)
        self.assertTrue(live.exists())

    def test_stdio_export_write_error_is_structured_and_same_destination_can_be_retried(self):
        script = """import errno,sys
sys.path.insert(0,sys.argv[1])
import session,protocol
original=session.json.dump
failed=False
def dump(value,file,**options):
    global failed
    if not failed:
        failed=True
        file.write('{')
        raise OSError(errno.ENOSPC,'owned disk-full fixture')
    return original(value,file,**options)
session.json.dump=dump
protocol.serve()
"""
        requests = [(1, 'initialize', {'schema': 1}),
                    (2, 'export', {'session': str(self.bundle), 'output': str(self.destination)}),
                    (3, 'inspect', {'session': str(self.bundle)}),
                    (4, 'export', {'session': str(self.bundle), 'output': str(self.destination)}),
                    (5, 'shutdown', {})]
        stream = io.BytesIO()
        for request_id, method, params in requests:
            write_message(stream, dict(id=request_id, method=method, params=params))
        result = subprocess.run([sys.executable, '-S', '-c', script, str(PACKAGE / 'lib/eagle')],
                                input=stream.getvalue(), capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        stream = io.BytesIO(result.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertIn('error', replies[1])
        self.assertEqual(replies[2]['result']['manifest']['schema'], 1)
        self.assertTrue(replies[3]['result']['export']['review_required'])
        self.assertEqual(json.loads(self.destination.read_text()), replies[3]['result'])
        self.assert_clean()


if __name__ == '__main__':
    unittest.main()
