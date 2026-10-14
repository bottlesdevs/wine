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
import provenance


class BuildProvenance(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'fixture.c').write_text('int fixture(void) { return 7; }\n')
        self.package = self.root / 'package'
        self.collector = self.package / 'lib/eagle/native/eagle-debug64.exe'
        self.collector.parent.mkdir(parents=True)
        self.collector.write_bytes(b'owned collector fixture')
        self.wine = self.root / 'wine'
        self.wine.write_bytes(b'owned launcher fixture')
        self.wine.chmod(0o700)

    def test_source_revision_and_dirty_tree_are_distinct(self):
        subprocess.run(['git', 'init', '-q', str(self.source)], check=True)
        subprocess.run(['git', '-C', str(self.source), 'add', 'fixture.c'], check=True)
        hooks = self.root / 'hooks'
        hooks.mkdir()
        subprocess.run(['git', '-C', str(self.source), '-c', 'core.hooksPath=' + str(hooks),
                        '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'fixture'], check=True)
        clean = provenance.source_identity(self.source)
        self.assertFalse(clean['dirty'])
        self.assertRegex(clean['revision'], r'^[0-9a-f]{40}$')
        (self.source / 'fixture.c').write_text('int fixture(void) { return 19; }\n')
        dirty = provenance.source_identity(self.source)
        self.assertTrue(dirty['dirty'])
        self.assertEqual(clean['revision'], dirty['revision'])
        self.assertNotEqual(clean['tree_sha256'], dirty['tree_sha256'])

    def test_archive_source_has_hashes_without_an_invented_revision(self):
        identity = provenance.source_identity(self.source)
        self.assertIsNone(identity['revision'])
        self.assertIsNone(identity['dirty'])
        self.assertEqual(identity['files']['fixture.c'], provenance.digest(self.source / 'fixture.c'))

    def test_source_symlinks_record_targets_without_reading_them(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'owned external fixture')
        link = self.source / 'fixture-link'
        link.symlink_to(outside)
        before = provenance.source_identity(self.source)
        outside.write_bytes(b'changed external fixture')
        after = provenance.source_identity(self.source)
        self.assertEqual(before['tree_sha256'], after['tree_sha256'])
        self.assertEqual(before['symlinks'], {'fixture-link': str(outside)})
        self.assertNotIn('fixture-link', before['files'])
        link.unlink()
        link.symlink_to('missing fixture')
        self.assertNotEqual(before['tree_sha256'], provenance.source_identity(self.source)['tree_sha256'])

    def test_manifest_write_is_deterministic_and_does_not_hash_itself(self):
        first = provenance.write(self.source, self.package)
        manifest = self.package / 'share/eagle/build.json'
        original = manifest.read_bytes()
        second = provenance.write(self.source, self.package)
        self.assertEqual(first, second)
        self.assertEqual(original, manifest.read_bytes())
        self.assertNotIn('share/eagle/build.json', first['files'])

    def test_capture_records_matching_and_changed_collectors(self):
        manifest = provenance.write(self.source, self.package)
        result = provenance.capture_identity(self.package, self.wine, self.collector)
        self.assertEqual(result['status'], 'matched')
        self.assertEqual(result['source_identity']['tree_sha256'], manifest['source']['tree_sha256'])
        self.assertEqual(result['wine_sha256'], provenance.digest(self.wine))
        self.collector.write_bytes(b'changed owned collector')
        changed = provenance.capture_identity(self.package, self.wine, self.collector)
        self.assertEqual(changed['status'], 'mismatched')
        self.assertNotEqual(result['collector_sha256'], changed['collector_sha256'])

    def test_missing_metadata_remains_explicit_for_older_packages(self):
        result = provenance.capture_identity(self.package, self.wine, self.collector)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['collector_sha256'], provenance.digest(self.collector))

    def test_invalid_metadata_is_not_accepted_as_a_build_identity(self):
        valid = provenance.write(self.source, self.package)
        manifest = self.package / 'share/eagle/build.json'
        for value in ([], {'schema': True}, dict(valid, source=[]),
                      dict(valid, source=dict(valid['source'], dirty=1)),
                      dict(valid, source=dict(valid['source'], revision='a' * 41)),
                      dict(valid, source=dict(valid['source'], tree_sha256='not-a-hash')),
                      dict(valid, files={})):
            with self.subTest(value=value):
                manifest.write_text(json.dumps(value))
                self.assertEqual(provenance.capture_identity(self.package, self.wine, self.collector)['status'], 'invalid')

    def test_nonregular_and_oversized_metadata_return_without_waiting(self):
        provenance.write(self.source, self.package)
        manifest = self.package / 'share/eagle/build.json'
        manifest.unlink()
        os.mkfifo(manifest)
        self.assertEqual(provenance.capture_identity(self.package, self.wine, self.collector)['status'], 'invalid')
        manifest.unlink()
        manifest.write_bytes(b' ' * (1024 * 1024 + 1))
        self.assertEqual(provenance.capture_identity(self.package, self.wine, self.collector)['status'], 'invalid')

    def test_capture_setup_persists_identity_before_process_creation(self):
        import session
        root = self.root / 'run'
        control = session.socket.socket(session.socket.AF_UNIX)
        with patch('session.socket.socket', return_value=control), patch('session.subprocess.Popen', side_effect=OSError('owned launch fixture stopped')):
            with self.assertRaisesRegex(OSError, 'owned launch fixture stopped'):
                session.capture(self.wine, self.root / 'prefix', root, pid=123, control_enabled=False)
        manifest = json.loads((root / 'manifest.json').read_text())
        self.assertEqual(manifest['build']['wine_sha256'], provenance.digest(self.wine))
        self.assertIn(manifest['build']['status'], ('matched', 'unavailable'))
        self.assertEqual(manifest['setup_error'], 'owned launch fixture stopped')
        self.assertFalse(manifest['completed'])
        self.assertTrue((root / 'events.jsonl').is_file())
        self.assertEqual(control.fileno(), -1)
        output = self.root / 'export.json'
        session.export(root, output)
        exported = json.loads(output.read_text())
        if manifest['build']['status'] == 'matched':
            self.assertEqual(exported['manifest']['build']['source_identity'], manifest['build']['source_identity'])
        self.assertNotIn(str(self.root), output.read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
