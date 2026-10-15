import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import session
from test_capture_startup import Collector


class ModuleInventory(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.image = self.root / 'owned library'
        shutil.copyfile(PACKAGE / 'lib/eagle/native/eagle-elf', self.image)

    def test_unchanged_image_and_symlink_alias_share_one_identity_query(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.image)
        cache = {}
        with patch.object(session, 'identity', wraps=session.identity) as query:
            first = session.cached_identity(self.image, cache)
            self.assertEqual(session.cached_identity(alias, cache), first)
            self.assertEqual(session.cached_identity(self.image, cache), first)
        self.assertEqual(query.call_count, 1)
        self.assertEqual(first, session.identity(self.image))

    def test_rewrite_with_restored_mtime_and_same_size_is_rehashed(self):
        cache = {}
        first = session.cached_identity(self.image, cache)
        before = self.image.stat()
        data = self.image.read_bytes()
        self.image.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        os.utime(self.image, ns=(before.st_atime_ns, before.st_mtime_ns))
        with patch.object(session, 'identity', wraps=session.identity) as query:
            changed = session.cached_identity(self.image, cache)
        self.assertEqual(query.call_count, 1)
        self.assertNotEqual(first['sha256'], changed['sha256'])

    def test_replacement_growth_and_symlink_retarget_invalidate_cached_files(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.image)
        cache = {}
        session.cached_identity(alias, cache)
        replacement = self.root / 'replacement'
        shutil.copyfile(self.image, replacement)
        replacement.replace(self.image)
        with patch.object(session, 'identity', wraps=session.identity) as query:
            session.cached_identity(alias, cache)
            with self.image.open('ab') as file:
                file.write(b'owned trailing fixture bytes')
            grown = session.cached_identity(alias, cache)
            other = self.root / 'other'
            shutil.copyfile(self.image, other)
            alias.unlink()
            alias.symlink_to(other)
            self.assertEqual(session.cached_identity(alias, cache), grown)
        self.assertEqual(query.call_count, 3)

    def test_failed_and_changed_inspections_do_not_populate_cache(self):
        cache = {}
        with patch.object(session, 'identity', side_effect=ValueError('fixture failure')):
            with self.assertRaisesRegex(ValueError, 'fixture failure'):
                session.cached_identity(self.image, cache)
        self.assertEqual(cache, {})
        expected = session.identity(self.image)
        def change(path):
            with path.open('ab') as file:
                file.write(b'changed during fixture inspection')
            return expected
        with patch.object(session, 'identity', side_effect=change):
            with self.assertRaisesRegex(ValueError, 'image changed'):
                session.cached_identity(self.image, cache)
        self.assertEqual(cache, {})
        self.assertNotEqual(session.cached_identity(self.image, cache)['sha256'], expected['sha256'])

    def test_cache_is_bounded_and_evicted_files_are_queried_again(self):
        cache = {}
        paths = [self.root / str(index) for index in range(1025)]
        for path in paths:
            path.write_bytes(b'owned cache fixture')
        with patch.object(session, 'identity', return_value={'sha256': 'fixture'}) as query:
            for path in paths:
                session.cached_identity(path, cache)
            self.assertEqual(len(cache), 1024)
            self.assertNotIn(str(paths[0]), cache)
            session.cached_identity(paths[0], cache)
        self.assertEqual(query.call_count, 1026)
        self.assertEqual(len(cache), 1024)

    def maps(self, path, *args, **options):
        if str(path).startswith('/proc/') and path.name == 'maps':
            pid = int(path.parent.name)
            base = 0x400000 + pid * 0x1000
            return io.StringIO(f'{base:x}-{base + 0x1000:x} r-xp 00000000 00:00 1 {self.image}\n')
        return self.original_open(path, *args, **options)

    def test_shared_inventory_preserves_each_pid_and_mapping_and_default_behavior(self):
        self.original_open = Path.open
        cache = {}
        with patch.object(Path, 'open', lambda path, *args, **options: self.maps(path, *args, **options)), patch.object(session, 'identity', wraps=session.identity) as query:
            first, skipped = session.unix_modules(10, cache)
            second, _ = session.unix_modules(20, cache)
            default, _ = session.unix_modules(20)
        self.assertEqual(query.call_count, 2)
        self.assertEqual(skipped, 0)
        self.assertEqual(second, default)
        self.assertEqual(first[str(self.image)]['pid'], 10)
        self.assertEqual(second[str(self.image)]['pid'], 20)
        self.assertNotEqual(first[str(self.image)]['regions'], second[str(self.image)]['regions'])
        first[str(self.image)]['regions'].clear()
        self.assertTrue(second[str(self.image)]['regions'])

    def test_capture_reuses_identities_across_children_but_not_across_sessions(self):
        launcher = self.root / 'launcher'
        launcher.write_bytes(b'owned nonexecuted launcher fixture')
        launcher.chmod(0o700)
        expected = session.identity(self.image)
        self.original_open = Path.open
        for index in range(2):
            events = [dict(seq=1, kind='process_create', pid=10, tid=1, unix_pid=10, base='0x400000', path=str(self.image)),
                      dict(seq=2, kind='module_load', pid=10, tid=1, base='0x500000', path=str(self.image)),
                      dict(seq=3, kind='process_create', pid=20, tid=2, unix_pid=20, base='0x400000', path=str(self.image)),
                      dict(seq=4, kind='process_exit', pid=10, tid=1, code=0),
                      dict(seq=5, kind='process_exit', pid=20, tid=2, code=0),
                      dict(seq=6, kind='finished', pid=0, tid=0)]
            collector = Collector(events)
            self.addCleanup(collector.close)
            with patch.object(Path, 'open', lambda path, *args, **options: self.maps(path, *args, **options)), patch('session.subprocess.Popen', return_value=collector):
                with patch.object(session, 'identity', return_value=expected) as query:
                    report = session.capture(launcher, self.root / 'prefix', self.root / ('capture' + str(index)), pid=10, control_enabled=False)
            self.assertEqual(query.call_count, 1)
            self.assertTrue(report['manifest']['completed'])
            self.assertEqual(report['counts']['process_create'], 2)
            self.assertEqual(report['manifest']['modules'][str(self.image)], expected)
            self.assertEqual(report['manifest']['unix_modules'][str(self.image)]['pid'], 20)
            recorded = [json.loads(line) for line in (self.root / ('capture' + str(index)) / 'events.jsonl').read_text().splitlines()]
            self.assertEqual([row['identity'] for row in recorded[:3]], [expected] * 3)
            self.assertTrue(collector.stdout.closed)


if __name__ == '__main__':
    unittest.main()
