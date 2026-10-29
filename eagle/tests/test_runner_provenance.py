import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import provenance

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('soda_provenance', ROOT / '.github/soda-provenance.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class RunnerProvenance(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        code = self.source / 'fixture.c'
        code.write_text('int main(void) { return 7; }\n')
        self.runner = self.root / 'runner'
        (self.runner / 'bin').mkdir(parents=True)
        subprocess.run(['gcc', '-g', str(code), '-o', str(self.runner / 'bin/wine')],
                       check=True, capture_output=True, timeout=20)
        target = self.runner / 'lib/wine/x86_64-windows/fixture.exe'
        target.parent.mkdir(parents=True)
        subprocess.run(['x86_64-w64-mingw32-gcc', '-g', '-Wl,--no-insert-timestamp', str(code), '-o', str(target)],
                       check=True, capture_output=True, timeout=20)
        (self.runner / 'bin/wineboot').symlink_to('wine')
        self.tools = PACKAGE / 'lib/eagle/native'

    def build(self, **options):
        return producer.package_metadata(self.runner, self.tools, 'soda-fixture-x86_64',
                                         options.pop('sources', {'wine': str(self.source)}),
                                         options.pop('expected', {}), **options)

    def test_files_and_binary_identifiers_are_recorded_without_running_targets(self):
        summary = self.build()
        self.assertEqual(summary['source_status'], 'recorded')
        self.assertEqual(summary['file_count'], 3)
        self.assertEqual(summary['binary_count'], 2)
        files = json.loads((self.runner / 'share/soda/files.json').read_text())
        self.assertEqual(files['bin/wineboot'], {'kind': 'symlink', 'target': 'wine'})
        self.assertEqual(files['bin/wine']['kind'], 'elf')
        self.assertTrue(files['bin/wine']['identity']['build_id'])
        self.assertEqual(files['lib/wine/x86_64-windows/fixture.exe']['identity']['machine'], 0x8664)
        self.assertEqual(files['lib/wine/x86_64-windows/fixture.exe']['identity']['timestamp'], 0)

    def test_non_host_elf_and_pdb_identifiers_are_read_statically(self):
        from symbols import host_tool
        elf_linker, pe_linker = host_tool('ld.lld'), host_tool('lld-link')
        if not elf_linker or not pe_linker or not shutil.which('clang') or not shutil.which('clang-cl'):
            self.skipTest('cross-architecture/PDB fixtures require existing Clang and LLD tools')
        code = self.source / 'fixture.c'
        subprocess.run(['clang', '--target=aarch64-linux-gnu', '-nostdlib', '-static',
                        '-fuse-ld=' + elf_linker, '-Wl,--build-id', '-Wl,-e,main',
                        str(code), '-o', str(self.runner / 'bin/wine')], check=True, capture_output=True, timeout=20)
        obj = self.source / 'fixture.obj'
        subprocess.run(['clang-cl', '--target=x86_64-pc-windows-msvc', '/nologo', '/Z7', '/c',
                        str(code), '/Fo' + str(obj)], check=True, capture_output=True, timeout=20)
        target = self.runner / 'lib/wine/x86_64-windows/fixture.exe'
        subprocess.run([pe_linker, '/nologo', '/entry:main', '/subsystem:console', '/nodefaultlib', '/debug',
                        '/pdb:' + str(self.source / 'fixture.pdb'), '/pdbaltpath:fixture.pdb', '/out:' + str(target), str(obj)],
                       check=True, capture_output=True, timeout=20)
        self.build()
        records = json.loads((self.runner / 'share/soda/files.json').read_text())
        self.assertEqual(records['bin/wine']['identity']['machine'], 183)
        self.assertTrue(records['lib/wine/x86_64-windows/fixture.exe']['identity']['codeview'][0]['guid'])

    def test_hybrid_pe_machine_header_values_are_retained(self):
        target = self.runner / 'lib/wine/x86_64-windows/fixture.exe'
        original = target.read_bytes()
        offset = int.from_bytes(original[60:64], 'little') + 4
        for machine in (0xa641, 0xa64e):
            with self.subTest(machine=machine):
                data = bytearray(original)
                data[offset:offset + 2] = machine.to_bytes(2, 'little')
                target.write_bytes(data)
                self.build()
                records = json.loads((self.runner / 'share/soda/files.json').read_text())
                self.assertEqual(records['lib/wine/x86_64-windows/fixture.exe']['identity']['machine'], machine)

    def test_pe_debug_companion_does_not_read_removed_runtime_sections(self):
        target = self.runner / 'lib/wine/x86_64-windows/fixture.exe'
        debug = target.with_suffix('.exe.debug')
        subprocess.run(['x86_64-w64-mingw32-objcopy', '--only-keep-debug', str(target), str(debug)],
                       check=True, capture_output=True, timeout=20)
        self.build()
        records = json.loads((self.runner / 'share/soda/files.json').read_text())
        record = records[str(debug.relative_to(self.runner))]
        self.assertEqual(record['kind'], 'pe')
        self.assertTrue(record['identity']['debug_info'])
        self.assertEqual(record['sha256'], provenance.digest(debug))

    def test_source_revision_mismatch_does_not_create_a_manifest(self):
        with self.assertRaisesRegex(ValueError, 'source revision mismatch'):
            self.build(expected={'wine': 'a' * 40})
        self.assertFalse((self.runner / 'share/soda/build.json').exists())

    def test_refresh_preserves_compilation_sources_and_records_new_assembly(self):
        first = self.build()
        before = json.loads((self.runner / 'share/soda/sources.json').read_text())
        (self.runner / 'notice.txt').write_text('owned assembly fixture')
        summary = self.build(sources={}, refresh=True, assembly=self.source)
        after = json.loads((self.runner / 'share/soda/sources.json').read_text())
        self.assertEqual(before['sources'], after['sources'])
        self.assertEqual(summary['source_identities'], first['source_identities'])
        self.assertEqual(summary['file_count'], first['file_count'] + 1)
        self.assertIn('assembly_source', after)

    def test_refresh_retains_assembly_until_explicitly_replaced(self):
        first = self.build(assembly=self.source)
        sources = self.runner / 'share/soda/sources.json'
        original = sources.read_bytes()
        (self.source / 'fixture.c').write_text('int main(void) { return 9; }\n')
        changed = provenance.source_identity(self.source)
        self.assertNotEqual(changed['tree_sha256'], first['assembly_source_identity']['tree_sha256'])
        summary = self.build(sources={}, refresh=True)
        self.assertEqual(summary['assembly_source_identity'], first['assembly_source_identity'])
        self.assertEqual(sources.read_bytes(), original)
        record = provenance.runner_identity(self.runner / 'bin/wine')
        self.assertEqual(record['assembly_source_identity'], first['assembly_source_identity'])
        bundle = self.root / 'session'
        bundle.mkdir()
        (bundle / 'manifest.json').write_text(json.dumps({'schema': 1, 'runner_build': record}))
        (bundle / 'events.jsonl').write_text('')
        from session import export
        report = export(bundle, self.root / 'report.json')
        self.assertEqual(report['manifest']['runner_build']['assembly_source_identity'], record['assembly_source_identity'])
        replaced = self.build(sources={}, refresh=True, assembly=self.source)
        self.assertEqual(replaced['source_identities'], first['source_identities'])
        self.assertEqual(replaced['assembly_source_identity']['tree_sha256'], changed['tree_sha256'])

    def test_prebuilt_source_absence_is_explicit(self):
        with self.assertRaisesRegex(ValueError, 'provenance is unavailable'):
            self.build(sources={}, refresh=True)
        summary = self.build(sources={}, refresh=True, prebuilt=True, assembly=self.source)
        self.assertEqual(summary['source_status'], 'unavailable')
        self.assertEqual(summary['source_identities'], {})
        self.assertIn('assembly_source_identity', summary)

    def test_corrupt_source_index_prevents_refresh(self):
        self.build()
        summary = self.runner / 'share/soda/build.json'
        original = summary.read_bytes()
        (self.runner / 'share/soda/sources.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.build(sources={}, refresh=True)
        self.assertEqual(summary.read_bytes(), original)

    def test_incomplete_provenance_is_not_downgraded_to_legacy(self):
        self.build()
        (self.runner / 'share/soda/sources.json').unlink()
        with self.assertRaisesRegex(ValueError, 'provenance is incomplete'):
            self.build(sources={}, refresh=True, prebuilt=True)

    def test_metadata_directory_links_are_not_followed(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.runner / 'share').mkdir()
        (self.runner / 'share/soda').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'must not be symlinks'):
            self.build()
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlinked_directories_are_recorded_without_following_them(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'not-in-runner').write_text('owned outside fixture')
        (self.runner / 'external').symlink_to(outside, target_is_directory=True)
        self.build()
        records = json.loads((self.runner / 'share/soda/files.json').read_text())
        self.assertEqual(records['external'], {'kind': 'symlink', 'target': str(outside)})
        self.assertNotIn('external/not-in-runner', records)

    def test_nonregular_runner_entries_are_rejected_without_waiting(self):
        os.mkfifo(self.runner / 'pipe')
        with self.assertRaisesRegex(ValueError, 'regular file or symlink'):
            self.build()

    def test_repeated_inventory_is_deterministic_and_excludes_metadata(self):
        self.build()
        files = {name: (self.runner / name).read_bytes() for name in producer.METADATA}
        self.build()
        self.assertEqual(files, {name: (self.runner / name).read_bytes() for name in producer.METADATA})
        records = json.loads(files['share/soda/files.json'])
        self.assertTrue(all(name not in records for name in producer.METADATA))
        self.assertEqual((self.runner / 'share/soda/build.json').stat().st_mode & 0o777, 0o644)

    def test_runtime_matches_launcher_and_reports_changed_or_legacy_runners(self):
        wine = self.runner / 'bin/wine'
        self.assertEqual(provenance.runner_identity(wine)['status'], 'unavailable')
        summary = self.build()
        record = provenance.runner_identity(wine)
        self.assertEqual(record['status'], 'matched')
        self.assertEqual(record['source_identities'], [dict(label=name, **value) for name, value in summary['source_identities'].items()])
        wine.write_bytes(wine.read_bytes() + b'owned change')
        self.assertEqual(provenance.runner_identity(wine)['status'], 'mismatched')

    def test_runner_source_labels_survive_review_export(self):
        self.build()
        record = provenance.runner_identity(self.runner / 'bin/wine')
        bundle = self.root / 'session'
        bundle.mkdir()
        (bundle / 'manifest.json').write_text(json.dumps({'schema': 1, 'runner_build': record}))
        (bundle / 'events.jsonl').write_text('')
        from session import export
        output = self.root / 'report.json'
        report = export(bundle, output)
        self.assertEqual(report['manifest']['runner_build']['source_identities'], record['source_identities'])
        self.assertEqual(report['manifest']['runner_build']['source_identities'][0]['label'], 'wine')
        self.assertNotIn(str(self.root), output.read_text())

    def test_runtime_rejects_bad_or_nonregular_metadata(self):
        self.build()
        wine = self.runner / 'bin/wine'
        path = self.runner / 'share/soda/build.json'
        valid = json.loads(path.read_text())
        for value in ([], {'schema': True}, dict(valid, wine={}), dict(valid, source_identities={'wine': []})):
            path.write_text(json.dumps(value))
            self.assertEqual(provenance.runner_identity(wine)['status'], 'invalid')
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(provenance.runner_identity(wine)['status'], 'invalid')


if __name__ == '__main__':
    unittest.main(verbosity=2)
