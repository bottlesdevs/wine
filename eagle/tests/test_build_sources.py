import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_runner_provenance as fixtures

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import build_sources
import symbols
from protocol import read_message, write_message


class BuildSources(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RunnerProvenance()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.build()
        self.image = self.fixture.runner / 'bin/wine'
        self.metadata = self.fixture.runner / 'share/soda'
        self.mapping = {'source': 'wine', 'path': 'fixture.c', 'file': str(self.fixture.source / 'fixture.c')}

    def report(self, maps=None, image=None):
        return symbols.query(image or self.image, runner_root=str(self.fixture.runner),
                             source_maps=maps if maps is not None else [self.mapping])['build_sources']

    def rewrite_sources(self, change):
        path = self.metadata / 'sources.json'
        inventory = json.loads(path.read_text())
        change(inventory)
        path.write_text(json.dumps(inventory))
        summary_path = self.metadata / 'build.json'
        summary = json.loads(summary_path.read_text())
        summary['sources_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        for label, source in inventory['sources'].items():
            summary['source_identities'][label] = {key: source[key] for key in ('revision', 'dirty', 'tree_sha256')}
        summary_path.write_text(json.dumps(summary))

    def test_actual_producer_binds_elf_and_pe_to_recorded_source_bytes(self):
        for image in [self.image, self.fixture.runner / 'lib/wine/x86_64-windows/fixture.exe']:
            with self.subTest(image=image.name):
                result = self.report(image=image)
                self.assertEqual(result['status'], 'available', result)
                self.assertEqual(result['files'][0]['status'], 'matched')
                self.assertEqual(result['files'][0]['sha256'], result['files'][0]['expected_sha256'])
                self.assertEqual(result['image']['sha256'], symbols.query(image)['sha256'])
                self.assertIn('per-module compile usage', result['scope'])

    def test_changed_missing_and_unrecorded_files_are_distinct(self):
        original = Path(self.mapping['file'])
        original.write_text(original.read_text() + '/* owned change */\n')
        missing = dict(self.mapping, file=str(self.fixture.root / 'missing.c'))
        absent = dict(self.mapping, path='elsewhere/fixture.c')
        result = self.report([self.mapping, missing, absent])
        self.assertEqual([file['status'] for file in result['files']], ['mismatched', 'missing', 'not-recorded'])

    def test_metadata_digests_are_checked_before_source_association(self):
        for name in ('files.json', 'sources.json'):
            with self.subTest(name=name):
                path = self.metadata / name
                original = path.read_bytes()
                path.write_bytes(original + b' ')
                result = self.report()
                self.assertEqual(result['status'], 'invalid')
                self.assertIn('digest', result['reason'])
                self.assertFalse(result['files'])
                path.write_bytes(original)

    def test_inner_source_tree_digest_is_checked_even_with_a_matching_outer_digest(self):
        self.rewrite_sources(lambda value: value['sources']['wine']['files'].update({'fixture.c': '0' * 64}))
        result = self.report()
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('source tree digest', result['reason'])

    def test_foreign_and_changed_images_do_not_use_the_inventory(self):
        other = self.fixture.root / 'outside'
        shutil.copyfile(self.image, other)
        self.assertEqual(self.report(image=other)['status'], 'invalid')
        with self.image.open('ab') as file:
            file.write(b'owned-changed-image')
        result = self.report()
        self.assertEqual(result['status'], 'mismatched')
        self.assertFalse(result['files'])

    def test_recorded_links_resolve_lexically_and_external_or_cyclic_links_do_not(self):
        source = self.fixture.source
        (source / 'alias.c').symlink_to('fixture.c')
        (source / 'directory').symlink_to('.', target_is_directory=True)
        (source / 'outside.c').symlink_to('../../outside.c')
        (source / 'cycle-a.c').symlink_to('cycle-b.c')
        (source / 'cycle-b.c').symlink_to('cycle-a.c')
        self.fixture.build()
        maps = [dict(self.mapping, path=path) for path in ['alias.c', 'directory/fixture.c', 'outside.c', 'cycle-a.c']]
        result = self.report(maps)
        self.assertEqual(result['status'], 'available')
        self.assertEqual([file['status'] for file in result['files']], ['matched', 'matched', 'invalid', 'invalid'])
        self.assertEqual(result['files'][0]['recorded_path'], 'fixture.c')

    def test_nonregular_and_symlink_metadata_are_rejected(self):
        path = self.metadata / 'files.json'
        saved = self.metadata / 'saved-index'
        path.rename(saved)
        path.symlink_to(saved)
        self.assertEqual(self.report()['status'], 'invalid')
        path.unlink()
        os.mkfifo(path)
        result = self.report()
        self.assertEqual(result['status'], 'invalid')
        self.assertFalse(result['files'])

    def test_large_retained_source_inventory_does_not_require_its_original_files(self):
        def enlarge(value):
            source = value['sources']['wine']
            checksum = source['files']['fixture.c']
            source['files'].update({('retained-source-' + str(index) + '/unit.c'): checksum for index in range(14000)})
            source['tree_sha256'] = hashlib.sha256(json.dumps(source['files'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.rewrite_sources(enlarge)
        self.assertGreater((self.metadata / 'sources.json').stat().st_size, 1024 * 1024)
        result = self.report()
        self.assertEqual(result['files'][0]['status'], 'matched')

    def test_explicit_reviewed_file_can_be_renamed_and_requires_no_llvm_or_source_scan(self):
        reviewed = self.fixture.root / 'reviewed-renamed.c'
        shutil.copyfile(Path(self.mapping['file']), reviewed)
        shutil.rmtree(self.fixture.source)
        with patch.object(symbols, 'host_tool', side_effect=AssertionError('unexpected LLVM lookup')):
            result = self.report([dict(self.mapping, file=str(reviewed))])
        self.assertEqual(result['files'][0]['status'], 'matched')
        self.assertEqual(result['files'][0]['recorded_path'], 'fixture.c')

    def test_metadata_mutation_after_reading_invalidates_the_result(self):
        original = build_sources.source_identity
        def changed(path, deadline):
            result = original(path, deadline)
            with (self.metadata / 'sources.json').open('ab') as file:
                file.write(b' ')
            return result
        with patch.object(build_sources, 'source_identity', side_effect=changed):
            result = self.report()
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('changed', result['reason'])
        self.assertFalse(result['files'])

    def test_missing_partial_and_legacy_metadata_are_distinct(self):
        (self.metadata / 'sources.json').unlink()
        result = self.report()
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('incomplete', result['reason'])
        for name in ('build.json', 'files.json'):
            (self.metadata / name).unlink()
        self.assertEqual(self.report()['status'], 'unavailable')
        self.fixture.build(sources={}, refresh=True, prebuilt=True)
        result = self.report()
        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('no recorded', result['reason'])

    def test_inventory_report_is_bound_to_the_initial_query_image_hash(self):
        original = build_sources.inspect_build_sources
        def changed(*arguments):
            with self.image.open('ab') as file:
                file.write(b'owned-query-race')
            return original(*arguments)
        with patch.object(build_sources, 'inspect_build_sources', side_effect=changed):
            result = self.report()
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('image changed', result['reason'])
        self.assertFalse(result['files'])

    def test_combined_source_reports_remain_below_the_transport_budget(self):
        import sources
        report = {'status': 'available', 'files': [{'path': '/' + 'x' * 3500} for _ in range(128)]}
        with patch.object(sources, 'inspect_sources', return_value=report), patch.object(build_sources, 'inspect_build_sources', return_value=report):
            with self.assertRaisesRegex(ValueError, 'source query response exceeds limit'):
                symbols.query(self.image, sources=True, runner_root=str(self.fixture.runner))

    def test_cli_backend_and_invalid_mapping_recovery(self):
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        cli = subprocess.run([*command, 'symbols', str(self.image), '--runner-root', str(self.fixture.runner),
                              '--source-map', 'wine:fixture.c=' + self.mapping['file']], capture_output=True, text=True, timeout=25)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        expected = json.loads(cli.stdout)['data']
        for maps in [True, [{}], [dict(self.mapping, path='../fixture.c')], [self.mapping] * 257]:
            with self.subTest(maps=str(maps)[:60]), self.assertRaises(ValueError):
                symbols.query(self.image, runner_root=str(self.fixture.runner), source_maps=maps)
        with self.assertRaises(ValueError):
            symbols.query(self.image, source_maps=[self.mapping])
        requests = [(1, 'initialize', {'schema': 1}), (2, 'symbols', {'path': str(self.image), 'runner_root': str(self.fixture.runner), 'source_maps': [self.mapping]}),
                    (3, 'symbols', {'path': str(self.image), 'runner_root': str(self.fixture.runner), 'source_maps': True}),
                    (4, 'symbols', {'path': str(self.image), 'runner_root': str(self.fixture.runner), 'source_maps': [self.mapping]}), (5, 'shutdown', {})]
        stream = io.BytesIO()
        for i, method, params in requests:
            write_message(stream, dict(id=i, method=method, params=params))
        process = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        stream = io.BytesIO(process.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertEqual(replies[1]['result'], expected)
        self.assertEqual(replies[3]['result'], expected)
        self.assertEqual(replies[2]['error']['code'], -32602)


if __name__ == '__main__':
    unittest.main()
