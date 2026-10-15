import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_inline_packages as packages
import session
import session_symbols
from protocol import read_message, write_message

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])


class SavedSymbols(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        packages.InlinePackages.setUpClass()

    def setUp(self):
        self.fixture = packages.InlinePackages()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root

    def image(self, compiler='gcc', **options):
        image, pdb, source, rva = self.fixture.fixture.build(compiler, **options)
        identity = session.identity(image)
        mapping = dict(sha256=identity['sha256'], image=str(image))
        if pdb:
            mapping['pdb'] = str(pdb)
        return image, identity, mapping, rva

    def load(self, image, identity, pid=1, base=0x400000, path='C:\\lab\\shared.dll', kind='module_load'):
        return dict(kind=kind, pid=pid, tid=2, path=path, image=str(image), identity=identity,
                    base=hex(base), identity_origin='owned fixture identity')

    def snapshot(self, rva, pid=1, base=0x400000, path='c:/lab/shared.dll'):
        return dict(kind='snapshot', pid=pid, tid=2,
                    frames=[dict(module='shared', image=path, rva=rva, address=hex(base + int(rva, 0)), symbol='captured-export')])

    def bundle(self, events, manifest=None):
        root = self.root / ('session-' + str(len(list(self.root.iterdir()))))
        root.mkdir()
        (root / 'manifest.json').write_text(json.dumps(dict(schema=1, **(manifest or {}))))
        (root / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
        return root

    def test_owned_elf_pe_and_pdb_frames_gain_source_and_inlines(self):
        for compiler, options in [('gcc', {}), ('i686-w64-mingw32-gcc', {}), ('x86_64-w64-mingw32-gcc', {}),
                                  ('pdb', {'target': 'i686'}), ('pdb', {'target': 'x86_64'}), ('pdb', {'target': 'aarch64'})]:
            with self.subTest(compiler=compiler, options=options):
                image, identity, mapping, rva = self.image(compiler, **options)
                mapping['debug_files'] = []
                root = self.bundle([self.load(image, identity), self.snapshot(rva)])
                before = (root / 'events.jsonl').read_bytes(), image.read_bytes()
                report = session.summary(root, [mapping])
                frame = report['snapshots'][0]['frames'][0]
                self.assertEqual(frame['symbol'], 'captured-export')
                enriched = frame['offline_symbols']
                self.assertEqual(enriched['status'], 'source-resolved')
                self.assertEqual(enriched['image_sha256'], identity['sha256'])
                self.assertEqual([value['symbol'] for value in enriched['resolved']['inline_frames']], ['leaf', 'middle', 'outer'])
                self.assertEqual(report['offline_symbolization']['counts'], {'source-resolved': 1})
                self.assertEqual(before, ((root / 'events.jsonl').read_bytes(), image.read_bytes()))

    def test_load_unload_reload_pid_reuse_and_exact_paths_select_recorded_identity(self):
        first, a, map_a, rva_a = self.image()
        second, b, map_b, rva_b = self.image()
        events = [self.load(first, a, kind='process_create'), self.load(second, b, pid=2, base=0x500000),
                  self.snapshot(rva_a), self.snapshot(rva_b, pid=2, base=0x500000),
                  self.snapshot(rva_a, path='d:/other/shared.dll'), self.snapshot(rva_a, base=0x900000),
                  dict(kind='module_unload', pid=1, base='0x400000'), self.snapshot(rva_a),
                  self.load(second, b), self.snapshot(rva_b), dict(kind='process_exit', pid=1, code=0),
                  self.snapshot(rva_b), self.load(first, a, kind='process_create'), self.snapshot(rva_a)]
        report = session.summary(self.bundle(events), [map_a, map_b])
        values = [event['frames'][0]['offline_symbols'] for event in report['snapshots']]
        self.assertEqual([value['status'] for value in values], ['source-resolved', 'source-resolved', 'unavailable', 'unavailable',
                                                               'unavailable', 'source-resolved', 'unavailable', 'source-resolved'])
        self.assertEqual([values[index]['image_sha256'] for index in (0, 1, 5, 7)], [a['sha256'], b['sha256'], b['sha256'], a['sha256']])

    def test_wrong_artifact_and_modified_selected_image_never_supply_source(self):
        first, identity, mapping, rva = self.image()
        second, _, _, _ = self.image()
        root = self.bundle([self.load(first, identity), self.snapshot(rva)])
        wrong = session.summary(root, [dict(mapping, image=str(second))])
        self.assertEqual(wrong['snapshots'][0]['frames'][0]['offline_symbols']['status'], 'unavailable')
        query = session_symbols.query
        def changed(*arguments, **options):
            result = query(*arguments, **options)
            with first.open('ab') as file:
                file.write(b'owned-concurrent-change')
            return result
        with patch.object(session_symbols, 'query', side_effect=changed):
            report = session.summary(root, [mapping])
        frame = report['snapshots'][0]['frames'][0]['offline_symbols']
        self.assertEqual(frame['status'], 'unavailable')
        self.assertNotIn('resolved', frame)

    def test_manifest_only_sessions_are_explicitly_unverified_and_do_not_resurrect_exited_processes(self):
        image, identity, mapping, rva = self.image()
        event = self.snapshot(rva, path=str(image))
        root = self.bundle([event, dict(kind='process_exit', pid=1, code=0), event], {'modules': {str(image): identity}})
        report = session.summary(root, [mapping])
        first, second = [event['frames'][0]['offline_symbols'] for event in report['snapshots']]
        self.assertEqual(first['status'], 'source-resolved')
        self.assertEqual(first['identity_origin'], 'manifest only; runtime unverified')
        self.assertEqual(second['status'], 'unavailable')

    def test_unused_missing_selections_and_unselected_frames_do_not_read_recorded_paths(self):
        image, identity, _, rva = self.image()
        root = self.bundle([self.load(image, identity), self.snapshot(rva)])
        mapping = dict(sha256='f' * 64, image=str(self.root / 'unused-missing-image'))
        with patch.object(session_symbols, 'file_identity', side_effect=AssertionError('unexpected artifact read')):
            report = session.summary(root, [mapping])
        self.assertEqual(report['offline_symbolization']['images'], {})
        self.assertEqual(report['snapshots'][0]['frames'][0]['offline_symbols']['reason'], 'no reviewed image for recorded SHA256')

    def test_invalid_and_ambiguous_selections_fail_before_export_creation(self):
        image, identity, mapping, rva = self.image()
        root = self.bundle([self.load(image, identity), self.snapshot(rva)])
        values = [None, {}, [None], [{}], [dict(mapping, sha256='bad')], [dict(mapping, image=True)],
                  [dict(mapping, inlines='yes')], [dict(mapping, debug_files=[True])],
                  [dict(mapping, unknown=True)], [mapping, dict(mapping, image=str(image) + '.other')], [mapping] * 257]
        for index, value in enumerate(values):
            if value is None:
                continue
            destination = self.root / ('invalid-' + str(index) + '.json')
            with self.subTest(value=index), self.assertRaises(ValueError):
                session.export(root, destination, value)
            self.assertFalse(destination.exists())
        report = session.summary(root, [mapping, mapping])
        self.assertEqual(report['offline_symbolization']['counts'], {'source-resolved': 1})

    def test_unique_address_limit_reuses_results_for_duplicate_frames(self):
        image, identity, mapping, _ = self.image()
        events = [self.load(image, identity)]
        snapshot = self.snapshot('0x0')
        snapshot['frames'] = [self.snapshot(hex(offset))['frames'][0] for offset in range(257)]
        snapshot['frames'].append(copy.deepcopy(snapshot['frames'][0]))
        events.append(snapshot)
        report = session.summary(self.bundle(events), [mapping])
        frames = [frame['offline_symbols'] for frame in report['snapshots'][0]['frames']]
        self.assertEqual(frames[1]['reason'], 'offline address limit reached')
        self.assertNotEqual(frames[256]['status'], 'unavailable')
        self.assertNotEqual(frames[257]['status'], 'unavailable')
        self.assertEqual(frames[0]['resolved'], frames[257]['resolved'])

    def test_terminal_fault_addresses_survive_later_snapshot_budget_pressure(self):
        image, identity, mapping, _ = self.image()
        earlier = self.snapshot('0x0')
        earlier['frames'] = [self.snapshot(hex(offset))['frames'][0] for offset in range(257)]
        later = self.snapshot('0x300')
        later['frames'] = [self.snapshot(hex(offset))['frames'][0] for offset in range(512, 800)]
        fault = dict(kind='exception', pid=1, tid=2, first_chance=False, code='0xc0000005', frame=self.snapshot('0x0')['frames'][0])
        report = session.summary(self.bundle([self.load(image, identity), earlier, fault, later]), [mapping])
        self.assertNotEqual(report['terminal_exceptions'][0]['frame']['offline_symbols']['status'], 'unavailable')
        self.assertEqual(report['snapshots'][0]['frames'][1]['offline_symbols']['reason'], 'offline address limit reached')
        self.assertNotEqual(report['snapshots'][1]['frames'][-1]['offline_symbols']['status'], 'unavailable')

    def test_ambiguous_active_image_paths_require_a_matching_load_base(self):
        first, a, map_a, rva_a = self.image()
        second, b, map_b, rva_b = self.image()
        unknown = self.snapshot(rva_a)
        del unknown['frames'][0]['address']
        events = [self.load(first, a), self.load(second, b, base=0x500000), self.snapshot(rva_a),
                  self.snapshot(rva_b, base=0x500000), unknown,
                  dict(kind='module_unload', pid=1, base='0x500000'), self.snapshot(rva_a)]
        report = session.summary(self.bundle(events), [map_a, map_b])
        annotations = [value['frames'][0]['offline_symbols'] for value in report['snapshots']]
        self.assertEqual(annotations[0]['image_sha256'], a['sha256'])
        self.assertEqual(annotations[1]['image_sha256'], b['sha256'])
        self.assertEqual(annotations[2]['status'], 'unavailable')
        self.assertEqual(annotations[3]['image_sha256'], a['sha256'])

    def test_outside_image_rva_does_not_displace_valid_frames(self):
        image, identity, mapping, rva = self.image()
        event = self.snapshot(rva)
        event['frames'].append(self.snapshot(hex(identity['size'] + 1))['frames'][0])
        report = session.summary(self.bundle([self.load(image, identity), event]), [mapping])
        first, second = [frame['offline_symbols'] for frame in report['snapshots'][0]['frames']]
        self.assertEqual(first['status'], 'source-resolved')
        self.assertEqual(second['reason'], 'recorded RVA is outside the selected image')

    def test_export_redacts_selected_paths_sources_and_private_diagnostics(self):
        image, identity, mapping, rva = self.image()
        root = self.bundle([self.load(image, identity), self.snapshot(rva)], {'modules': {str(image): identity}})
        report = session.export(root, self.root / 'good-export.json', [mapping])
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertEqual(report['snapshots'][0]['frames'][0]['offline_symbols']['status'], 'source-resolved')
        missing = dict(mapping, image=str(self.root / 'PRIVATE-MISSING-IMAGE'))
        private = session.summary(root, [missing])
        self.assertIn('PRIVATE-MISSING-IMAGE', json.dumps(private['offline_symbolization']))
        shared = session.export(root, self.root / 'missing-export.json', [missing])
        self.assertNotIn('PRIVATE-MISSING-IMAGE', json.dumps(shared))
        self.assertNotIn(str(self.root), json.dumps(shared))
        self.assertTrue(shared['export']['review_required'])

    def test_relocated_split_bundle_selection_supplies_saved_inline_frames(self):
        image, package, _, rva = self.fixture.build()
        identity = session.identity(image)
        mapping = dict(sha256=identity['sha256'], image=str(image), debug_files=[str(package)])
        report = session.summary(self.bundle([self.load(image, identity), self.snapshot(rva)]), [mapping])
        self.assertEqual(report['snapshots'][0]['frames'][0]['offline_symbols']['resolved']['inline_status'], 'available')
        self.assertEqual(report['offline_symbolization']['images'][identity['sha256']]['inline_artifacts']['status'], 'matched')

    def test_reviewed_selection_file_size_and_regular_file_contract(self):
        configuration = self.root / 'selection.json'
        configuration.write_bytes(b'[]' + b' ' * (1024 * 1024 - 2))
        self.assertEqual(session_symbols.read_images(configuration), [])
        with configuration.open('ab') as file:
            file.write(b' ')
        with self.assertRaisesRegex(ValueError, 'exceeds limit'):
            session_symbols.read_images(configuration)
        pipe = self.root / 'selection-pipe'
        os.mkfifo(pipe)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            session_symbols.read_images(pipe)

    def test_cli_and_stdio_selected_exports_match_and_keep_review_required(self):
        image, identity, mapping, rva = self.image()
        root = self.bundle([self.load(image, identity), self.snapshot(rva)], {'modules': {str(image): identity}})
        configuration = self.root / 'reviewed.json'
        configuration.write_text(json.dumps([mapping]))
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        cli = subprocess.run([*command, 'export', str(root), str(self.root / 'cli-export.json'), '--symbol-images', str(configuration)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        expected = json.loads(cli.stdout)['data']
        self.assertNotIn(str(self.root), json.dumps(expected))
        destination = self.root / 'backend-export.json'
        stream = io.BytesIO()
        requests = [(1, 'initialize', {'schema': 1}), (2, 'export', {'session': str(root), 'output': str(destination), 'symbol_images': [mapping]}),
                    (3, 'shutdown', {})]
        for i, method, params in requests:
            write_message(stream, dict(id=i, method=method, params=params))
        result = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        stream = io.BytesIO(result.stdout)
        read_message(stream)
        self.assertEqual(read_message(stream)['result'], expected)
        self.assertEqual(json.loads(destination.read_text()), expected)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertTrue(expected['export']['review_required'])

    def test_cli_stdio_default_compatibility_selection_and_recovery(self):
        image, identity, mapping, rva = self.image()
        root = self.bundle([self.load(image, identity), self.snapshot(rva)])
        configuration = self.root / 'reviewed.json'
        configuration.write_text(json.dumps([mapping]))
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        plain = subprocess.run([*command, 'inspect', str(root)], capture_output=True, text=True, timeout=15)
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertNotIn('offline_symbolization', json.loads(plain.stdout)['data'])
        selected = subprocess.run([*command, 'inspect', str(root), '--symbol-images', str(configuration)], capture_output=True, text=True, timeout=30)
        self.assertEqual(selected.returncode, 0, selected.stderr)
        expected = json.loads(selected.stdout)['data']
        requests = [(1, 'initialize', {'schema': 1}), (2, 'inspect', {'session': str(root), 'symbol_images': [mapping]}),
                    (3, 'inspect', {'session': str(root), 'symbol_images': {}}),
                    (4, 'inspect', {'session': str(root), 'symbol_images': [mapping]}), (5, 'shutdown', {})]
        stream = io.BytesIO()
        for i, method, params in requests:
            write_message(stream, dict(id=i, method=method, params=params))
        result = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        stream = io.BytesIO(result.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertEqual(replies[1]['result'], expected)
        self.assertEqual(replies[2]['error']['code'], -32602)
        self.assertEqual(replies[3]['result'], expected)


if __name__ == '__main__':
    unittest.main()
