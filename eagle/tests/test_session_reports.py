import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_session_symbols as fixtures
import session
import session_reports
import session_symbols
from protocol import read_message, write_message

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])


class SessionReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.SavedSymbols.setUpClass()

    def setUp(self):
        self.fixture = fixtures.SavedSymbols()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root

    def events(self, compiler='gcc'):
        image, identity, mapping, rva = self.fixture.image(compiler)
        events = [self.fixture.load(image, identity), self.fixture.snapshot(rva)]
        for index, event in enumerate(events, 1):
            event['seq'] = index
        return image, identity, mapping, rva, events

    def report(self, events, manifest=None):
        root = self.fixture.bundle(events, manifest)
        destination = self.root / ('report-' + str(len(list(self.root.iterdir()))) + '.log')
        value = session.export(root, destination)
        return root, destination, value

    def live(self, events, tail=b'', **header):
        destination = self.root / ('live-' + str(len(list(self.root.iterdir()))) + '.running.log')
        first = dict(format='eagle-live-v1', completed=False, byte_limit=16 * 1024 * 1024)
        first.update(header)
        destination.write_bytes((json.dumps(first) + '\n' + ''.join(json.dumps(session.redact(event)) + '\n' for event in events)).encode() + tail)
        return destination

    def test_generated_exported_elf_and_pdb_logs_gain_reviewed_source_without_session_directory(self):
        for compiler in ('gcc', 'pdb'):
            with self.subTest(compiler=compiler):
                image, identity, mapping, _, events = self.events(compiler)
                root, path, original = self.report(events, {'modules': {str(image): identity}})
                import shutil
                shutil.rmtree(root)
                before = path.read_bytes(), image.read_bytes()
                report = session.summary(path, [mapping])
                frame = report['snapshots'][0]['frames'][0]['offline_symbols']
                self.assertEqual(frame['status'], 'source-resolved')
                self.assertEqual([value['symbol'] for value in frame['resolved']['inline_frames']], ['leaf', 'middle', 'outer'])
                self.assertEqual(report['counts'], original['counts'])
                self.assertEqual(report['input_coverage']['history'], 'retained subset')
                self.assertEqual(report['input_coverage']['event_order'], 'sequence')
                self.assertEqual(before, (path.read_bytes(), image.read_bytes()))

    def test_duplicate_fault_views_share_one_ordered_event_and_one_symbol_result(self):
        _, _, mapping, rva, events = self.events()
        fault = dict(kind='exception', pid=1, tid=2, seq=3, code='0xc0000005', first_chance=False,
                     frame=self.fixture.snapshot(rva)['frames'][0])
        events.append(fault)
        _, path, original = self.report(events)
        report = session.summary(path, [mapping])
        fault_view = report['terminal_exceptions'][0]
        self.assertIs(fault_view, next(event for event in report['timeline'] if event['kind'] == 'exception'))
        self.assertEqual(report['input_coverage']['retained_records'], 3)
        self.assertEqual(report['offline_symbolization']['counts'], {'source-resolved': 2})
        self.assertEqual(report['counts'], original['counts'])

    def test_collection_order_is_restored_from_sequence_across_reload(self):
        image, a, map_a, rva_a, events = self.events()
        second, b, map_b, rva_b = self.fixture.image()
        events.extend([dict(kind='module_unload', pid=1, base='0x400000'), self.fixture.load(second, b), self.fixture.snapshot(rva_b)])
        for index, event in enumerate(events, 1):
            event['seq'] = index
        _, path, value = self.report(events)
        value['snapshots'].reverse()
        path.write_text(json.dumps(value))
        report = session.summary(path, [map_a, map_b])
        frames = [event['frames'][0]['offline_symbols'] for event in report['snapshots']]
        self.assertEqual([frame['image_sha256'] for frame in frames], [b['sha256'], a['sha256']])

    def test_missing_sequence_disables_identity_reconstruction_without_artifact_reads(self):
        _, _, mapping, _, events = self.events()
        del events[1]['seq']
        _, path, _ = self.report(events)
        with patch.object(session_symbols, 'file_identity', side_effect=AssertionError('unexpected artifact read')):
            report = session.summary(path, [mapping])
        self.assertEqual(report['input_coverage']['event_order'], 'unverified')
        self.assertEqual(report['snapshots'][0]['frames'][0]['offline_symbols']['reason'], 'retained event order is unavailable')

    def test_omitted_load_history_preserves_declared_counts_and_never_uses_module_basename(self):
        _, _, mapping, _, events = self.events()
        _, path, value = self.report(events)
        value['timeline'] = []
        value['timeline_events_omitted'] = 1
        path.write_text(json.dumps(value))
        report = session.summary(path, [mapping])
        self.assertEqual(report['counts']['module_load'], 1)
        self.assertEqual(report['input_coverage']['timeline_omitted'], 1)
        self.assertEqual(report['snapshots'][0]['frames'][0]['offline_symbols']['status'], 'unavailable')

    def test_redacted_image_alias_requires_recorded_absolute_frame_address(self):
        _, _, mapping, _, events = self.events()
        _, path, value = self.report(events)
        del value['snapshots'][0]['frames'][0]['address']
        path.write_text(json.dumps(value))
        report = session.summary(path, [mapping])
        self.assertEqual(report['snapshots'][0]['frames'][0]['offline_symbols']['status'], 'unavailable')

    def test_live_logs_preserve_stream_order_and_stay_partial_after_finished(self):
        _, _, mapping, _, events = self.events()
        events.append(dict(kind='finished', pid=1, tid=2, seq=3))
        path = self.live(events, completed=True)
        report = session.summary(path, [mapping])
        self.assertFalse(report['manifest']['completed'])
        self.assertEqual(report['input_coverage']['history'], 'live partial')
        self.assertEqual(report['input_coverage']['event_order'], 'stream')
        self.assertEqual(report['snapshots'][0]['frames'][0]['offline_symbols']['status'], 'source-resolved')

    def test_actual_trace_writer_partial_log_is_imported_without_target_execution(self):
        import tracing
        image, _, mapping, _, events = self.events('pdb')
        prefix = self.root / 'prefix'
        prefix.mkdir()
        logs = prefix / 'logs/runs'
        def capture(*arguments, **options):
            for event in events:
                options['observer'](event)
            raise RuntimeError('owned capture setup failure')
        with patch.object(tracing, 'capture', side_effect=capture), self.assertRaises(RuntimeError):
            tracing.trace('unused-host', prefix, logs, [str(image)])
        path = next(logs.glob('*.running.log'))
        before = path.read_bytes()
        report = session.summary(path, [mapping])
        self.assertEqual(report['counts']['capture_error'], 1)
        self.assertEqual(report['snapshots'][0]['frames'][0]['offline_symbols']['status'], 'source-resolved')
        self.assertFalse(report['manifest']['completed'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.read_bytes(), before)

    def test_live_incomplete_tail_and_byte_limit_markers_remain_visible(self):
        _, _, _, _, events = self.events()
        events.append(dict(kind='capture_limit', coverage='partial', byte_limit=16 * 1024 * 1024))
        path = self.live(events, tail=b'{"kind":')
        report = session.summary(path)
        self.assertTrue(report['input_coverage']['incomplete_tail'])
        self.assertTrue(report['input_coverage']['capture_limited'])
        self.assertEqual(report['counts']['capture_limit'], 1)
        malformed = self.live(events)
        with malformed.open('ab') as file:
            file.write(b'not-json\n')
        with self.assertRaisesRegex(ValueError, 'live session event'):
            session.summary(malformed)

    def test_invalid_reports_and_conflicting_duplicate_sequences_fail_before_export(self):
        _, _, _, _, events = self.events()
        _, _, original = self.report(events)
        bad = []
        for field, value in [('manifest', []), ('counts', {'snapshot': True}), ('snapshots', {}),
                             ('timeline_events_omitted', -1), ('unknown-field', 'unsupported')]:
            value_report = copy.deepcopy(original)
            value_report[field] = value
            bad.append(value_report)
        conflict = copy.deepcopy(original)
        conflict['snapshots'][0]['seq'] = conflict['timeline'][0]['seq']
        bad.append(conflict)
        for index, value in enumerate(bad):
            path = self.root / ('bad-' + str(index) + '.log')
            path.write_text(json.dumps(value))
            destination = self.root / ('bad-export-' + str(index) + '.json')
            with self.subTest(index=index), self.assertRaises(ValueError):
                session.export(path, destination)
            self.assertFalse(destination.exists())

    def test_import_and_reexport_remove_memory_and_dump_blobs_keep_metadata_and_review(self):
        _, _, _, _, events = self.events()
        _, path, value = self.report(events)
        value['timeline'].append(dict(kind='memory', pid=1, seq=3, data='PRIVATE_MEMORY'))
        dump = dict(kind='dump', pid=1, tid=2, seq=4, path='/private/fixture.dmp', size=512, data='PRIVATE_DUMP')
        value['timeline'].append(dump)
        value['dumps'] = [copy.deepcopy(dump)]
        path.write_text(json.dumps(value))
        report = session.summary(path)
        self.assertEqual(report['input_coverage']['memory_records_excluded'], 1)
        self.assertNotIn('PRIVATE_', json.dumps(report))
        destination = self.root / 'reviewed.json'
        exported = session.export(path, destination)
        self.assertNotIn('/private/', json.dumps(exported))
        self.assertNotIn('PRIVATE_', destination.read_text())
        self.assertEqual(exported['dumps'][0]['size'], 512)
        self.assertTrue(exported['export']['review_required'])
        self.assertFalse(exported['export']['memory_and_dumps_included'])
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_regular_file_size_bounds_and_full_bundle_comparison_requirement(self):
        _, _, _, _, events = self.events()
        root, path, _ = self.report(events)
        with self.assertRaisesRegex(ValueError, 'complete session bundles'):
            session.compare(root, path)
        self.assertEqual(session.compare(root, root)['added'], [])
        oversized = self.root / 'oversized.log'
        with oversized.open('wb') as file:
            file.truncate(session_reports.MAX_REPORT + 1)
        with self.assertRaisesRegex(ValueError, '32 MiB'):
            session.summary(oversized)
        pipe = self.root / 'report-pipe'
        os.mkfifo(pipe)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            session.summary(pipe)

    def test_actual_cli_stdio_inspect_enrich_export_and_invalid_input_recovery(self):
        _, _, mapping, _, events = self.events('pdb')
        _, path, _ = self.report(events)
        config = self.root / 'images.json'
        config.write_text(json.dumps([mapping]))
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        cli = subprocess.run([*command, 'inspect', str(path), '--symbol-images', str(config)], capture_output=True, text=True, timeout=30)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        expected = json.loads(cli.stdout)['data']
        bad = self.root / 'invalid.log'
        bad.write_text('{}')
        destination = self.root / 'backend-export.json'
        requests = [(1, 'initialize', {'schema': 1}), (2, 'inspect', {'session': str(path), 'symbol_images': [mapping]}),
                    (3, 'inspect', {'session': str(bad)}),
                    (4, 'export', {'session': str(path), 'output': str(destination), 'symbol_images': [mapping]}),
                    (5, 'inspect', {'session': str(path), 'symbol_images': [mapping]}), (6, 'shutdown', {})]
        stream = io.BytesIO()
        for i, method, params in requests:
            write_message(stream, dict(id=i, method=method, params=params))
        result = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        stream = io.BytesIO(result.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertEqual(replies[1]['result'], expected)
        self.assertEqual(replies[2]['error']['code'], -32602)
        self.assertTrue(replies[3]['result']['export']['review_required'])
        self.assertEqual(replies[4]['result'], expected)
        self.assertNotIn(str(self.root), destination.read_text())



if __name__ == '__main__':
    unittest.main()
