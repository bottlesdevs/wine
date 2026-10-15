import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
sys.path.insert(0, str(PACKAGE))
from session import compare, export, read_bundle, summary
from protocol import read_message, write_message


class SessionComparison(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.manifest = dict(schema=1, target_identity={'sha256': 'a' * 64},
                             arguments=[], profile='trace', trigger=None, interactive=False)

    def bundle(self, name, events, **changes):
        root = self.root / name
        root.mkdir()
        (root / 'manifest.json').write_text(json.dumps(dict(self.manifest, **changes)))
        (root / 'events.jsonl').write_text(''.join(json.dumps(event) + '\n' for event in events))
        return root

    def provider(self, **changes):
        data = dict(provider=4, event='CoCreateInstanceEx', hresult='0x00000000',
                    clsid='fixture-class', iid='fixture-interface', object='0x1000', caller='0x2000')
        data.update(changes)
        return dict(kind='provider', pid=1, tid=2, seq=3, time_ms=4, data=data,
                    frame={'module': 'fixture.dll', 'rva': '0x120'})

    def snapshot(self):
        return dict(kind='snapshot', pid=1, tid=2, seq=3, time_ms=4,
                    registers={'ip': '0x401120', 'sp': '0x7000'}, unwind='dbghelp', truncated=False,
                    frames=[{'module': 'fixture', 'rva': '0x120', 'address': '0x401120'},
                            {'module': 'caller', 'rva': '0x220', 'address': '0x501220'}])

    def test_stack_callers_order_depth_and_unwind_quality_change_comparison(self):
        original = self.snapshot()
        baseline = self.bundle('baseline', [original, original])
        changes = []
        for field, value in [('module', 'other'), ('rva', '0x330')]:
            event = copy.deepcopy(original)
            event['frames'][1][field] = value
            changes.append(event)
        event = copy.deepcopy(original)
        event['frames'].reverse()
        changes.append(event)
        event = copy.deepcopy(original)
        event['frames'].pop()
        changes.append(event)
        for field, value in [('truncated', True), ('unwind', 'other-engine')]:
            event = copy.deepcopy(original)
            event[field] = value
            changes.append(event)
        for index, event in enumerate(changes):
            with self.subTest(change=index):
                candidate = self.bundle('candidate-' + str(index), [original, event])
                result = compare(baseline, candidate)
                self.assertTrue(result['matching_inputs'])
                self.assertEqual([item['count'] for item in result['added']], [1])
                self.assertEqual([item['count'] for item in result['removed']], [1])

    def test_stack_aslr_symbols_paths_and_numeric_rva_spelling_do_not_change_comparison(self):
        original = self.snapshot()
        changed = copy.deepcopy(original)
        changed.update(pid=10, tid=20, seq=30, time_ms=40, registers={'ip': '0x801120', 'sp': '0x9000'})
        changed['frames'][0].update(rva=288, address='0x801120', symbol='resolved-name', file='/reviewed/fixture.c', line=7)
        changed['frames'][1].update(rva='0X00000220', address='0x901220', image='/other/caller.dll')
        baseline = self.bundle('baseline', [original])
        candidate = self.bundle('candidate', [changed])
        result = compare(baseline, candidate)
        self.assertEqual(result['added'], [])
        self.assertEqual(result['removed'], [])
        original = self.provider()
        changed = copy.deepcopy(original)
        changed['frame']['rva'] = 288
        self.assertEqual(compare(self.bundle('provider-a', [original]), self.bundle('provider-b', [changed]))['added'], [])

    def test_invalid_stacks_and_rvas_fail_before_export_creation(self):
        events = []
        for value in [None, {}, [None], [42], [{'module': []}], [{'rva': True}],
                      [{'rva': -1}], [{'rva': 'not-an-address'}], [{'rva': 1 << 64}], [{}] * 4097]:
            event = self.snapshot()
            event['frames'] = value
            events.append(event)
        for field, value in [('unwind', []), ('truncated', 1)]:
            event = self.snapshot()
            event[field] = value
            events.append(event)
        for rva in [False, -1, 'bad-rva', 1 << 64, '0x' + '0' * 40]:
            events.append(dict(kind='fixture', frame={'module': 'fixture', 'rva': rva}))
        for index, event in enumerate(events):
            with self.subTest(case=index):
                root = self.bundle('bad-' + str(index), [event])
                destination = self.root / ('bad-export-' + str(index) + '.json')
                with self.assertRaisesRegex(ValueError, 'line 1'):
                    summary(root)
                with self.assertRaises(ValueError):
                    export(root, destination)
                self.assertFalse(destination.exists())

    def test_partial_stacks_remain_readable_without_mutating_saved_events(self):
        maximum = self.bundle('maximum-stack', [dict(kind='snapshot', frames=[{}] * 4096)])
        self.assertEqual(len(read_bundle(maximum)[1][0]['frames']), 4096)
        events = [dict(kind='snapshot', frames=[]), dict(kind='snapshot', frames=[{}, {'module': None, 'rva': None}]),
                  dict(kind='fixture', frame=None), dict(kind='snapshot')]
        root = self.bundle('partial-stacks', events)
        original = (root / 'events.jsonl').read_bytes()
        self.assertEqual(read_bundle(root)[1], events)
        self.assertEqual(summary(root)['snapshots'], [events[0], events[1], events[3]])
        self.assertEqual(compare(root, root)['added'], [])
        self.assertTrue(export(root, self.root / 'partial-stacks.json')['export']['review_required'])
        self.assertEqual((root / 'events.jsonl').read_bytes(), original)
        result = compare(self.bundle('unknown-a', [events[0]]), self.bundle('unknown-b', [events[3]]))
        self.assertEqual(len(result['added']), 1)

    def test_provider_payload_and_stack_changes_are_both_retained(self):
        original = self.provider()
        original['frames'] = self.snapshot()['frames']
        changed = copy.deepcopy(original)
        changed['data']['hresult'] = '0x80040111'
        baseline = self.bundle('baseline', [original])
        candidate = self.bundle('candidate', [changed])
        result = compare(baseline, candidate)
        self.assertEqual(len(result['added']), 1)
        self.assertEqual(result['added'][0]['fingerprint'][6][0], 'stack')
        self.assertIn('0x80040111', result['added'][0]['fingerprint'][7])

    def test_cli_stdio_stack_comparison_and_invalid_stack_recovery(self):
        original = self.snapshot()
        changed = copy.deepcopy(original)
        changed['frames'][1]['rva'] = '0x330'
        baseline = self.bundle('baseline', [original])
        candidate = self.bundle('candidate', [changed])
        invalid = self.bundle('invalid', [dict(kind='snapshot', frames=[42])])
        expected = json.loads(json.dumps(compare(baseline, candidate)))
        cli = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'compare', str(baseline), str(candidate)],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(json.loads(cli.stdout)['data'], expected)
        destination = self.root / 'invalid-stack-export.json'
        requests = [(1, 'initialize', {'schema': 1}), (2, 'compare', {'baseline': str(baseline), 'candidate': str(candidate)}),
                    (3, 'inspect', {'session': str(invalid)}), (4, 'export', {'session': str(invalid), 'output': str(destination)}),
                    (5, 'compare', {'baseline': str(baseline), 'candidate': str(candidate)}), (6, 'shutdown', {})]
        stream = io.BytesIO()
        for i, method, params in requests:
            write_message(stream, dict(id=i, method=method, params=params))
        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'serve'], input=stream.getvalue(), capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        stream = io.BytesIO(result.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertEqual(replies[1]['result'], expected)
        self.assertEqual(replies[2]['error']['code'], -32602)
        self.assertEqual(replies[3]['error']['code'], -32602)
        self.assertEqual(replies[4]['result'], expected)
        self.assertFalse(destination.exists())

    def test_provider_changes_are_reported(self):
        baseline = self.bundle('baseline', [self.provider()])
        for field, value in [('provider', 1), ('event', 'CoGetClassObject'),
                             ('hresult', '0x80040111'), ('clsid', 'other-class'),
                             ('iid', 'other-interface')]:
            with self.subTest(field=field):
                candidate = self.bundle(field, [self.provider(**{field: value})])
                result = compare(baseline, candidate)
                self.assertTrue(result['matching_inputs'])
                self.assertEqual([item['count'] for item in result['added']], [1])
                self.assertEqual([item['count'] for item in result['removed']], [1])

    def test_provider_addresses_and_event_times_do_not_change_counts(self):
        original = self.provider()
        changed = self.provider(object='0x3000', caller='0x4000')
        changed.update(pid=10, tid=20, seq=30, time_ms=40)
        changed['data'] = dict(reversed(list(changed['data'].items())))
        baseline = self.bundle('baseline', [original])
        candidate = self.bundle('candidate', [changed])

        result = compare(baseline, candidate)
        self.assertEqual(result['added'], [])
        self.assertEqual(result['removed'], [])

    def test_wait_and_glyph_outcomes_remain_distinct(self):
        for provider, data, change in [
            (8, dict(event='WaitEnd', value=0, timeout_ms=100), dict(value=258)),
            (2, dict(event='CreateAlphaTexture', width=20, height=10), dict(width=21)),
        ]:
            with self.subTest(provider=provider):
                original = self.provider(provider=provider, **data)
                changed = copy.deepcopy(original)
                changed['data'].update(change)
                baseline = self.bundle(str(provider) + '-baseline', [original])
                candidate = self.bundle(str(provider) + '-candidate', [changed])
                result = compare(baseline, candidate)
                self.assertEqual(len(result['added']), 1)
                self.assertEqual(len(result['removed']), 1)

    def test_explicit_working_directory_is_part_of_the_input(self):
        baseline = self.bundle('baseline', [], target_cwd='/fixture/first')
        candidate = self.bundle('candidate', [], target_cwd='/fixture/second')
        self.assertFalse(compare(baseline, candidate)['matching_inputs'])

    def test_changed_input_and_observer_settings_are_inconclusive(self):
        baseline = self.bundle('baseline', [])
        changes = dict(target_identity={'sha256': 'b' * 64}, arguments=['--other'],
                       profile='crash', trigger={'hresult': '0x80040111', 'action': 'dump'},
                       interactive=True)
        for field, value in changes.items():
            with self.subTest(field=field):
                candidate = self.bundle(field, [], **{field: value})
                result = compare(baseline, candidate)
                self.assertFalse(result['matching_inputs'])
                self.assertTrue(result['verdict'].startswith('inconclusive'))

    def test_nonprovider_fingerprints_keep_existing_counts(self):
        original = dict(kind='process_exit', pid=1, code=0)
        changed = dict(kind='process_exit', pid=99, code=1)
        baseline = self.bundle('baseline', [original, original])
        candidate = self.bundle('candidate', [original, changed])
        result = compare(baseline, candidate)
        self.assertEqual([item['count'] for item in result['added']], [1])
        self.assertEqual([item['count'] for item in result['removed']], [1])
        self.assertEqual(len(result['added'][0]['fingerprint']), 6)

    def test_cli_preserves_provider_comparison(self):
        baseline = self.bundle('baseline', [self.provider()])
        candidate = self.bundle('candidate', [self.provider(hresult='0x80040111')])
        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'),
                                 'compare', str(baseline), str(candidate)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['data'], compare(baseline, candidate))
        self.assertEqual(len(json.loads(result.stdout)['data']['added']), 1)


    def test_manifest_containers_and_versions_are_rejected(self):
        for index, manifest in enumerate([[], None, 1, "fixture", {"schema": True}, {"schema": 999}]):
            with self.subTest(manifest=manifest):
                root = self.bundle('manifest-' + str(index), [])
                (root / 'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    read_bundle(root)

    def test_invalid_module_inventories_are_rejected(self):
        for index, value in enumerate([[], None, {'module': None}, {'module': {}}, {'module': {'sha256': []}}]):
            for name in ['modules', 'unix_modules']:
                with self.subTest(name=name, value=value):
                    root = self.bundle(name + str(index), [], **{name: value})
                    with self.assertRaises(ValueError):
                        read_bundle(root)

    def test_invalid_event_structures_are_rejected(self):
        records = [[], None, "fixture", {}, {'kind': []}, {'kind': 'process_exit'},
                   {'kind': 'exception'}, {'kind': 'exception', 'first_chance': 1},
                   {'kind': 'provider', 'data': []}, {'kind': 'provider', 'data': None},
                   {'kind': 'provider', 'data': {'provider': []}},
                   {'kind': 'fixture', 'frame': []}, {'kind': 'fixture', 'frame': {'module': []}},
                   {'kind': 'fixture', 'frame': {'rva': []}}, {'kind': 'fixture', 'path': []},
                   {'kind': 'fixture', 'code': []},
                   {'kind': 'provider', 'data': {}, 'wait_graph': []}]
        for index, event in enumerate(records):
            with self.subTest(event=event):
                root = self.bundle('event-' + str(index), [event])
                with self.assertRaises(ValueError):
                    read_bundle(root)

    def test_partial_sessions_keep_optional_records(self):
        events = [{'kind': 'fixture', 'frame': None}, {'kind': 'memory', 'data': 'own fixture'},
                  {'kind': 'provider', 'data': {}}, {'kind': 'exception', 'first_chance': True},
                  {'kind': 'process_exit', 'pid': 1, 'code': 0}]
        root = self.bundle('partial', events)
        (root / 'manifest.json').write_text('{"schema":1}')
        manifest, parsed = read_bundle(root)
        self.assertEqual(manifest, {'schema': 1})
        self.assertEqual(parsed, events)
        self.assertEqual(summary(root)['counts']['fixture'], 1)
        self.assertTrue(export(root, self.root / 'partial.json')['export']['review_required'])

    def test_cli_returns_structured_errors_without_creating_exports(self):
        valid = self.bundle('valid', [])
        bad_manifest = self.bundle('bad-manifest', [])
        (bad_manifest / 'manifest.json').write_text('[]')
        bad_event = self.bundle('bad-event', [{'kind': 'process_exit'}])
        bad_inventory = self.bundle('bad-inventory', [], modules={'module': {}})
        for index, root in enumerate([bad_manifest, bad_event, bad_inventory]):
            destination = self.root / ('export-' + str(index) + '.json')
            for args in [('inspect', str(root)), ('compare', str(valid), str(root)),
                         ('export', str(root), str(destination))]:
                with self.subTest(arguments=args):
                    result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), *args],
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, '')
                    self.assertFalse(json.loads(result.stderr)['status'])
                    self.assertNotIn('Traceback', result.stderr)
                    self.assertFalse(destination.exists())

    def test_nested_module_maps_fail_before_export_creation(self):
        root = self.bundle('nested-module-map', [{'kind': 'fixture', 'data': {'modules': []}}])
        destination = self.root / 'nested-export.json'
        with self.assertRaises(ValueError):
            export(root, destination)
        self.assertFalse(destination.exists())

    def test_stdio_keeps_serving_after_invalid_sessions(self):
        valid = self.bundle('valid', [])
        bad_manifest = self.bundle('bad-manifest', [])
        (bad_manifest / 'manifest.json').write_text('[]')
        bad_event = self.bundle('bad-event', [None])
        bad_inventory = self.bundle('bad-inventory', [], metadata={'modules': []})
        destination = self.root / 'invalid-export.json'
        requests = [(1, 'initialize', {'schema': 1}),
                    (2, 'inspect', {'session': str(bad_manifest)}),
                    (3, 'compare', {'baseline': str(valid), 'candidate': str(bad_event)}),
                    (4, 'export', {'session': str(bad_inventory), 'output': str(destination)}),
                    (5, 'capabilities', {}), (6, 'inspect', {'session': str(valid)}),
                    (7, 'shutdown', {})]
        stream = io.BytesIO()
        for request_id, method, params in requests:
            write_message(stream, dict(id=request_id, method=method, params=params))
        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'serve'],
                                input=stream.getvalue(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        messages = io.BytesIO(result.stdout)
        responses = [read_message(messages) for _ in requests]
        self.assertEqual([item['id'] for item in responses], list(range(1, 8)))
        for item in responses[1:4]:
            self.assertEqual(item['error']['code'], -32602)
        self.assertEqual(responses[4]['result']['schema'], 1)
        self.assertEqual(responses[5]['result']['counts'], {})
        self.assertIsNone(responses[6]['result'])
        self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
