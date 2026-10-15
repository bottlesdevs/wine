import json
import hashlib
import platform
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from identity_stages import decode
from session import export, fingerprint


class IdentityStages(unittest.TestCase):
    def runner(self, root):
        architectures = ('aarch64',) if platform.machine() == 'aarch64' else ('i386', 'x86_64')
        for architecture in architectures:
            directory = root / f'lib/wine/{architecture}-windows';directory.mkdir(parents=True)
            for module in ('combase', 'dwrite', 'kernelbase', 'windows.security.authentication.onlineid'):
                (directory / (module + '.dll')).write_bytes(b'EAGLE/1 identity.stage identity.native.stage')
        return architectures

    def test_installer_rejects_missing_identity_instrumentation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);architectures = self.runner(root)
            (root / f'lib/wine/{architectures[0]}-windows/windows.security.authentication.onlineid.dll').write_bytes(b'EAGLE/1')
            result = subprocess.run([sys.executable, '-S', str(Path(__file__).resolve().parents[1] / 'install.py'), str(root)],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'share/eagle/providers.json').exists())

    def test_installer_records_identity_scope_and_module_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);architectures = self.runner(root)
            result = subprocess.run([sys.executable, '-S', str(Path(__file__).resolve().parents[1] / 'install.py'), str(root)],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((root / 'share/eagle/providers.json').read_text())
            self.assertEqual(data['identity_stages'], {'schema': 1, 'provider': 1, 'transports': ['host-bridge', 'native'], 'native_flow': True})
            for architecture in architectures:
                name = f'{architecture}/windows.security.authentication.onlineid'
                self.assertEqual(data['provider_sha256'][name], hashlib.sha256(b'EAGLE/1 identity.stage identity.native.stage').hexdigest())

    def payload(self):
        return dict(provider=1, event='identity.stage', hresult='0x8000000a', a=2, b=1,
                    c=77, d=1, subject='', iid='', caller='0000000140001234')

    def test_operations_and_stages_have_fixed_names(self):
        for operation, name in ((2, 'authorize'), (3, 'get_token'), (5, 'list_accounts')):
            for stage, label in ((1, 'begin'), (2, 'transport'), (3, 'response'), (4, 'complete')):
                value = self.payload();value.update(a=operation, d=stage)
                data = decode(value)
                self.assertEqual(data['operation'], name)
                self.assertEqual(data['stage'], label)
                self.assertEqual(data['request_id'], 77)
                self.assertEqual(data['transport'], 'host-bridge')
                self.assertNotIn('subject', data)
                self.assertNotIn('iid', data)

    def test_native_stages_are_distinct_and_have_fixed_names(self):
        for operation in (2, 3, 5):
            for stage, name in ((1, 'begin'), (3, 'response'), (4, 'complete'), (5, 'cache'),
                                (6, 'request'), (7, 'prompt'), (8, 'persist')):
                value = self.payload();value.update(event='identity.native.stage', a=operation, b=2, d=stage)
                data = decode(value)
                self.assertEqual(data['transport'], 'native')
                self.assertEqual(data['stage'], name)
                self.assertEqual(data['event'], 'identity.stage')
                self.assertNotEqual(fingerprint({'kind': 'provider', 'data': data}), fingerprint({'kind': 'provider', 'data': dict(data, transport='host-bridge')}))
        for changes in ({'b': 1}, {'d': 2}, {'d': 9}, {'subject': 'private-sentinel'}, {'token': 'private-sentinel'}):
            value = self.payload();value.update(event='identity.native.stage', b=2);value.update(changes)
            with self.assertRaises(ValueError):decode(value)

    def test_installer_rejects_bridge_only_onlineid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);architectures = self.runner(root)
            (root / f'lib/wine/{architectures[0]}-windows/windows.security.authentication.onlineid.dll').write_bytes(b'EAGLE/1 identity.stage')
            result = subprocess.run([sys.executable, '-S', str(Path(__file__).resolve().parents[1] / 'install.py'), str(root)],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'share/eagle/providers.json').exists())

    def test_account_and_token_fields_are_rejected_without_echo(self):
        for field in ('access_token', 'account_id', 'client_id', 'authority', 'payload', 'code'):
            value = self.payload();value[field] = 'private-sentinel'
            with self.assertRaises(ValueError) as result:
                decode(value)
            self.assertNotIn('private-sentinel', str(result.exception))
        for field in ('subject', 'iid'):
            value = self.payload();value[field] = 'private-sentinel'
            with self.assertRaises(ValueError):decode(value)

    def test_scalar_bounds_and_types_are_checked(self):
        for field, values in {'a': [0, 1, 4, True], 'b': [0, 2, True],
                              'c': [0, -1, 0x100000000, True, '77'], 'd': [0, 5, True],
                              'provider': [True, 2], 'event': ['other'],
                              'hresult': [None, '0x1', '0x123456789'],
                              'caller': [None, 'account@example.test', 'x' * 100]}.items():
            for invalid in values:
                with self.subTest(field=field, value=invalid):
                    value = self.payload();value[field] = invalid
                    with self.assertRaises(ValueError):decode(value)
        value = self.payload();value['c'] = 0xffffffff
        self.assertEqual(decode(value)['request_id'], 0xffffffff)

    def test_request_numbers_do_not_create_comparison_changes(self):
        a = {'kind': 'provider', 'data': decode(self.payload())}
        b = {'kind': 'provider', 'data': dict(a['data'], request_id=12)}
        self.assertEqual(fingerprint(a), fingerprint(b))
        b['data']['stage'] = 'complete'
        self.assertNotEqual(fingerprint(a), fingerprint(b))
        a['data']['event'] = b['data']['event'] = 'other'
        b['data']['stage'] = a['data']['stage']
        self.assertNotEqual(fingerprint(a), fingerprint(b))

    def test_export_keeps_stage_correlation_and_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'session';root.mkdir()
            (root / 'manifest.json').write_text(json.dumps({'schema': 1, 'completed': True}))
            rows = []
            for stage in range(1, 5):
                value = self.payload();value.update(d=stage, hresult='0x80070005' if stage == 4 else '0x00000000')
                rows.append({'seq': stage, 'kind': 'provider', 'pid': 10, 'tid': 11, 'data': decode(value)})
            (root / 'events.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            output = Path(directory) / 'export.log';export(root, output)
            report = json.loads(output.read_text())
            self.assertEqual([x['data']['stage'] for x in report['providers']], ['begin', 'transport', 'response', 'complete'])
            self.assertTrue(all(x['data']['request_id'] == 77 for x in report['providers']))
            self.assertEqual(report['providers'][-1]['data']['hresult'], '0x80070005')


if __name__ == '__main__':
    unittest.main()
