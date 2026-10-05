import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(os.environ['EAGLE_COM_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
sys.path.insert(0, str(CANDIDATE / 'lib/eagle'))
from session import windows_path


class ComProvider(unittest.TestCase):
    def capture(self, profile, name, extra=()):
        bundle = ROOT / name
        marker = ROOT / (name + '.last-error')
        command = [str(CANDIDATE / 'bin/eagle'), 'run', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile, '--timeout', '120', *extra, str(ROOT / 'target.exe'), windows_path(marker)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=140)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        events = [json.loads(line) for line in (bundle / 'events.jsonl').read_text().splitlines()]
        if profile == 'com':
            providers = [item for item in events if item['kind'] == 'provider']
            self.assertTrue(providers)
            self.assertTrue(all(int(item['frame']['address'], 16) == int(item['data']['caller'], 16) for item in providers))
            self.assertTrue(any(item['frame'].get('symbol') == 'main' and item['frame'].get('line', 0) > 0 for item in providers))
        self.assertEqual(next(item['code'] for item in events if item['kind'] == 'process_exit'), 0)
        self.assertEqual(len(marker.read_bytes()), 4)
        manifest = json.loads((bundle / 'manifest.json').read_text())
        self.assertTrue(manifest['completed'])
        self.assertEqual(manifest['dropped_events'], 0)
        return events, marker.read_bytes()

    def test_activation_apartment_qi_and_last_error_controls(self):
        for attempt in range(3):
            off, baseline = self.capture('crash', f'off-{attempt}')
            self.assertFalse(any(item['kind'] == 'provider' for item in off))
            events, observed = self.capture('com', f'on-{attempt}')
            self.assertEqual(observed, baseline)
            values = [item['data'] for item in events if item['kind'] == 'provider']
            self.assertTrue(values)
            self.assertTrue(all(item['provider'] == 4 for item in values))
            init = [item for item in values if item['event'] == 'CoInitializeEx']
            self.assertEqual(init[0]['hresult'], '0x00000000')
            self.assertEqual(init[0]['model_requested'], 0)
            self.assertTrue(any(item['model_requested'] == 2 and item['hresult'] == '0x80010106' for item in init))
            missing = next(item for item in values if item['event'] == 'CoGetClassObject' and item['clsid'] == 'c0decafe-1234-4321-8001-000102030405')
            self.assertEqual(missing['hresult'], '0x80040111')
            self.assertEqual(missing['iid'], '00000001-0000-0000-c000-000000000046')
            activation = next(item for item in values if item['event'] == 'CoCreateInstanceEx')
            self.assertEqual(activation['hresult'], '0x00000000')
            self.assertEqual(activation['clsid'], '00000323-0000-0000-c000-000000000046')
            self.assertEqual(activation['count'], 2)
            self.assertNotEqual(int(activation['object'], 16), 0)
            query = next(item for item in values if item['event'] == 'ActivationQueryInterface')
            self.assertEqual(query['hresult'], '0x00000000')
            self.assertEqual(query['iid'], '00000146-0000-0000-c000-000000000046')
            self.assertEqual(init[0]['apartment_requested'], 'MTA')
            partial = next(item for item in values if item['event'] == 'CoCreateInstanceEx' and item['count'] == 3)
            self.assertEqual(partial['hresult'], '0x00080012')
            rejected = next(item for item in values if item['event'] == 'ActivationQueryInterface' and item['hresult'] == '0x80004002')
            self.assertEqual(rejected['interface_index'], 2)
            self.assertEqual(rejected['scope'], 'activation only')
            self.assertEqual(rejected['iid'], 'c0decafe-1234-4321-8001-000102030405')
            self.assertEqual(query['object'], activation['object'])
            self.assertEqual(query['interface_index'], 1)
            self.assertTrue(any(item['event'] == 'CoUninitialize' and item['initialization_depth'] == 1 for item in values))
        events, _ = self.capture('com', 'trigger-dump', ['--on-hresult', '0x80040111', '--trigger-action', 'dump'])
        trigger = next(item for item in events if item['kind'] == 'trigger')
        self.assertTrue(any(item['kind'] == 'snapshot' and item['seq'] > trigger['seq'] for item in events))
        dump = next(item for item in events if item['kind'] == 'dump')
        self.assertEqual((ROOT / 'trigger-dump/dumps' / dump['path']).read_bytes()[:4], b'MDMP')


if __name__ == '__main__':
    unittest.main(verbosity=2)
