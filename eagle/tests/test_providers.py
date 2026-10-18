import json
import os
from pathlib import Path
import statistics
import subprocess
import time
import unittest

ROOT = Path(os.environ['EAGLE_PROVIDER_TEST_ROOT'])
CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
CLI = CANDIDATE / 'bin/eagle'
BITS = int(os.environ.get('EAGLE_PROVIDER_BITS', '64'))


class Providers(unittest.TestCase):
    def run_profile(self, profile, name, extra=()):
        bundle = ROOT / name
        command = [str(CLI), 'run', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(ROOT / 'prefix'), '--session', str(bundle), '--profile', profile, '--timeout', '120', *extra, str(ROOT / f'provider{BITS}.exe')]
        start = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=140)
        elapsed = time.monotonic() - start
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        events = [json.loads(line) for line in (bundle / 'events.jsonl').read_text().splitlines()]
        self.assertEqual(next(item['code'] for item in events if item['kind'] == 'process_exit'), 0)
        manifest = json.loads((bundle / 'manifest.json').read_text())
        self.assertTrue(manifest['completed'])
        self.assertEqual(manifest['dropped_events'], 0)
        return events, elapsed

    def test_observer_off_on_controls_and_hresult_trigger(self):
        measurements = {'off': [], 'winrt': [], 'dwrite': []}
        for attempt in range(3):
            events, elapsed = self.run_profile('crash', f'off-{attempt}')
            self.assertFalse(any(item['kind'] == 'provider' for item in events))
            measurements['off'].append(elapsed)
            for profile in ('winrt', 'dwrite'):
                events, elapsed = self.run_profile(profile, f'{profile}-{attempt}')
                measurements[profile].append(elapsed)
                providers = [item for item in events if item['kind'] == 'provider']
                self.assertTrue(all(int(item['frame']['address'], 16) == int(item['data']['caller'], 16) for item in providers))
                self.assertTrue(any(item['frame'].get('symbol') == 'main' and item['frame'].get('line', 0) > 0 for item in providers))
                captured = [item['data'] for item in providers]
                self.assertTrue(captured)
                if profile == 'winrt':
                    self.assertEqual(captured[0]['hresult'], '0x80040154')
                    self.assertEqual(captured[0]['class'], 'Windows.Eagle.Nonexistent')
                    self.assertEqual(captured[0]['iid'], '00000035-0000-0000-c000-000000000046')
                else:
                    self.assertEqual(captured[0]['hresult'], '0x8007007a')
                    self.assertGreater(captured[0]['width'], 0)
                    self.assertGreater(captured[0]['height'], 0)
                    self.assertEqual(captured[0]['buffer_bytes'], 1)
        events, _ = self.run_profile('dwrite', 'trigger-dump', ['--on-hresult', '0x8007007a', '--trigger-action', 'dump'])
        trigger = next(item for item in events if item['kind'] == 'trigger')
        self.assertTrue(any(item['kind'] == 'snapshot' and item['seq'] > trigger['seq'] for item in events))
        dump = next(item for item in events if item['kind'] == 'dump')
        self.assertEqual((ROOT / 'trigger-dump/dumps' / dump['path']).read_bytes()[:4], b'MDMP')
        measurements['median_seconds'] = {key: statistics.median(value) for key, value in measurements.items()}
        measurements['scope'] = 'Complete debug capture wall time; three interleaved repetitions, not provider CPU overhead'
        (ROOT / 'observer-measurements.json').write_text(json.dumps(measurements, indent=2) + '\n')


if __name__ == '__main__':
    unittest.main()
