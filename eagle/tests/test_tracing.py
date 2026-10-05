import json
import os
from pathlib import Path
import subprocess
import unittest
import time
import shutil

CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
ROOT = Path(os.environ['EAGLE_TRACE_TEST_ROOT'])


class Tracing(unittest.TestCase):
    def test_running_log_is_available_before_application_exit(self):
        prefix = (ROOT / 'prefix').resolve()
        logs = prefix / 'logs/runs'
        before = set(logs.glob('*.running.log'))
        command = [str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(logs), '--', str(ROOT / 'target64.exe'), 'tracewait']
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            try:
                deadline = time.monotonic() + 30
                found = None
                while time.monotonic() < deadline:
                    created = set(logs.glob('*.running.log')) - before
                    if created:
                        found = created.pop()
                        try:
                            records = [json.loads(line) for line in found.read_text().splitlines()]
                        except (ValueError, FileNotFoundError):
                            records = []
                        if any(item.get('kind') == 'process_create' for item in records):
                            break
                    time.sleep(0.05)
                self.assertIsNotNone(found)
                self.assertIsNone(process.poll(), 'target must still be running when its log is readable')
                self.assertTrue(any(item.get('kind') == 'process_create' for item in records))
                self.assertTrue(records[0]['review_required'])
                self.assertFalse(records[0]['completed'])
                self.assertEqual(found.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(str(ROOT), found.read_text())
                output, error = process.communicate(timeout=40)
                self.assertEqual(process.returncode, 0, error)
                self.assertFalse(found.exists())
                final = json.loads(Path(json.loads(output)['data']['log']).read_text())
                self.assertTrue(final['manifest']['completed'])
                self.assertTrue(any(item['kind'] == 'process_create' for item in final['timeline']))
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)

    def test_automatic_logs_arguments_cwd_children_and_exit_status(self):
        prefix = (ROOT / 'prefix').resolve()
        logs = prefix / 'logs/runs'
        logs.mkdir(parents=True, exist_ok=True)
        for bits in ('32', '64'):
            for mode, code in [('exit', 7), ('child', 0), ('marker', 0)]:
                before = set(logs.glob('*.log'))
                arguments = [str(ROOT / ('target' + bits + '.exe')), mode]
                if mode == 'marker':
                    arguments.append('cwd-marker-' + bits)
                result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(logs), '--cwd', str(ROOT), '--', *arguments], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, code, result.stderr[-4000:])
                response = json.loads(result.stdout)
                self.assertTrue(response['status'])
                created = set(logs.glob('*.log')) - before
                self.assertEqual(len(created), 1)
                path = created.pop()
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                report = json.loads(path.read_text())
                self.assertTrue(report['manifest']['completed'])
                self.assertTrue(report['export']['review_required'])
                self.assertFalse(report['export']['memory_and_dumps_included'])
                self.assertEqual(report['manifest']['arguments'], '[redacted]')
                self.assertEqual(report['manifest']['target_cwd'], '[redacted]')
                self.assertNotIn(str(ROOT), path.read_text())
                if mode == 'child':
                    self.assertEqual(report['counts']['process_create'], 2)
                    self.assertEqual(sorted(item['code'] for item in report['exits']), [0, 7])
                if mode == 'marker':
                    self.assertEqual((ROOT / ('cwd-marker-' + bits)).read_text(), 'alive')

    def test_windows_path_and_builtin_starter(self):
        prefix = (ROOT / 'prefix').resolve()
        logs = prefix / 'logs/runs'
        target = 'Z:' + str(ROOT / 'target64.exe').replace('/', '\\')
        for arguments in ([target, 'exit'], ['start', '/wait', target, 'exit']):
            result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(logs), '--', *arguments], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 7, result.stderr[-4000:])
            report = json.loads(Path(json.loads(result.stdout)['data']['log']).read_text())
            self.assertTrue(report['manifest']['completed'])
            if arguments[0] == 'start':
                self.assertTrue(any(item['kind'] == 'process_excluded' and item['reason'] == 'Wine console host outside application tracing scope' for item in report['timeline']))

    def test_application_named_conhost_is_still_traced(self):
        prefix = (ROOT / 'prefix').resolve()
        target = ROOT / 'conhost.exe'
        shutil.copy2(ROOT / 'target64.exe', target)
        result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(prefix / 'logs/runs'), '--', str(target), 'child'], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        report = json.loads(Path(json.loads(result.stdout)['data']['log']).read_text())
        self.assertEqual(report['counts']['process_create'], 2)
        self.assertEqual(sorted(item['code'] for item in report['exits']), [0, 7])
        self.assertNotIn('process_excluded', report['counts'])

    def test_provider_details_and_wait_cycles_survive_log_export(self):
        prefix = (ROOT / 'prefix').resolve()
        logs = prefix / 'logs/runs'
        result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(logs), '--', str(ROOT / 'wait.exe')], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr[-4000:])
        report = json.loads(Path(json.loads(result.stdout)['data']['log']).read_text())
        self.assertTrue(any(item['data']['provider'] == 8 for item in report['providers']))
        self.assertTrue(report['observed_wait_cycles'])
        self.assertTrue(all(item['wait_graph']['coverage'] == 'partial' for item in report['observed_wait_cycles']))
        self.assertEqual(report['provider_events_omitted'], 0)
        self.assertEqual(report['wait_cycles_omitted'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
