import json
import os
from pathlib import Path
import subprocess
import unittest
import time
import shutil
import hashlib
import struct

CANDIDATE = Path(os.environ['EAGLE_CANDIDATE'])
ROOT = Path(os.environ['EAGLE_TRACE_TEST_ROOT'])


class Tracing(unittest.TestCase):
    def test_loaded_builtin_identity_ignores_the_stale_prefix_copy(self):
        prefix = (ROOT / 'prefix').resolve()
        environment = dict(os.environ, WINEPREFIX=str(prefix))
        for bits, directory, architecture in [('32', 'syswow64', 'i386'), ('64', 'system32', 'x86_64')]:
            with self.subTest(bits=bits):
                subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-k'], env=environment, timeout=10)
                subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-w'], env=environment, timeout=15)
                image = prefix / 'drive_c/windows' / directory / 'kernelbase.dll'
                saved = image.read_bytes()
                stale = bytearray(saved)
                offset = struct.unpack_from('<I', stale, 0x3c)[0]
                struct.pack_into('<I', stale, offset + 8, 0)
                image.write_bytes(stale)
                before = set((prefix / 'logs/runs').glob('*.session'))
                try:
                    result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(prefix / 'logs/runs'), '--', str(ROOT / ('target' + bits + '.exe')), 'tracewait'], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr[-4000:])
                    session = (set((prefix / 'logs/runs').glob('*.session')) - before).pop()
                    events = [json.loads(line) for line in (session / 'events.jsonl').read_text().splitlines()]
                    application = next(event['pid'] for event in events if event['kind'] == 'process_create' and event['path'].lower().endswith('target' + bits + '.exe'))
                    module = next(event for event in events if event['kind'] == 'module_load' and event['pid'] == application and event['path'].lower().endswith('kernelbase.dll'))
                    expected = hashlib.sha256((CANDIDATE / ('lib/wine/' + architecture + '-windows/kernelbase.dll')).read_bytes()).hexdigest()
                    self.assertNotEqual(hashlib.sha256(image.read_bytes()).hexdigest(), expected)
                    self.assertEqual(module['identity']['sha256'], expected)
                    self.assertEqual(module['identity_origin'], 'process mapping')
                    exported = Path(json.loads(result.stdout)['data']['log']).read_text()
                    self.assertNotIn(str(ROOT), exported)
                finally:
                    subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-k'], env=environment, timeout=10)
                    subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-w'], env=environment, timeout=15)
                    image.write_bytes(saved)

    def test_dll_overrides_are_preserved(self):
        prefix = (ROOT / 'prefix').resolve()
        logs = prefix / 'logs/runs'
        for bits in ('32', '64'):
            for override, code in [('wtsapi32=d', 12), ('wtsapi32=b', 0)]:
                environment = dict(os.environ, WINEPREFIX=str(prefix), WINEDLLOVERRIDES=override)
                target = str(ROOT / ('target' + bits + '.exe'))
                plain = subprocess.run([str(CANDIDATE / 'bin/wine'), target, 'module'], env=environment, capture_output=True, timeout=60)
                self.assertEqual(plain.returncode, code)
                result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(logs), '--', target, 'module'], env=environment, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, code, result.stderr[-4000:])
                report = json.loads(Path(json.loads(result.stdout)['data']['log']).read_text())
                self.assertTrue(report['manifest']['completed'])

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

    def test_window_trace_finishes_with_wine_services_running(self):
        prefix = (ROOT / 'prefix').resolve()
        environment = dict(os.environ, WINEPREFIX=str(prefix))
        for bits in ('64', '32'):
            with self.subTest(bits=bits):
                subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-k'], env=environment, timeout=10)
                subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-w'], env=environment, timeout=15)
                helper = None
                collector = None
                try:
                    before = set((prefix / 'logs/runs').glob('*.running.log'))
                    before_sessions = set((prefix / 'logs/runs').glob('*.session'))
                    collector = subprocess.Popen([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(prefix / 'logs/runs'), '--', str(ROOT / ('target' + bits + '.exe')), 'window', '6000'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        created = set((prefix / 'logs/runs').glob('*.session')) - before_sessions
                        if any((path / 'events.jsonl').exists() and 'explorer.exe' in (path / 'events.jsonl').read_text().lower() for path in created):
                            break
                        time.sleep(0.05)
                    helper = subprocess.Popen([str(CANDIDATE / 'bin/wine'), str(ROOT / ('target' + bits + '.exe')), 'window', '15000'], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    output, error = collector.communicate(timeout=25)
                    self.assertEqual(collector.returncode, 0, error[-4000:])
                    self.assertIsNone(helper.poll(), 'untraced GUI client must still use the Wine desktop')
                    report = json.loads(Path(json.loads(output)['data']['log']).read_text())
                    self.assertTrue(report['manifest']['completed'])
                    self.assertIn('finished', report['counts'])
                    self.assertEqual(report['counts'].get('wine_services_detached'), 1)
                    self.assertFalse(report['terminal_exceptions'])
                    for event in report['timeline']:
                        if event['kind'] == 'detached':
                            alive = subprocess.run([str(CANDIDATE / 'bin/wine'), str(ROOT / ('target' + bits + '.exe')), 'pidalive', str(event['pid'])], env=environment, capture_output=True, timeout=10)
                            self.assertEqual(alive.returncode, 0, 'detached Wine service must stay alive')
                    self.assertFalse(set((prefix / 'logs/runs').glob('*.running.log')) - before)
                finally:
                    subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-k'], env=environment, timeout=10)
                    subprocess.run([str(CANDIDATE / 'bin/wineserver'), '-w'], env=environment, timeout=15)
                    if helper:
                        helper.wait(timeout=10)
                    if collector and collector.poll() is None:
                        collector.kill()
                        collector.communicate(timeout=10)

    def test_application_named_wine_service_keeps_its_children(self):
        prefix = (ROOT / 'prefix').resolve()
        for bits in ('32', '64'):
            for name in ('explorer', 'tabtip'):
                with self.subTest(bits=bits, name=name):
                    target = ROOT / ('names-' + bits) / (name + '.exe')
                    target.parent.mkdir(exist_ok=True)
                    shutil.copy2(ROOT / ('target' + bits + '.exe'), target)
                    result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(prefix / 'logs/runs'), '--', str(target), 'childwait'], capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr[-4000:])
                    report = json.loads(Path(json.loads(result.stdout)['data']['log']).read_text())
                    self.assertTrue(report['manifest']['completed'])
                    self.assertEqual(report['counts']['process_create'], 2)
                    self.assertEqual([item['code'] for item in report['exits']], [0, 7])
                    self.assertNotIn('process_excluded', report['counts'])
                    self.assertNotIn('wine_services_detached', report['counts'])

    def test_system_directory_replacement_keeps_its_children(self):
        prefix = (ROOT / 'prefix').resolve()
        for bits, directory in [('32', 'syswow64'), ('64', 'system32')]:
            target = prefix / 'drive_c/windows' / directory / 'explorer.exe'
            backup = ROOT / ('explorer-' + bits + '.original')
            target.rename(backup)
            try:
                shutil.copy2(ROOT / ('target' + bits + '.exe'), target)
                result = subprocess.run([str(CANDIDATE / 'bin/eagle'), 'trace', '--wine', str(CANDIDATE / 'bin/wine'), '--prefix', str(prefix), '--logs', str(prefix / 'logs/runs'), '--', str(target), 'childwait'], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr[-4000:])
                report = json.loads(Path(json.loads(result.stdout)['data']['log']).read_text())
                self.assertTrue(report['manifest']['completed'])
                self.assertEqual(report['counts']['process_create'], 2)
                self.assertEqual([item['code'] for item in report['exits']], [0, 7])
                self.assertNotIn('wine_services_detached', report['counts'])
            finally:
                target.unlink()
                backup.rename(target)


if __name__ == '__main__':
    unittest.main(verbosity=2)
