import io
import json
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest


SOURCE = Path(__file__).resolve().parents[1]
PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
sys.dont_write_bytecode = True
sys.path.insert(0, str(SOURCE))
from protocol import read_message, write_message


class AnalysisAdapter(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.native = self.root / 'native'
        self.native.mkdir()
        for name in ('eagle-driver', 'eagle-pe', 'eagle-analysis', 'eagle-intel'):
            shutil.copy2(PACKAGE / 'native' / name, self.native / name)
        shutil.copy2(PACKAGE / 'analysis.json', self.root / 'analysis.json')
        for name in ('eagle', 'analysis.py', 'cli.py', 'session.py', 'protocol.py', 'errors.py', 'symbols.py', 'waits.py'):
            shutil.copy2(SOURCE / name, self.root / name)
        (self.root / 'engine').mkdir()
        for name in ('eagle.yar', 'eagle-intel.sqlite'):
            (self.root / 'engine' / name).touch()
        scanner = self.native / 'eagle-yara'
        scanner.write_text('#!' + sys.executable + '\nprint(\'{"matches":[]}\')\n')
        scanner.chmod(0o755)
        self.target = self.root / 'app.exe'
        source = self.root / 'app.c'
        source.write_text('int main(void) { return 0; }\n')
        subprocess.run(['x86_64-w64-mingw32-gcc', str(source), '-o', str(self.target)], check=True, capture_output=True)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.env = dict(os.environ, TMPDIR=str(self.work), TMP=str(self.work), TEMP=str(self.work),
                        PYTHONPATH=str(self.root), EAGLE_INTEL_DB=str(self.root / 'engine/eagle-intel.sqlite'),
                        XDG_DATA_HOME=str(self.root / 'xdg'))

    def cli(self, *arguments):
        return subprocess.run([sys.executable, str(self.root / 'eagle'), *arguments],
                              text=True, capture_output=True, timeout=10, env=self.env)

    def test_cli_report_and_progress_match_direct_driver(self):
        direct = subprocess.run([str(self.native / 'eagle-driver')], text=True, capture_output=True,
                                input=json.dumps(dict(target=str(self.target), work=str(self.work), scan_limit=1)),
                                timeout=10, env=self.env)
        self.assertEqual(direct.returncode, 0, direct.stderr)
        expected = [json.loads(line) for line in direct.stdout.splitlines()]
        plain = self.cli('analyze', str(self.target), '--scan-limit', '1')
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertEqual(json.loads(plain.stdout), expected[-1])
        progress = self.cli('analyze', str(self.target), '--scan-limit', '1', '--progress')
        self.assertEqual(progress.returncode, 0, progress.stderr)
        self.assertEqual([json.loads(line) for line in progress.stdout.splitlines()], expected)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_cli_rejects_events_after_report_and_unknown_events(self):
        report = dict(status=True, data={'name': 'fixture'})
        for messages in ([report, dict(event='step', data='late step')],
                         [dict(report, event='unknown')]):
            with self.subTest(messages=messages):
                output = ''.join(json.dumps(message) + '\n' for message in messages)
                driver = self.native / 'eagle-driver'
                driver.write_text('#!' + sys.executable + '\nimport sys\n'
                                  'sys.stdout.write(' + repr(output) + ')\n')
                driver.chmod(0o755)
                result = self.cli('analyze', str(self.target), '--progress')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn('unexpected analysis response', result.stderr)

    def test_stdio_rejects_truncated_headers(self):
        self.assertIsNone(read_message(io.BytesIO(b'')))
        for fragment in (b'Content-Length: 2', b'Content-Length: 2\r\n',
                         b'Content-Length: 2\r\nContent-Type: application/json\r\n'):
            with self.subTest(fragment=fragment):
                result = subprocess.run([sys.executable, str(self.root / 'eagle'), 'serve'],
                                        input=fragment, capture_output=True, env=self.env, timeout=7)
                self.assertEqual(result.returncode, 0, result.stderr)
                response = read_message(io.BytesIO(result.stdout))
                self.assertIsNotNone(response)
                self.assertEqual(response['error']['code'], -32700)
                self.assertIn('truncated message headers', response['error']['message'])

    def test_incomplete_package_hides_analysis(self):
        for missing in ('native/eagle-driver', 'analysis.json', 'engine/eagle.yar', 'engine/eagle-intel.sqlite'):
            with self.subTest(missing=missing):
                path = self.root / missing
                backup = path.with_name(path.name + '.saved')
                path.rename(backup)
                try:
                    result = self.cli('capabilities')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    capabilities = json.loads(result.stdout)['data']
                    self.assertFalse(capabilities['analysis']['available'])
                    self.assertFalse(capabilities['native_static_analyzer'])
                    self.assertNotIn('analyze', self.cli('--help').stdout)
                finally:
                    backup.rename(path)

    def test_invalid_limit_and_missing_target(self):
        for arguments in (('analyze', str(self.target), '--scan-limit', '0'),
                          ('analyze', str(self.root / 'missing.exe'))):
            result = self.cli(*arguments)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(result.stderr)['status'])

    def waiting_helper(self):
        receipt = self.root / 'helper.pid'
        helper = self.native / 'eagle-pe'
        helper.write_text('#!' + sys.executable + '\nimport os,time\n'
                          'from pathlib import Path\n'
                          'Path(' + repr(str(receipt)) + ').write_text(str(os.getpid()))\n'
                          'time.sleep(60)\n')
        helper.chmod(0o755)
        return receipt

    def wait_receipt(self, receipt):
        until = time.monotonic() + 5
        while time.monotonic() < until:
            try:
                return int(receipt.read_text())
            except (FileNotFoundError, ValueError):
                time.sleep(0.01)
        self.fail('native helper did not start')

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream:
                stream.close()

    def test_cli_signal_cancels_native_helper(self):
        receipt = self.waiting_helper()
        process = subprocess.Popen([sys.executable, str(self.root / 'eagle'), 'analyze', str(self.target), '--progress'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
        self.addCleanup(self.stop, process)
        pid = self.wait_receipt(receipt)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=7)
        self.assertEqual(process.returncode, 130, stdout + stderr)
        self.assertTrue(json.loads(stderr)['cancelled'])
        self.assertFalse(Path('/proc', str(pid)).exists())
        self.assertEqual(list(self.work.iterdir()), [])

    def test_stdio_shutdown_and_eof_cancel_active_analysis(self):
        for shutdown in (False, True):
            with self.subTest(shutdown=shutdown):
                receipt = self.waiting_helper()
                receipt.unlink(missing_ok=True)
                process = subprocess.Popen([sys.executable, str(self.root / 'eagle'), 'serve'],
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
                self.addCleanup(self.stop, process)
                write_message(process.stdin, dict(id=1, method='initialize', params=dict(schema=1)))
                write_message(process.stdin, dict(id=2, method='analyze', params=dict(path=str(self.target))))
                pid = self.wait_receipt(receipt)
                if shutdown:
                    write_message(process.stdin, dict(id=3, method='shutdown'))
                process.stdin.close()
                process.stdin = None
                stdout, stderr = process.communicate(timeout=7)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertIn(b'"code": -32800', stdout)
                self.assertFalse(Path('/proc', str(pid)).exists())
                self.assertEqual(list(self.work.iterdir()), [])

    def test_stdio_analysis_and_cancellation(self):
        process = subprocess.Popen([sys.executable, str(self.root / 'eagle'), 'serve'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        self.addCleanup(self.stop, process)
        messages = queue.Queue()
        def receive():
            try:
                while True:
                    message = read_message(process.stdout)
                    if message is None:
                        return
                    messages.put(message)
            except (OSError, ValueError) as error:
                messages.put(error)
        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        def reply(request_id):
            steps = []
            while True:
                message = messages.get(timeout=7)
                if isinstance(message, Exception):
                    raise message
                if message.get('id') == request_id:
                    return message, steps
                steps.append(message)
        write_message(process.stdin, dict(id=1, method='initialize', params=dict(schema=1)))
        initialized, _ = reply(1)
        self.assertTrue(initialized['result']['native_static_analyzer'])
        write_message(process.stdin, dict(id=6, method='security-scan', params=dict(path=str(self.target))))
        self.assertEqual(reply(6)[0], dict(id=6, result=[]))
        write_message(process.stdin, dict(id=2, method='analyze', params=dict(path=str(self.target), scan_limit=1)))
        result, steps = reply(2)
        self.assertEqual(result['result']['arch'], 'x86_64 (64-bit)')
        self.assertTrue(any(step.get('event') == 'analysis.step' for step in steps))
        receipt = self.waiting_helper()
        write_message(process.stdin, dict(id=3, method='analyze', params=dict(path=str(self.target))))
        pid = self.wait_receipt(receipt)
        write_message(process.stdin, dict(id=4, method='cancel', params=dict(request_id=3)))
        cancelled = {}
        while len(cancelled) < 2:
            message = messages.get(timeout=7)
            if isinstance(message, Exception):
                raise message
            if message.get('id') in (3, 4):
                cancelled[message['id']] = message
        self.assertTrue(cancelled[4]['result']['requested'])
        self.assertEqual(cancelled[3]['error']['code'], -32800)
        self.assertFalse(Path('/proc', str(pid)).exists())
        write_message(process.stdin, dict(id=5, method='shutdown'))
        self.assertEqual(reply(5)[0], dict(id=5, result=None))
        process.wait(timeout=7)
        reader.join(timeout=2)
        self.assertFalse(reader.is_alive())
        self.assertEqual(process.returncode, 0)
        self.assertEqual(list(self.work.iterdir()), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
