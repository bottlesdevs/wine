import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from protocol import read_message, write_message
from engine.runtime import Cancelled, cancellation, run_tool


class BackendTests(unittest.TestCase):
    def test_native_tool_cancellation_reaps_child(self):
        cancel = threading.Event()
        timer = threading.Timer(0.1, cancel.set)
        timer.start()
        token = cancellation.set(cancel)
        start = time.monotonic()
        try:
            with self.assertRaises(Cancelled):
                run_tool([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=35, capture_output=True)
        finally:
            cancellation.reset(token)
            timer.cancel()
        self.assertLess(time.monotonic() - start, 2)

    def test_security_scan_remains_responsive_and_reaps_native_scanner(self):
        root = Path(os.environ['EAGLE_TEST_ROOT'])
        fifo = root / 'security-cancel.fifo'
        os.mkfifo(fifo, 0o600)
        self.addCleanup(fifo.unlink)
        with subprocess.Popen([str(PACKAGE / 'bin/eagle'), 'serve'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
            try:
                write_message(process.stdin, {'id': 1, 'method': 'initialize', 'params': {'schema': 1}})
                self.assertEqual(read_message(process.stdout)['id'], 1)
                write_message(process.stdin, {'id': 2, 'method': 'security-scan', 'params': {'path': str(fifo)}})
                child = None
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and child is None:
                    for children in Path(f'/proc/{process.pid}/task').glob('*/children'):
                        for pid in children.read_text().split():
                            command = Path(f'/proc/{pid}/cmdline')
                            if command.exists() and b'eagle-yara' in command.read_bytes(): child = int(pid)
                    if child is None: time.sleep(0.02)
                self.assertIsNotNone(child, 'native scanner was not started')
                write_message(process.stdin, {'id': 3, 'method': 'capabilities'})
                self.assertEqual(read_message(process.stdout)['id'], 3)
                write_message(process.stdin, {'id': 4, 'method': 'cancel', 'params': {'request_id': 2}})
                replies = {}
                while len(replies) < 2:
                    message = read_message(process.stdout)
                    if 'id' in message: replies[message['id']] = message
                self.assertTrue(replies[4]['result']['requested'])
                self.assertEqual(replies[2]['error']['code'], -32800)
                self.assertFalse(Path(f'/proc/{child}').exists(), 'native scanner survived cancellation')
                write_message(process.stdin, {'id': 5, 'method': 'shutdown'})
                self.assertEqual(read_message(process.stdout)['id'], 5)
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=5)

    def test_backend_remains_responsive_and_cancels_analysis(self):
        with subprocess.Popen([str(PACKAGE / 'bin/eagle'), 'serve'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
            try:
                write_message(process.stdin, {'id': 1, 'method': 'initialize', 'params': {'schema': 1}})
                self.assertEqual(read_message(process.stdout)['id'], 1)
                write_message(process.stdin, {'id': 2, 'method': 'analyze', 'params': {'path': str(Path(os.environ['EAGLE_TEST_ROOT']) / 'target64.exe')}})
                first = read_message(process.stdout)
                self.assertEqual(first.get('event'), 'analysis.step')
                write_message(process.stdin, {'id': 3, 'method': 'capabilities'})
                write_message(process.stdin, {'id': 4, 'method': 'cancel', 'params': {'request_id': 2}})
                replies = {}
                while len(replies) < 3:
                    response = read_message(process.stdout)
                    self.assertIsNotNone(response)
                    if 'id' in response:
                        replies[response['id']] = response
                self.assertEqual(replies[3]['result']['schema'], 1)
                self.assertTrue(replies[4]['result']['requested'])
                self.assertEqual(replies[2]['error']['code'], -32800)
                write_message(process.stdin, {'id': 5, 'method': 'shutdown'})
                self.assertEqual(read_message(process.stdout)['id'], 5)
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
