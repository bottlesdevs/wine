import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
ROOT = Path(os.environ['EAGLE_TOOL_TEST_ROOT'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.runtime import Cancelled, cancellation, run_tool


class ToolTests(unittest.TestCase):
    def command(self, name, inherited=True, exits=False):
        marker = ROOT / (name + '.pid')
        script = '\n'.join((
            'import os, signal, subprocess, sys, time',
            'child = subprocess.Popen([sys.executable, "-c", "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"], ' + ('close_fds=True)' if inherited else 'stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)'),
            'with open(sys.argv[1], "w") as output: output.write(str(child.pid))',
            'sys.exit(7)' if exits else 'time.sleep(60)',
        ))
        self.addCleanup(self.stop_child, marker)
        return [sys.executable, '-c', script, str(marker)], marker

    def stop_child(self, marker):
        if marker.exists():
            try:
                os.kill(int(marker.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass

    def assert_stopped(self, marker):
        self.assertTrue(marker.exists(), 'descendant was not launched')
        state = Path('/proc') / marker.read_text() / 'stat'
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                if state.read_text().split(') ')[1][0] == 'Z': return
            except FileNotFoundError:
                return
            time.sleep(0.01)
        self.fail('descendant survived tool completion')

    def test_cancellation_stops_descendants_with_open_output(self):
        command, marker = self.command('cancel')
        cancel = threading.Event()
        def request_cancel():
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            cancel.set()
        thread = threading.Thread(target=request_cancel)
        thread.start()
        token = cancellation.set(cancel)
        started = time.monotonic()
        try:
            with self.assertRaises(Cancelled):
                run_tool(command, timeout=10, capture_output=True)
        finally:
            cancellation.reset(token)
            thread.join(timeout=5)
        self.assertLess(time.monotonic() - started, 2)
        self.assert_stopped(marker)

    def test_timeout_stops_descendants_after_leader_exit(self):
        command, marker = self.command('timeout', exits=True)
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            run_tool(command, timeout=0.5, capture_output=True)
        self.assertLess(time.monotonic() - started, 2)
        self.assert_stopped(marker)

    def test_completed_tool_stops_background_descendants(self):
        command, marker = self.command('completed', inherited=False, exits=True)
        result = run_tool(command, timeout=5, capture_output=True)
        self.assertEqual(result.returncode, 7)
        self.assert_stopped(marker)

    def test_input_output_and_exit_code_are_preserved(self):
        result = run_tool([sys.executable, '-c', 'import sys; print(sys.stdin.read()); print("diagnostic", file=sys.stderr); sys.exit(3)'], input='input', capture_output=True, text=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (3, 'input\n', 'diagnostic\n'))


if __name__ == '__main__':
    ROOT.mkdir(parents=True, exist_ok=True)
    unittest.main()
