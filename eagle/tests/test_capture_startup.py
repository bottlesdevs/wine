import io
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import session


class Commands(io.BytesIO):
    def __init__(self):
        super().__init__()
        self.commands = []

    def write(self, data):
        self.commands.append(data)
        return super().write(data)


class Collector:
    def __init__(self, events=(), live=False, detach=True, terminate=True):
        self.stdin = Commands()
        self.stdout = self.pipe(b''.join(json.dumps(event).encode() + b'\n' for event in events))
        self.stderr = self.pipe(b'')
        self.returncode = None if live else 0
        self.detach_works = detach
        self.terminate_works = terminate
        self.terminated = self.killed = 0

    def pipe(self, data):
        reader, writer = os.pipe()
        os.write(writer, data)
        os.close(writer)
        return os.fdopen(reader, 'rb', buffering=0)

    def poll(self):
        return self.returncode

    def wait(self, timeout):
        if self.returncode is None and self.detach_works and b'detach\n' in self.stdin.commands:
            self.returncode = 0
        if self.returncode is None:
            raise subprocess.TimeoutExpired('owned collector fixture', timeout)
        return self.returncode

    def terminate(self):
        self.terminated += 1
        if self.terminate_works:
            self.returncode = -15

    def kill(self):
        self.killed += 1
        self.returncode = -9

    def close(self):
        for stream in (self.stdin, self.stdout, self.stderr):
            stream.close()


class CaptureStartup(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.wine = self.root / 'wine'
        self.wine.write_bytes(b'owned launcher fixture')
        self.wine.chmod(0o700)

    def capture(self, collector, root, control_enabled=True, register_failure=None):
        self.addCleanup(collector.close)
        control = socket.socket(socket.AF_UNIX)
        selector = selectors.DefaultSelector()
        self.addCleanup(control.close)
        self.addCleanup(selector.close)
        self.control, self.selector = control, selector
        original = selector.register
        count = 0
        def register(*args):
            nonlocal count
            count += 1
            if count == register_failure:
                raise OSError('owned registration failure')
            return original(*args)
        with patch('session.socket.socket', return_value=control), patch('session.selectors.DefaultSelector', return_value=selector), patch('session.subprocess.Popen', return_value=collector), patch.object(selector, 'register', side_effect=register):
            return session.capture(self.wine, self.root / 'prefix', root, pid=123,
                                   control_enabled=control_enabled)

    def assert_closed(self, collector, root):
        self.assertIsNotNone(collector.poll())
        self.assertTrue(all(stream.closed for stream in (collector.stdin, collector.stdout, collector.stderr)))
        self.assertEqual(self.control.fileno(), -1)
        self.assertIsNone(self.selector.get_map())
        self.assertFalse((root / 'control.sock').exists())
        manifest = json.loads((root / 'manifest.json').read_text())
        self.assertIn('ended', manifest)
        self.assertFalse(manifest['completed'])
        self.assertEqual((root / 'events.jsonl').read_bytes(), b'')
        return manifest

    def test_normal_capture_records_events_in_the_reserved_history(self):
        for control in (False, True):
            with self.subTest(control=control):
                root = self.root / str(control)
                events = [{'seq': 1, 'kind': 'process_exit', 'pid': 123, 'tid': 456, 'code': 0},
                          {'seq': 2, 'kind': 'finished', 'pid': 0, 'tid': 0}]
                collector = Collector(events)
                report = self.capture(collector, root, control_enabled=control)
                self.assertTrue(report['manifest']['completed'])
                self.assertEqual(report['manifest']['collector_exit'], 0)
                self.assertEqual([json.loads(line) for line in (root / 'events.jsonl').read_text().splitlines()], events)
                self.assertEqual((root / 'events.jsonl').stat().st_mode & 0o777, 0o600)
                self.assertTrue(collector.stdout.closed)
                self.assertEqual(self.control.fileno(), -1)

    def test_stream_setup_failure_detaches_and_preserves_history(self):
        root = self.root / 'stream'
        collector = Collector(live=True)
        with patch('session.os.set_blocking', side_effect=OSError('owned stream setup failure')):
            with self.assertRaisesRegex(OSError, 'owned stream setup failure'):
                self.capture(collector, root)
        manifest = self.assert_closed(collector, root)
        self.assertEqual(manifest['setup_error'], 'owned stream setup failure')
        self.assertIn(b'detach\n', collector.stdin.commands)
        self.assertEqual(collector.terminated, 0)

    def test_each_registration_failure_closes_partial_resources(self):
        for position in (1, 2, 3):
            with self.subTest(position=position):
                root = self.root / str(position)
                collector = Collector(live=True)
                with self.assertRaisesRegex(OSError, 'owned registration failure'):
                    self.capture(collector, root, register_failure=position)
                self.assertEqual(self.assert_closed(collector, root)['setup_error'], 'owned registration failure')

    def test_closed_control_input_falls_back_to_termination(self):
        root = self.root / 'closed-input'
        collector = Collector(live=True)
        collector.stdin.close()
        with self.assertRaisesRegex(OSError, 'owned registration failure'):
            self.capture(collector, root, register_failure=1)
        self.assert_closed(collector, root)
        self.assertEqual(collector.terminated, 1)

    def test_unresponsive_collector_is_killed_and_reaped(self):
        root = self.root / 'stubborn'
        collector = Collector(live=True, detach=False, terminate=False)
        with self.assertRaisesRegex(OSError, 'owned registration failure'):
            self.capture(collector, root, register_failure=1)
        self.assert_closed(collector, root)
        self.assertEqual((collector.terminated, collector.killed), (1, 1))

    def test_already_exited_collector_needs_no_stop_command(self):
        root = self.root / 'exited'
        collector = Collector()
        with self.assertRaisesRegex(OSError, 'owned registration failure'):
            self.capture(collector, root, register_failure=1)
        self.assert_closed(collector, root)
        self.assertEqual(collector.stdin.commands, [])

    def test_event_error_still_closes_the_collector_and_history(self):
        root = self.root / 'event-error'
        collector = Collector([{'kind': 'provider', 'payload': '[]'}], live=True, detach=False, terminate=False)
        with self.assertRaisesRegex(ValueError, 'unsupported provider payload'):
            self.capture(collector, root)
        self.assert_closed(collector, root)
        self.assertEqual((collector.terminated, collector.killed), (1, 1))


if __name__ == '__main__':
    unittest.main(verbosity=2)
