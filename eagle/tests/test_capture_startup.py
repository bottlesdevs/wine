import errno
import hashlib
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
    def __init__(self, events=(), live=False, detach=True, terminate=True, stderr=b'', stdout=b'', trailing=b''):
        self.stdin = Commands()
        self.stdout = self.pipe(stdout + b''.join(json.dumps(event).encode() + b'\n' for event in events) + trailing)
        self.stderr = self.pipe(stderr)
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

    def capture(self, collector, root, control_enabled=True, register_failure=None, observer=None):
        self.addCleanup(collector.close)
        socket_type = socket.socket
        control = socket_type(socket.AF_UNIX)
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
        with patch('session.socket.socket', side_effect=lambda *args, **kwargs: socket_type(*args, **kwargs) if 'fileno' in kwargs else control), patch('session.selectors.DefaultSelector', return_value=selector), patch('session.subprocess.Popen', return_value=collector), patch.object(selector, 'register', side_effect=register):
            return session.capture(self.wine, self.root / 'prefix', root, pid=123,
                                   control_enabled=control_enabled, observer=observer)

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

    def test_export_frames_gain_exact_source_without_stale_displacements(self):
        image = self.root / 'owned.dll'
        image.write_bytes(b'owned image fixture')
        identity = dict(sha256=hashlib.sha256(image.read_bytes()).hexdigest())
        for symbol_type, line, resolved in [(1, None, True), (4, None, True),
                                             (4, 12, False), (7, None, False)]:
            with self.subTest(symbol_type=symbol_type, line=line):
                frame = dict(image=str(image), rva='0x20', address='0x400020',
                             symbol='nearest_export', symbol_type=symbol_type, displacement=100)
                if line:
                    frame.update(file='owned.c', line=line)
                events = [dict(seq=1, kind='module_load', pid=123, tid=456, path=str(image), base='0x400000'),
                          dict(seq=2, kind='snapshot', pid=123, tid=456, frames=[frame]),
                          dict(seq=3, kind='finished', pid=0, tid=0)]
                root = self.root / f'symbols-{symbol_type}-{line}'
                with patch('session.cached_identity', return_value=identity), \
                        patch('symbols.resolve', return_value=[dict(symbol='internal_function', file='owned.c', line=42)]) as resolve:
                    self.capture(Collector(events), root, control_enabled=False)
                recorded = json.loads((root / 'events.jsonl').read_text().splitlines()[1])['frames'][0]
                self.assertEqual(resolve.call_count, int(resolved))
                if resolved:
                    self.assertEqual(recorded['symbol'], 'internal_function')
                    self.assertEqual(recorded['line'], 42)
                    self.assertNotIn('displacement', recorded)
                else:
                    self.assertEqual(recorded['symbol'], 'nearest_export')
                    self.assertEqual(recorded['displacement'], 100)

    def test_export_resolution_keeps_fallbacks_and_reuses_cached_results(self):
        image = self.root / 'owned.dll'
        image.write_bytes(b'owned image fixture')
        identity = dict(sha256=hashlib.sha256(image.read_bytes()).hexdigest())
        for index, answer in enumerate(([], [dict(symbol='without_source')],
                                         [dict(symbol='nearest_export', file='owned.c', line=42)])):
            with self.subTest(answer=answer):
                frame = dict(image=str(image), rva='0x20', address='0x400020',
                             symbol='nearest_export', symbol_type=4, displacement=100)
                events = [dict(seq=1, kind='module_load', pid=123, tid=456, path=str(image), base='0x400000'),
                          dict(seq=2, kind='snapshot', pid=123, tid=456, frames=[frame]),
                          dict(seq=3, kind='snapshot', pid=123, tid=456, frames=[frame]),
                          dict(seq=4, kind='finished', pid=0, tid=0)]
                root = self.root / f'fallback-{index}'
                with patch('session.cached_identity', return_value=identity), \
                        patch('symbols.resolve', return_value=answer) as resolve:
                    self.capture(Collector(events), root, control_enabled=False)
                self.assertEqual(resolve.call_count, 1)
                recorded = [json.loads(line)['frames'][0] for line in (root / 'events.jsonl').read_text().splitlines()[1:3]]
                for value in recorded:
                    self.assertEqual(value['symbol'], 'nearest_export')
                    self.assertEqual(value['displacement'], 100)
                    self.assertEqual(value.get('line'), 42 if index == 2 else None)

    def test_export_resolution_rejects_a_changed_image(self):
        image = self.root / 'owned.dll'
        image.write_bytes(b'owned image fixture')
        frame = dict(image=str(image), rva='0x20', address='0x400020',
                     symbol='nearest_export', symbol_type=4, displacement=100)
        events = [dict(seq=1, kind='module_load', pid=123, tid=456, path=str(image), base='0x400000'),
                  dict(seq=2, kind='snapshot', pid=123, tid=456, frames=[frame]),
                  dict(seq=3, kind='finished', pid=0, tid=0)]
        root = self.root / 'changed-image'
        with patch('session.cached_identity', side_effect=[dict(sha256='a' * 64), dict(sha256='b' * 64)]), \
                patch('symbols.resolve') as resolve:
            self.capture(Collector(events), root, control_enabled=False)
        resolve.assert_not_called()
        recorded = json.loads((root / 'events.jsonl').read_text().splitlines()[1])['frames'][0]
        self.assertEqual(recorded['symbol'], 'nearest_export')
        self.assertEqual(recorded['symbol_status'], 'image missing or mismatched')

    def test_control_is_serviced_between_buffered_events(self):
        root = self.root / 'buffered-control'
        events = [{'seq': 1, 'kind': 'thread_create', 'pid': 123, 'tid': 456},
                  {'seq': 2, 'kind': 'thread_exit', 'pid': 123, 'tid': 456},
                  {'seq': 3, 'kind': 'finished', 'pid': 0, 'tid': 0}]
        collector = Collector(events)
        client = socket.socket(socket.AF_UNIX)
        self.addCleanup(client.close)
        client.settimeout(1)
        def observe(event):
            if event['seq'] == 1:
                client.connect(str(root / 'control.sock'))
                client.sendall(b'pause\n')
            elif event['seq'] == 2:
                self.assertIn(b'pause\n', collector.stdin.commands)
                self.assertTrue(json.loads(client.recv(4096))['accepted'])
        report = self.capture(collector, root, observer=observe)
        self.assertTrue(report['manifest']['completed'])
        self.assertEqual(collector.stdin.commands, [b'pause\n'])

    def test_stderr_tail_is_bounded_and_counts_discarded_bytes(self):
        for size in (0, 1, 127, 128, 129, 4096):
            with self.subTest(size=size):
                root = self.root / str(size)
                data = bytes(index % 256 for index in range(size))
                collector = Collector([{'seq': 1, 'kind': 'finished', 'pid': 0, 'tid': 0}], stderr=data)
                with patch('session.MAX_STDERR', 128, create=True):
                    report = self.capture(collector, root)
                manifest = report['manifest']
                self.assertTrue(manifest['completed'])
                self.assertEqual(manifest['stderr_bytes'], size)
                self.assertEqual(manifest['discarded_stderr_bytes'], max(0, size - 128))
                self.assertEqual(manifest['stderr_capture']['limit_bytes'], 128)
                self.assertEqual(manifest['stderr_capture']['retained_bytes'], min(size, 128))
                if data:
                    self.assertEqual((root / 'stderr.log').read_bytes(), data[-128:])
                    self.assertEqual(manifest['stderr_capture']['sha256'], hashlib.sha256(data[-128:]).hexdigest())
                else:
                    self.assertFalse((root / 'stderr.log').exists())

    def test_raw_stderr_stays_private_when_exporting(self):
        root = self.root / 'private-stderr'
        data = b'owned private diagnostic /home/reporter/private-file \xff\x00\n'
        collector = Collector([{'seq': 1, 'kind': 'finished', 'pid': 0, 'tid': 0}], stderr=data)
        self.capture(collector, root)
        self.assertEqual((root / 'stderr.log').read_bytes(), data)
        self.assertEqual((root / 'stderr.log').stat().st_mode & 0o777, 0o600)
        self.assertEqual(root.stat().st_mode & 0o777, 0o700)
        destination = self.root / 'upload.log'
        session.export(root, destination)
        exported = destination.read_bytes()
        self.assertNotIn(b'owned private diagnostic', exported)
        self.assertNotIn(b'/home/reporter/private-file', exported)
        self.assertEqual(json.loads(exported)['manifest']['stderr_capture']['retained_bytes'], len(data))

    def test_stderr_collision_preserves_existing_file_and_reports_loss(self):
        root = self.root / 'stderr-collision'
        collector = Collector([{'seq': 1, 'kind': 'finished', 'pid': 0, 'tid': 0}], stderr=b'new diagnostic')
        report = self.capture(collector, root, observer=lambda event: (root / 'stderr.log').write_bytes(b'existing'))
        self.assertTrue(report['manifest']['completed'])
        self.assertEqual((root / 'stderr.log').read_bytes(), b'existing')
        self.assertEqual(report['manifest']['stderr_capture']['retained_bytes'], 0)
        self.assertEqual(report['manifest']['stderr_capture']['error_errno'], errno.EEXIST)
        self.assertEqual(report['manifest']['discarded_stderr_bytes'], len(b'new diagnostic'))

    def test_stdout_keeps_only_target_output_and_stays_private_when_exporting(self):
        root = self.root / 'private-stdout'
        data = b'018c:fixme:mlang:DetectInputCodepage private-token /home/reporter/private-file\n'
        data += b'{"private-field":"private-value"}\n'
        trailing = b'private trailing diagnostic \xff\x00'
        events = [{'seq': 1, 'kind': 'finished', 'pid': 0, 'tid': 0}]
        report = self.capture(Collector(events, stdout=data, trailing=trailing), root)
        retained = data + trailing
        self.assertTrue(report['manifest']['completed'])
        self.assertEqual([json.loads(line) for line in (root / 'events.jsonl').read_text().splitlines()], events)
        self.assertEqual((root / 'stdout.log').read_bytes(), retained)
        self.assertEqual((root / 'stdout.log').stat().st_mode & 0o777, 0o600)
        self.assertEqual(report['manifest']['stdout_bytes'], len(retained))
        self.assertEqual(report['manifest']['discarded_target_output_bytes'], 0)
        self.assertEqual(report['manifest']['stdout_capture']['sha256'], hashlib.sha256(retained).hexdigest())
        destination = self.root / 'stdout-upload.log'
        session.export(root, destination)
        exported = destination.read_bytes()
        for value in (b'private-token', b'private-field', b'private-value', b'/home/reporter/private-file', trailing):
            self.assertNotIn(value, exported)
        self.assertEqual(json.loads(exported)['manifest']['stdout_capture']['retained_bytes'], len(retained))

    def test_stdout_retains_a_bounded_tail_without_losing_protocol_events(self):
        for size in (0, 1, 127, 128, 129, 1024):
            with self.subTest(size=size):
                root = self.root / ('stdout-' + str(size))
                data = (b'owned diagnostic\n' * 65)[:size]
                collector = Collector([{'seq': 1, 'kind': 'finished', 'pid': 0, 'tid': 0}], trailing=data)
                with patch('session.MAX_STDOUT', 128, create=True):
                    report = self.capture(collector, root)
                manifest = report['manifest']
                self.assertTrue(manifest['completed'])
                self.assertEqual(manifest['stdout_bytes'], size)
                self.assertEqual(manifest['discarded_target_output_bytes'], max(0, size - 128))
                self.assertEqual(manifest['stdout_capture']['limit_bytes'], 128)
                self.assertEqual(manifest['stdout_capture']['retained_bytes'], min(size, 128))
                if data:
                    self.assertEqual((root / 'stdout.log').read_bytes(), data[-128:])
                else:
                    self.assertFalse((root / 'stdout.log').exists())

    def test_stdout_collision_preserves_existing_file_and_reports_loss(self):
        root = self.root / 'stdout-collision'
        data = b'new stdout diagnostic\n'
        collector = Collector([{'seq': 1, 'kind': 'finished', 'pid': 0, 'tid': 0}], stdout=data)
        report = self.capture(collector, root, observer=lambda event: (root / 'stdout.log').write_bytes(b'existing'))
        self.assertTrue(report['manifest']['completed'])
        self.assertEqual((root / 'stdout.log').read_bytes(), b'existing')
        self.assertEqual(report['manifest']['stdout_capture']['retained_bytes'], 0)
        self.assertEqual(report['manifest']['stdout_capture']['error_errno'], errno.EEXIST)
        self.assertEqual(report['manifest']['discarded_target_output_bytes'], len(data))

    def test_disconnected_control_client_does_not_end_capture(self):
        root = self.root / 'disconnected-control'
        events = [{'seq': 1, 'kind': 'thread_create', 'pid': 123, 'tid': 456},
                  {'seq': 2, 'kind': 'thread_exit', 'pid': 123, 'tid': 456},
                  {'seq': 3, 'kind': 'finished', 'pid': 0, 'tid': 0}]
        collector = Collector(events)
        client = socket.socket(socket.AF_UNIX)
        self.addCleanup(client.close)
        def observe(event):
            if event['seq'] == 1:
                client.connect(str(root / 'control.sock'))
                client.sendall(b'pause\n')
                client.close()
        report = self.capture(collector, root, observer=observe)
        self.assertTrue(report['manifest']['completed'])
        self.assertEqual(collector.stdin.commands, [b'pause\n'])

    def test_unreadable_control_request_does_not_end_capture(self):
        for payload in (b'\xff', None):
            with self.subTest(payload=payload):
                root = self.root / ('invalid-control' if payload else 'idle-control')
                collector = Collector([{'seq': 1, 'kind': 'thread_create', 'pid': 123, 'tid': 456},
                                       {'seq': 2, 'kind': 'finished', 'pid': 0, 'tid': 0}])
                client = socket.socket(socket.AF_UNIX)
                self.addCleanup(client.close)
                def observe(event):
                    if event['seq'] == 1:
                        client.connect(str(root / 'control.sock'))
                        if payload is not None:
                            client.sendall(payload)
                report = self.capture(collector, root, observer=observe)
                self.assertTrue(report['manifest']['completed'])
                self.assertEqual(collector.stdin.commands, [])

    def test_control_preserves_collector_pipe_errors(self):
        root = self.root / 'collector-pipe'
        collector = Collector([{'seq': 1, 'kind': 'thread_create', 'pid': 123, 'tid': 456},
                               {'seq': 2, 'kind': 'finished', 'pid': 0, 'tid': 0}])
        client = socket.socket(socket.AF_UNIX)
        self.addCleanup(client.close)
        def observe(event):
            if event['seq'] == 1:
                client.connect(str(root / 'control.sock'))
                client.sendall(b'pause\n')
        with patch.object(collector.stdin, 'write', side_effect=BrokenPipeError('collector pipe closed')):
            with self.assertRaisesRegex(BrokenPipeError, 'collector pipe closed'):
                self.capture(collector, root, observer=observe)

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
