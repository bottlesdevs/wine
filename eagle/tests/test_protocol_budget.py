import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from protocol import MAX_MESSAGE, MessageTooLarge, read_message, write_message


class ProtocolBudget(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle'), 'serve']

    def exchange(self, requests):
        stream = io.BytesIO()
        for request in requests:
            write_message(stream, request)
        process = subprocess.run(self.command, input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        stream = io.BytesIO(process.stdout)
        replies = []
        while (message := read_message(stream)) is not None:
            replies.append(message)
        return replies

    def request(self, request_id, method, **params):
        return {'id': request_id, 'method': method, 'params': params}

    def inspect(self, padding):
        root = self.root / 'session'
        root.mkdir()
        (root / 'manifest.json').write_text(json.dumps({'schema': 1, 'owned_padding': padding}))
        (root / 'events.jsonl').write_text('')
        return self.exchange([self.request(1, 'initialize', schema=1), self.request(2, 'inspect', session=str(root)),
                              self.request(3, 'capabilities'), self.request(4, 'shutdown')])

    def test_explicit_writer_limit_is_exact_and_never_writes_a_partial_frame(self):
        value = {'data': ''}
        value['data'] = 'x' * (MAX_MESSAGE - len(json.dumps(value).encode()))
        stream = io.BytesIO()
        write_message(stream, value, limit=MAX_MESSAGE)
        self.assertEqual(read_message(io.BytesIO(stream.getvalue())), value)
        stream = io.BytesIO()
        value['data'] += 'x'
        with self.assertRaises(MessageTooLarge):
            write_message(stream, value, limit=MAX_MESSAGE)
        self.assertFalse(stream.getvalue())

    def test_valid_request_ids_cover_encoded_boundaries_and_nullable_sync_ids(self):
        ids = [1, -7, '', None, 'r' * 1022, '\u00e9' * 170, 10 ** 1000]
        replies = self.exchange([self.request(value, 'initialize', schema=1) for value in ids] + [self.request(8, 'shutdown')])
        self.assertEqual([row['id'] for row in replies], ids + [8])
        self.assertTrue(all('result' in row for row in replies))
        self.assertEqual(replies[0]['result']['stdio']['maximum_message_bytes'], MAX_MESSAGE)

    def test_invalid_ids_do_not_dispatch_shutdown_or_break_following_requests(self):
        ids = ['r' * 1023, '\u00e9' * 171, True, 1.5, [], {}]
        replies = self.exchange([self.request(1, 'initialize', schema=1)] +
                                [self.request(value, 'shutdown') for value in ids] +
                                [self.request(2, 'capabilities'), self.request(3, 'shutdown')])
        self.assertEqual(len(replies), len(ids) + 3)
        for row in replies[1:1 + len(ids)]:
            self.assertIsNone(row['id'])
            self.assertEqual(row['error']['code'], -32600)
        self.assertIn('result', replies[-2])
        self.assertEqual(replies[-1]['id'], 3)

    def test_large_but_supported_inspection_is_returned_without_truncation(self):
        padding = 'x' * (MAX_MESSAGE - 8192)
        replies = self.inspect(padding)
        self.assertEqual(replies[1]['result']['manifest']['owned_padding'], padding)
        self.assertIn('result', replies[2])

    def test_oversized_result_is_a_bounded_error_and_backend_recovers(self):
        replies = self.inspect('x' * MAX_MESSAGE)
        self.assertEqual(replies[1]['error']['code'], -32603)
        self.assertIn('CLI or file export', replies[1]['error']['message'])
        self.assertNotIn('result', replies[1])
        self.assertIn('result', replies[2])
        self.assertEqual(replies[3]['id'], 4)

    def test_oversized_error_detail_has_a_bounded_fallback_and_backend_recovers(self):
        request = self.request(2, 'inspect', session=str(self.root) + '/')
        request['params']['session'] += 'x' * (MAX_MESSAGE - 8 - len(json.dumps(request).encode()))
        self.assertLess(len(json.dumps(request).encode()), MAX_MESSAGE)
        replies = self.exchange([self.request(1, 'initialize', schema=1), request,
                                 self.request(3, 'capabilities'), self.request(4, 'shutdown')])
        self.assertEqual(replies[1]['error']['code'], -32602)
        self.assertEqual(replies[1]['error']['message'], 'error detail exceeds message size limit')
        self.assertIn('result', replies[2])

    def test_oversized_input_frame_is_a_bounded_terminal_parse_error(self):
        stream = io.BytesIO()
        write_message(stream, self.request(1, 'initialize', schema=1, padding='x' * MAX_MESSAGE))
        process = subprocess.run(self.command, input=stream.getvalue(), capture_output=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        stream = io.BytesIO(process.stdout)
        reply = read_message(stream)
        self.assertIsNone(reply['id'])
        self.assertEqual(reply['error']['code'], -32700)
        self.assertIsNone(read_message(stream))

    def collector(self, mode):
        host = self.root / 'collector-host'
        marker = self.root / 'collector-ended'
        pid = self.root / 'collector-pid'
        host.write_text('#!' + sys.executable + '\n' +
                        'import os,json,sys\nfrom pathlib import Path\n' +
                        'if "--version" in sys.argv:\n print("owned collector fixture");sys.exit(0)\n' +
                        'Path(' + repr(str(pid)) + ').write_text(str(os.getpid()))\n' +
                        'event={"kind":"owned_fixture","pid":1,"tid":2,"padding":"x"*' +
                        str(MAX_MESSAGE + 1024 if mode == 'event' else MAX_MESSAGE // 2 + 1024) + '}\n' +
                        'for _ in range(' + str(1 if mode == 'event' else 2) + '):\n print(json.dumps(event),flush=True)\n' +
                        ('for line in sys.stdin:\n if line.strip()=="detach": break\n' if mode == 'event' else 'print(json.dumps({"kind":"finished","pid":1,"tid":2}),flush=True)\n') +
                        'Path(' + repr(str(marker)) + ').write_text("ended")\n')
        host.chmod(0o700)
        prefix = self.root / 'prefix'
        prefix.mkdir()
        process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop_backend, process)
        timer = threading.Timer(25, process.kill)
        timer.start()
        self.addCleanup(timer.cancel)
        write_message(process.stdin, self.request(1, 'initialize', schema=1))
        self.assertIn('result', read_message(process.stdout))
        session = self.root / 'capture'
        write_message(process.stdin, self.request(2, 'run', wine=str(host), prefix=str(prefix), session=str(session),
                                                 target=str(PACKAGE / 'lib/eagle/native/eagle-debug64.exe'), timeout=10))
        messages = []
        while True:
            value = read_message(process.stdout)
            self.assertIsNotNone(value)
            messages.append(value)
            if value.get('id') == 2:
                break
        self.assertEqual(messages[-1]['error']['code'], -32603, messages[-1])
        self.assertTrue(marker.is_file())
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid.read_text()), 0)
        write_message(process.stdin, self.request(3, 'capabilities'))
        self.assertIn('result', read_message(process.stdout))
        write_message(process.stdin, self.request(4, 'shutdown'))
        self.assertEqual(read_message(process.stdout)['id'], 4)
        self.assertEqual(process.wait(timeout=5), 0)
        timer.cancel()
        self.assertFalse((session / 'control.sock').exists())
        manifest = json.loads((session / 'manifest.json').read_text())
        self.assertIsNotNone(manifest.get('ended'))
        return messages, manifest, session

    def stop_backend(self, process):
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()

    def test_oversized_async_result_keeps_recorded_capture_and_valid_events(self):
        messages, manifest, root = self.collector('result')
        self.assertTrue(manifest['completed'])
        events = [message for message in messages if message.get('event') == 'debug.event' and message['data']['kind'] == 'owned_fixture']
        self.assertEqual(len(events), 2)
        self.assertTrue(all(len(value['data']['padding']) == MAX_MESSAGE // 2 + 1024 for value in events))
        cli = subprocess.run([sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle'), 'inspect', str(root)],
                             capture_output=True, text=True, timeout=15)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertGreater(len(cli.stdout.encode()), MAX_MESSAGE)
        self.assertEqual(len([event for event in json.loads(cli.stdout)['data']['timeline'] if event['kind'] == 'owned_fixture']), 2)

    def test_oversized_async_event_stops_owned_collector_and_retains_partial_history(self):
        messages, manifest, root = self.collector('event')
        self.assertFalse(any(message.get('event') == 'debug.event' for message in messages))
        self.assertIsNot(manifest.get('completed'), True)
        event = json.loads((root / 'events.jsonl').read_text().splitlines()[0])
        self.assertEqual(len(event['padding']), MAX_MESSAGE + 1024)


if __name__ == '__main__':
    unittest.main()
