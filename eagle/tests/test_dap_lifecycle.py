import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'))
from dap import Adapter
from protocol import read_message


class DapLifecycle(unittest.TestCase):
    def setUp(self):
        self.output = io.BytesIO()
        self.adapter = Adapter(io.BytesIO(), self.output)

    def messages(self):
        stream = io.BytesIO(self.output.getvalue())
        messages = []
        while (message := read_message(stream)) is not None:
            messages.append(message)
        return messages

    def observe(self, kind, pid, **fields):
        self.adapter.observed(dict(kind=kind, pid=pid, **fields))

    def test_child_exit_keeps_the_main_process_alive(self):
        self.observe('process_create', 1, parent_pid=0)
        self.observe('process_create', 2, parent_pid=1)
        self.observe('process_exit', 2, code=7)
        self.assertEqual(self.messages(), [])
        self.observe('process_exit', 1, code=11)
        self.assertEqual([(m['event'], m['body']) for m in self.messages()],
                         [('exited', {'exitCode': 11})])

    def test_main_exit_is_reported_once_while_children_finish(self):
        self.observe('process_create', 1, parent_pid=0)
        self.observe('process_create', 2, parent_pid=1)
        self.observe('process_exit', 1, code=11)
        self.observe('process_exit', 2, code=7)
        self.observe('process_create', 1, parent_pid=2)
        self.observe('process_exit', 1, code=19)
        self.assertEqual([(m['event'], m['body']) for m in self.messages()],
                         [('exited', {'exitCode': 11})])
        self.assertFalse(self.adapter.done.is_set())

    def test_launch_and_attach_reset_the_main_process(self):
        for attach, pid, code in [(True, 5, 11), (False, 8, 17), (True, 5, 23)]:
            with self.subTest(attach=attach, pid=pid, code=code):
                def capture(*args, **options):
                    if attach:
                        self.observe('process_create', 2, parent_pid=pid)
                    self.observe('process_create', pid, parent_pid=0)
                    self.observe('stopped', pid, tid=3, reason='entry')
                    self.observe('process_exit', 2, code=7)
                    self.observe('process_exit', pid, code=code)
                after = len(self.messages())
                with patch('dap.capture', side_effect=capture):
                    self.adapter.start({'session': 'unused-session', 'prefix': 'unused-prefix',
                                        'wine': 'unused-wine', 'program': 'owned.exe', 'processId': pid}, attach)
                    self.adapter.thread.join(timeout=2)
                    self.assertFalse(self.adapter.thread.is_alive())
                events = self.messages()[after:]
                self.assertEqual([m['body']['exitCode'] for m in events if m['event'] == 'exited'], [code])
                self.assertEqual(sum(m['event'] == 'terminated' for m in events), 1)


if __name__ == '__main__':
    unittest.main()
