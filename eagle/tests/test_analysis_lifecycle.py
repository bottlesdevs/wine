import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest


PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'


class AnalysisLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.libc = ctypes.CDLL(None, use_errno=True)
        cls.previous = ctypes.c_int()
        if cls.libc.prctl(37, ctypes.byref(cls.previous), 0, 0, 0) or cls.libc.prctl(36, 1, 0, 0, 0):
            raise RuntimeError('cannot collect test fixture descendants')

    @classmethod
    def tearDownClass(cls):
        cls.libc.prctl(36, cls.previous.value, 0, 0, 0)

    def case(self, extractor=False, complete=False, interrupt=None, deadline=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / 'native'
            native.mkdir()
            for name in ('eagle-driver', 'eagle-pe', 'eagle-analysis', 'eagle-intel'):
                shutil.copyfile(PACKAGE / 'native' / name, native / name)
                (native / name).chmod(0o755)
            shutil.copyfile(PACKAGE / 'analysis.json', root / 'analysis.json')
            scanner = native / 'eagle-yara'
            scanner.write_text('#!' + sys.executable + '\nprint(\'{"matches":[]}\')\n')
            scanner.chmod(0o755)
            work = root / 'work'
            work.mkdir()
            tools = root / 'tools'
            tools.mkdir()
            receipt = root / 'receipt.json'
            structure = dict(machine=0x8664, min_os='10.0', timestamp=0,
                             characteristics=0, dll_characteristics=0,
                             rich_products=[], sections=[], manifests=[],
                             imports=[], managed=False, version={}, imphash_material='')
            helper = tools / '7z' if extractor else native / 'eagle-pe'
            helper.write_text('#!' + sys.executable + '\n'
                'import json,os,subprocess,sys,time\nfrom pathlib import Path\n'
                'receipt=Path(' + repr(str(receipt)) + ')\n'
                'child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)",str(receipt)])\n'
                + ('output=Path(next(value[2:] for value in sys.argv if value.startswith("-o")))\n'
                   '(output/"first.exe").write_bytes(b"fixture")\n' if extractor else '')
                + 'receipt.write_text(json.dumps({"leader":os.getpid(),"child":child.pid}))\n'
                + ('' if complete else 'time.sleep(60)\n')
                + ('print("extracted",flush=True)\n' if extractor else 'print(' + repr(json.dumps(structure)) + ',flush=True)\n'))
            helper.chmod(0o755)
            target = root / ('fixture.msi' if extractor else 'fixture.exe')
            target.write_bytes(b'fixture')
            env = dict(os.environ, PATH=str(tools))
            request = dict(target=str(target), work=str(work), scan_limit=1,
                           database=str(root / 'missing.sqlite'))
            process = subprocess.Popen([str(native / 'eagle-driver')], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, env=env, start_new_session=True)
            pids = []
            started = time.monotonic()
            try:
                process.stdin.write(json.dumps(request))
                process.stdin.close()
                process.stdin = None
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    try:
                        pids = list(json.loads(receipt.read_text()).values())
                        break
                    except (FileNotFoundError, json.JSONDecodeError):
                        time.sleep(0.01)
                self.assertEqual(len(pids), 2, 'helper did not reach its controlled wait')
                if interrupt is not None:
                    process.send_signal(interrupt)
                stdout, stderr = process.communicate(timeout=36 if deadline else 5)
                messages = [json.loads(line) for line in stdout.splitlines()]
                expected = 128 + interrupt if interrupt is not None else 1 if deadline else 0
                self.assertEqual(process.returncode, expected, stderr + ' workspace=' + str(list(work.iterdir())))
                if interrupt is not None:
                    self.assertTrue(messages[-1]['cancelled'])
                    self.assertFalse(messages[-1]['status'])
                elif deadline:
                    self.assertIn('timed out', messages[-1]['error'])
                else:
                    self.assertTrue(messages[-1]['status'])
                self.assertLess(time.monotonic() - started, 35 if deadline else 5)
                for pid in pids:
                    self.assertFalse(Path('/proc', str(pid)).exists(), 'fixture process was not reaped: ' + str(pid))
                self.assertEqual(list(work.iterdir()), [])
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                for pid in pids:
                    command = Path('/proc', str(pid), 'cmdline')
                    try:
                        if str(root).encode() in command.read_bytes():
                            os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except FileNotFoundError:
                        pass
                for pid in pids:
                    try:
                        os.waitpid(pid, 0)
                    except ChildProcessError:
                        pass

    def test_cancel_helper_stops_descendants(self):
        self.case(interrupt=signal.SIGTERM)

    def test_interrupt_extraction_cleans_workspace(self):
        self.case(extractor=True, interrupt=signal.SIGINT)

    def test_completed_helper_reaps_inherited_output_child(self):
        self.case(complete=True)

    def test_completed_extractor_reaps_child_and_cleans_workspace(self):
        self.case(extractor=True, complete=True)

    def test_helper_deadline_stops_descendants(self):
        self.case(deadline=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
