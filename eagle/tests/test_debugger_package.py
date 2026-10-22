import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import time
import unittest
import mmap
import ctypes
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from protocol import read_message, write_message
from symbols import host_path
from session import capture, mapped_image, windows_path


class DebuggerPackageTests(unittest.TestCase):
    def test_launcher_ignores_foreign_python_paths(self):
        with tempfile.TemporaryDirectory(dir=os.environ['EAGLE_TEST_ROOT']) as directory:
            root = Path(directory)
            (root / 'json.py').write_text('raise RuntimeError("foreign Python path")\n')
            for variables in (
                {'PYTHONHOME': str(root)},
                {'PYTHONPATH': str(root)},
                {'PYTHONHOME': str(root), 'PYTHONPATH': str(root)},
            ):
                with self.subTest(variables=tuple(variables)):
                    environment = os.environ.copy()
                    environment.update(variables)
                    result = subprocess.run([str(PACKAGE / 'bin/eagle'), '--help'],
                                            env=environment, capture_output=True,
                                            text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('trace', result.stdout)

    def test_launcher_does_not_write_bytecode(self):
        with tempfile.TemporaryDirectory(dir=os.environ['EAGLE_TEST_ROOT']) as directory:
            root = Path(directory)
            library = root / 'lib/eagle'
            library.mkdir(parents=True)
            (root / 'bin').mkdir()
            for source in (PACKAGE / 'lib/eagle').iterdir():
                if source.suffix == '.py' or source.name == 'eagle':
                    (library / source.name).write_bytes(source.read_bytes())
            launcher = root / 'bin/eagle'
            launcher.write_bytes((PACKAGE / 'bin/eagle').read_bytes())
            launcher.chmod(0o755)
            before = sorted(str(path.relative_to(root)) for path in root.rglob('*'))
            result = subprocess.run([str(launcher), '--help'], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sorted(str(path.relative_to(root)) for path in root.rglob('*')), before)

    def test_runtime_image_mapping_rejects_missing_and_deleted_files(self):
        with tempfile.TemporaryDirectory(dir=os.environ['EAGLE_TEST_ROOT']) as directory:
            image = Path(directory) / 'image.dll'
            image.write_bytes((PACKAGE / 'lib/wine/x86_64-windows/kernelbase.dll').read_bytes())
            with image.open('rb') as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_COPY) as mapping:
                address = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
                self.assertEqual(mapped_image(os.getpid(), hex(address)), image)
                self.assertIsNone(mapped_image(os.getpid(), hex(address + 4096)))
                self.assertIsNone(mapped_image(0, hex(address)))
                image.unlink()
                image.write_bytes(b'MZreplacement')
                self.assertIsNone(mapped_image(os.getpid(), hex(address)))

    def test_exited_collector_with_inherited_output_is_bounded(self):
        with tempfile.TemporaryDirectory(dir=os.environ['EAGLE_TEST_ROOT']) as directory:
            root = Path(directory)
            child = root / 'child.py'
            child.write_text('import time\ntime.sleep(3)\n')
            collector = root / 'collector.py'
            collector.write_text('import json,subprocess,sys\nfrom pathlib import Path\n'
                                 'child=subprocess.Popen([sys.executable,sys.argv[1]])\n'
                                 'Path(sys.argv[2]).write_text(str(child.pid))\n'
                                 'print(json.dumps({"kind":"finished","pid":0,"tid":0,"seq":1,"time_ms":0}),flush=True)\n')
            marker = root / 'child.pid'
            popen = subprocess.Popen
            def launch(arguments, **options):
                if arguments[0] != str((PACKAGE / 'bin/wine').resolve()):
                    return popen(arguments, **options)
                return popen([sys.executable, str(collector), str(child), str(marker)], **options)
            started = time.monotonic()
            try:
                with patch('session.subprocess.Popen', side_effect=launch):
                    result = capture(PACKAGE / 'bin/wine', root, root / 'session', target=Path(os.environ['EAGLE_TEST_ROOT']) / 'target64.exe', timeout=0.8, profile='process', control_enabled=False)
                self.assertLess(time.monotonic() - started, 2)
                self.assertTrue(result['manifest']['completed'])
                self.assertEqual(set(result['manifest']['inherited_output_streams']), {'stdout', 'stderr'})
            finally:
                if marker.exists():
                    pid = int(marker.read_text())
                    command = Path('/proc') / str(pid) / 'cmdline'
                    if command.exists() and str(child).encode() in command.read_bytes():
                        os.kill(pid, 15)

    def test_windows_module_paths_keep_file_case_and_drive_mapping(self):
        with tempfile.TemporaryDirectory(dir=os.environ['EAGLE_TEST_ROOT']) as directory:
            prefix = Path(directory)
            image = prefix / 'drive_c/Program Files/Example/vfs/Shared/Image.DLL'
            image.parent.mkdir(parents=True)
            image.write_bytes(b'fixture')
            (prefix / 'dosdevices').mkdir()
            (prefix / 'dosdevices/c:').symlink_to(prefix / 'drive_c', target_is_directory=True)
            self.assertEqual(windows_path(image, prefix), 'C:\\Program Files\\Example\\vfs\\Shared\\Image.DLL')
            self.assertEqual(windows_path(prefix / 'drive_c', prefix), 'C:\\')
            self.assertEqual(windows_path(image), 'Z:' + str(image).replace('/', '\\'))
            for value in ('C:\\Program Files\\Example\\vfs\\Shared\\Image.DLL', '\\\\?\\C:\\program files\\example\\VFS\\shared\\image.dll'):
                self.assertEqual(host_path(value, prefix).resolve(), image.resolve())
            self.assertEqual(host_path(str(image), prefix), image)
            self.assertEqual(host_path('Z:' + str(image).replace('/', '\\'), prefix), image)
            image.with_name('IMAGE.dll').write_bytes(b'other image')
            self.assertFalse(host_path('C:\\program files\\example\\VFS\\shared\\image.dll', prefix).is_file())
            self.assertEqual(host_path('C:\\Program Files\\Example\\vfs\\Shared\\Image.DLL', prefix).resolve(), image.resolve())

    def test_launch_paths_use_the_most_specific_drive(self):
        with tempfile.TemporaryDirectory(dir=os.environ['EAGLE_TEST_ROOT']) as directory:
            prefix = Path(directory)
            image = prefix / 'drive_c/Shared/Image.dll'
            image.parent.mkdir(parents=True)
            image.touch()
            devices = prefix / 'dosdevices'
            devices.mkdir()
            (devices / 'c:').symlink_to(prefix / 'drive_c', target_is_directory=True)
            for drive in ('d:', 'x:'):
                (devices / drive).symlink_to(image.parent, target_is_directory=True)
            (devices / 'e:').symlink_to(prefix / 'missing')
            (devices / 'f:').symlink_to('f:')
            self.assertEqual(windows_path(image, prefix), 'D:\\Image.dll')
            self.assertEqual(host_path(windows_path(image, prefix), prefix).resolve(), image)

    def test_configured_z_drive_is_used_in_both_directions(self):
        with tempfile.TemporaryDirectory(dir=os.environ['EAGLE_TEST_ROOT']) as directory:
            prefix = Path(directory)
            image = prefix / 'mapped/Example/Image.DLL'
            image.parent.mkdir(parents=True)
            image.touch()
            (prefix / 'dosdevices').mkdir()
            (prefix / 'dosdevices/z:').symlink_to(prefix / 'mapped', target_is_directory=True)
            self.assertEqual(windows_path(image, prefix), 'Z:\\Example\\Image.DLL')
            self.assertEqual(host_path('Z:\\example\\image.dll', prefix).resolve(), image)

    def test_provider_dlls_leave_executable_tls_unchanged(self):
        for architecture in ('i386', 'x86_64'):
            for module in ('kernelbase', 'kernel32', 'combase', 'dwrite', 'd2d1', 'ntdll'):
                path = PACKAGE / f'lib/wine/{architecture}-windows/{module}.dll'
                with self.subTest(architecture=architecture, module=module):
                    data = path.read_bytes()
                    self.assertEqual(data[:2], b'MZ')
                    offset = struct.unpack_from('<I', data, 0x3c)[0]
                    self.assertEqual(data[offset:offset + 4], b'PE\0\0')
                    optional = offset + 24
                    magic = struct.unpack_from('<H', data, optional)[0]
                    self.assertIn(magic, (0x10b, 0x20b))
                    directories = optional + (96 if magic == 0x10b else 112)
                    tls = struct.unpack_from('<II', data, directories + 9 * 8)
                    self.assertEqual(tls, (0, 0), 'provider DLL must not allocate compiler TLS before the executable')

    def test_available_commands_match_release_scope(self):
        executable = str(PACKAGE / 'bin/eagle')
        result = subprocess.run([executable, 'capabilities'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)['data']
        self.assertEqual(data['debug_architectures'], ['x86', 'x86_64'])
        self.assertEqual(data['static_analyzer'], 'Soda Eagle native analysis')
        self.assertTrue(data['analysis']['available'])
        result = subprocess.run([executable, '--help'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('trace', result.stdout)
        self.assertIn('analyze', result.stdout)
        self.assertIn('security-scan', result.stdout)

    def test_invalid_paths_leave_backend_responsive(self):
        with subprocess.Popen([str(PACKAGE / 'bin/eagle'), 'serve'], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as process:
            try:
                write_message(process.stdin, {'id': 1, 'method': 'initialize', 'params': {'schema': 1}})
                self.assertTrue(read_message(process.stdout)['result']['analysis']['available'])
                for request_id, method in ((2, 'analyze'), (3, 'security-scan')):
                    write_message(process.stdin, {'id': request_id, 'method': method, 'params': {'path': '/missing'}})
                    response = read_message(process.stdout)
                    self.assertEqual(response['id'], request_id)
                    self.assertEqual(response['error']['code'], -32602)
                write_message(process.stdin, {'id': 4, 'method': 'capabilities'})
                self.assertEqual(read_message(process.stdout)['id'], 4)
                write_message(process.stdin, {'id': 5, 'method': 'shutdown'})
                self.assertEqual(read_message(process.stdout)['id'], 5)
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    def test_both_architecture_identities_match_targets(self):
        for bits, machine in ((32, 0x14c), (64, 0x8664)):
            result = subprocess.run([str(PACKAGE / 'bin/eagle'), 'symbols', str(Path(os.environ['EAGLE_TEST_ROOT']) / f'target{bits}.exe')], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['data']['machine'], machine)


if __name__ == '__main__':
    unittest.main()
