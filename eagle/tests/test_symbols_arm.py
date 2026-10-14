import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import symbols
import session
from protocol import read_message, write_message

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('soda_symbols', ROOT / '.github/soda-symbols.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)
sys.path.remove(str(ROOT / 'eagle'))


class ArmSymbols(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.linker = symbols.host_tool('lld-link')
        cls.elf_linker = symbols.host_tool('ld.lld')
        cls.objcopy = symbols.host_tool('llvm-objcopy')
        cls.nm = symbols.host_tool('llvm-nm')
        cls.resolver = symbols.host_tool('llvm-symbolizer')
        if not shutil.which('clang') or not all((cls.linker, cls.elf_linker, cls.objcopy, cls.nm, cls.resolver)):
            raise unittest.SkipTest('static ARM fixtures require existing Clang and LLVM tools')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.runner = self.root / 'runner'
        self.runner.mkdir()
        self.bundle = self.root / 'symbols'
        self.tools = PACKAGE / 'lib/eagle/native'

    def build(self, name='fixture.exe', elf=False):
        source = self.root / (name + '.c')
        source.write_text('__attribute__((noinline)) int eagle_arm(int value) { return value + 7; }\nint main(void) { return eagle_arm(1); }\n')
        image = self.runner / name
        if elf:
            command = ['clang', '--target=aarch64-linux-gnu', '-g', '-gdwarf-5', '-O2', '-nostdlib', '-static',
                       '-fuse-ld=' + self.elf_linker, '-Wl,--build-id', '-Wl,-e,main', str(source), '-o', str(image)]
        else:
            obj = self.root / (name + '.obj')
            subprocess.run(['clang', '--target=aarch64-w64-windows-gnu', '-g', '-gdwarf-5', '-O2', '-c',
                            str(source), '-o', str(obj)], check=True, capture_output=True, timeout=30)
            command = [self.linker, '/entry:main', '/subsystem:console', '/nodefaultlib', '/debug:dwarf',
                       '/timestamp:0', '/out:' + str(image), str(obj)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        metadata = symbols.image_metadata(image)
        self.assertEqual(metadata['machine'], 183 if elf else 0xaa64)
        listing = subprocess.check_output([self.nm, '-n', str(image)], text=True)
        address = int(next(line.split()[0] for line in listing.splitlines() if line.endswith(' eagle_arm')), 16)
        return image, source, hex(address - int(metadata['image_base'], 0)), metadata

    def test_arm_pe_source_lines_use_the_cross_architecture_resolver(self):
        image, source, rva, _ = self.build()
        frame, = symbols.query(image, rvas=[rva])['resolved']
        self.assertEqual((frame['symbol'], frame['file'], frame['line']), ('eagle_arm', str(source), 1))
        self.assertEqual(frame['resolver'], 'llvm-exact-image')
        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle'), 'symbols', str(image), '--rva', rva],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['data']['resolved'][0], frame)
        requests = [(1, 'initialize', {'schema': 1}),
                    (2, 'symbols', {'path': str(image), 'rvas': [rva]}),
                    (3, 'symbols', {'path': str(image), 'rvas': [True]}),
                    (4, 'symbols', {'path': str(image), 'rvas': [rva]}),
                    (5, 'capabilities', {}), (6, 'shutdown', {})]
        stream = io.BytesIO()
        for request_id, method, params in requests:
            write_message(stream, dict(id=request_id, method=method, params=params))
        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle'), 'serve'],
                                input=stream.getvalue(), capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        stream = io.BytesIO(result.stdout)
        responses = [read_message(stream) for _ in requests]
        self.assertEqual([response['id'] for response in responses], list(range(1, 7)))
        self.assertEqual(responses[1]['result']['resolved'][0], frame)
        self.assertEqual(responses[2]['error']['code'], -32602)
        self.assertEqual(responses[3]['result']['resolved'][0], frame)
        self.assertIn('llvm-symbolizer', responses[4]['result']['symbol_queries']['arm_pe'])

    def test_llvm_stages_arm_elf_and_pe_without_changing_binary_identities(self):
        cases = [self.build(), self.build('fixture-elf', elf=True)]
        expected = {image.name: symbols.query(image, rvas=[rva])['resolved'][0] for image, _, rva, _ in cases}
        result = producer.stage(self.runner, self.bundle, self.tools, 'owned-arm-fixture',
                                required=list(expected), objcopy=self.objcopy)
        self.assertEqual(result['retained'], 2)
        for image, _, rva, before in cases:
            self.assertNotEqual(symbols.query(image, rvas=[rva])['resolved'][0]['status'], 'source-resolved')
            after = symbols.image_metadata(image)
            self.assertEqual(after.get('build_id'), before.get('build_id'))
            self.assertEqual(after.get('timestamp'), before.get('timestamp'))
        shutil.copytree(self.bundle, self.runner, dirs_exist_ok=True)
        for image, _, rva, _ in cases:
            frame, = symbols.query(image, rvas=[rva])['resolved']
            self.assertEqual(frame, expected[image.name])
        self.assertEqual(producer.verify(self.runner, self.bundle, self.tools), result)

    def test_existing_arm_companions_do_not_require_a_host_objcopy(self):
        cases = [self.build(), self.build('fixture-elf', elf=True)]
        before = {}
        for image, _, _, _ in cases:
            debug = image.with_name(image.name + '.debug')
            subprocess.run([self.objcopy, '--only-keep-debug', str(image), str(debug)], check=True, capture_output=True)
            subprocess.run([self.objcopy, '--strip-debug', '--add-gnu-debuglink=' + str(debug), str(image)], check=True, capture_output=True)
            before[image.name] = producer.digest(image)
        result = producer.stage(self.runner, self.bundle, self.tools, 'owned-arm-fixture',
                                required=list(before), objcopy='/nonexistent/objcopy')
        self.assertEqual(result['retained'], 2)
        for image, _, _, _ in cases:
            self.assertEqual(producer.digest(image), before[image.name])
            self.assertEqual(result['images'][image.name]['coverage'], 'dwarf')

    def test_corrupt_arm_companion_does_not_resolve_source_lines(self):
        image, _, rva, _ = self.build()
        result = producer.stage(self.runner, self.bundle, self.tools, 'owned-arm-fixture', objcopy=self.objcopy)
        shutil.copytree(self.bundle, self.runner, dirs_exist_ok=True)
        debug = self.runner / result['images'][image.name]['debug_file']
        with debug.open('ab') as file:
            file.write(b'changed-owned-fixture')
        self.assertNotEqual(symbols.query(image, rvas=[rva])['resolved'][0]['status'], 'source-resolved')

    def test_missing_cross_architecture_tool_is_explicit(self):
        image, _, rva, _ = self.build()
        with patch('symbols.host_tool', return_value=None):
            with self.assertRaisesRegex(ValueError, 'symbol resolver unavailable'):
                symbols.query(image, rvas=[rva])

    def test_frame_limit_applies_before_cross_architecture_tool_selection(self):
        with patch('symbols.image_metadata', side_effect=AssertionError('image must not be read')):
            with self.assertRaisesRegex(ValueError, 'frame limit'):
                symbols.resolve('owned-fixture', ['0x1000'] * 257)

    def test_cross_architecture_response_and_timeout_errors_remain_controlled(self):
        for code, output in [(1, '[]'), (0, '{}'), (0, 'not-json'),
                             (0, '[{"Address":"0x2000","Symbol":[]}]')]:
            with self.subTest(code=code, output=output):
                with patch('symbols.subprocess.run', return_value=subprocess.CompletedProcess([], code, output, 'failure')):
                    with self.assertRaisesRegex(ValueError, 'source resolver failed'):
                        symbols.resolve_llvm('owned-fixture', ['0x1000'], self.resolver, 'llvm-exact-image')
        with patch('symbols.subprocess.run', side_effect=subprocess.TimeoutExpired('llvm-symbolizer', 10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                symbols.resolve_llvm('owned-fixture', ['0x1000'], self.resolver, 'llvm-exact-image')


if __name__ == '__main__':
    unittest.main()
