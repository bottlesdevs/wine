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
from protocol import read_message, write_message

SOURCE = '#ifdef _MSC_VER\n#define INLINE __forceinline\n#define NOINLINE __declspec(noinline)\n#else\n#define INLINE inline __attribute__((always_inline))\n#define NOINLINE __attribute__((noinline))\n#endif\nvolatile int bias = 1;\nstatic INLINE int leaf(int n)\n{\n    return n * 3 + bias;\n}\nstatic INLINE int middle(int n)\n{\n    return leaf(n) + 7;\n}\nNOINLINE int outer(int n)\n{\n    return middle(n) * 5;\n}\nint main(int argc, char **argv) { (void)argv; return outer(argc); }\nint entry(void) { return outer(3); }\n'


class InlineSymbols(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = symbols.host_tool('llvm-symbolizer')
        cls.dwp = symbols.host_tool('llvm-dwp')
        cls.linker = symbols.host_tool('lld-link')
        if not all((cls.tool, cls.dwp, cls.linker, shutil.which('clang-cl'), shutil.which('clang'), shutil.which('gcc'))):
            raise unittest.SkipTest('inline fixtures require existing GCC,Clang,LLVM tools')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.expected_lines = {}

    def build(self, compiler='gcc', version=5, pie=True, split=False, target='x86_64'):
        root = self.root / str(len(list(self.root.iterdir())))
        root.mkdir()
        source = root / 'fixture.c'
        source.write_text(SOURCE)
        pdb = None
        if compiler == 'pdb':
            image, obj, pdb = [root / name for name in ('module.exe', 'fixture.obj', 'fixture.pdb')]
            subprocess.run(['clang-cl', '--target=' + target + '-pc-windows-msvc', '/nologo', '/O2', '/Ob3', '/Z7', '/GS-',
                            '/c', str(source), '/Fo' + str(obj)], check=True, capture_output=True, timeout=30)
            subprocess.run([self.linker, '/nologo', '/entry:entry', '/subsystem:console', '/nodefaultlib', '/debug',
                            '/opt:noref', '/opt:noicf', '/pdb:' + str(pdb), '/pdbaltpath:fixture.pdb', '/out:' + str(image), str(obj)],
                           check=True, capture_output=True, timeout=30)
            metadata = symbols.image_metadata(image)
            entry = int(metadata['entry_rva'], 0) if isinstance(metadata['entry_rva'], str) else metadata['entry_rva']
            addresses = [hex(value) for value in range(max(0, entry - 64), entry + 64) if target != 'aarch64' or value % 4 == 0]
        else:
            pe = 'mingw32' in compiler
            image = root / ('module.exe' if pe else 'module')
            flags = [] if pe else ['-fPIE', '-pie'] if pie else ['-fno-pie', '-no-pie']
            if split:
                flags.append('-gsplit-dwarf')
            subprocess.run([compiler, '-O2', '-g', '-gdwarf-' + str(version), *flags, str(source), '-o', str(image)],
                           check=True, capture_output=True, timeout=30)
            nm = compiler.removesuffix('gcc') + 'nm' if pe else 'nm'
            text = subprocess.check_output([nm, '-n', str(image)], text=True)
            address = int(next(line.split()[0] for line in text.splitlines() if line.split()[-1].lstrip('_') == 'outer'), 16)
            metadata = symbols.image_metadata(image)
            if pe:
                address -= int(metadata['image_base'], 0)
            addresses = [hex(address + value) for value in range(32)]
        result = subprocess.run([self.tool, '--obj=' + str(image), '--relative-address', '--output-style=JSON', '--no-debuginfod', *addresses],
                                capture_output=True, text=True, timeout=20,
                                env={key: value for key, value in os.environ.items() if key != 'LLVM_SYMBOLIZER_OPTS'})
        self.assertEqual(result.returncode, 0, result.stderr)
        selected = max(json.loads(result.stdout), key=lambda row: len(row['Symbol']))
        self.assertEqual([frame['FunctionName'] for frame in selected['Symbol']], ['leaf', 'middle', 'outer'])
        address = int(selected['Address'], 0)
        rva = address - int(metadata['image_base'], 0) if metadata.get('format') == 'ELF' else address
        self.expected_lines[image] = [11, 15, 18 if compiler == 'pdb' and target == 'i686' else 19]
        return image, pdb, source, hex(rva)

    def check(self, image, pdb, source, rva, **options):
        plain = symbols.query(image, pdb=str(pdb) if pdb else None, rvas=[rva])
        result = symbols.query(image, pdb=str(pdb) if pdb else None, rvas=[rva], inlines=True, **options)
        frame, = result['resolved']
        self.assertEqual(result['inline_order'], 'innermost-to-outermost')
        self.assertEqual(frame['inline_status'], 'available', frame)
        self.assertEqual([value['symbol'] for value in frame['inline_frames']], ['leaf', 'middle', 'outer'])
        self.assertEqual([value['line'] for value in frame['inline_frames']], self.expected_lines[image])
        self.assertEqual([value['inlined'] for value in frame['inline_frames']], [True, True, False])
        self.assertTrue(all(value['file'] == str(source) and value['status'] == 'source-resolved' for value in frame['inline_frames']))
        stripped = {key: value for key, value in frame.items() if key not in ('inline_frames', 'inline_status', 'inline_reason')}
        self.assertEqual(stripped, plain['resolved'][0])
        return result

    def test_optimized_elf_versions_compilers_and_image_bases(self):
        for compiler in ('gcc', 'clang'):
            for version in (4, 5):
                for pie in (False, True):
                    with self.subTest(compiler=compiler, version=version, pie=pie):
                        self.check(*self.build(compiler, version, pie))

    def test_separate_and_compressed_dwarf_use_the_matching_debug_file(self):
        for compressed in (None, 'zlib', 'zlib-gnu'):
            image, pdb, source, rva = self.build()
            debug = image.parent / '.debug/module.debug'
            debug.parent.mkdir()
            subprocess.run(['objcopy', '--only-keep-debug', str(image), str(debug)], check=True, capture_output=True)
            if compressed:
                subprocess.run(['objcopy', '--compress-debug-sections=' + compressed, str(debug)], check=True, capture_output=True)
            subprocess.run(['objcopy', '--strip-unneeded', '--add-gnu-debuglink=' + str(debug), str(image)], check=True, capture_output=True)
            self.check(image, pdb, source, rva)

    def test_split_archive_relocation_and_missing_companion_are_distinct(self):
        self.split_archive('gcc', 4)

    def test_clang_dwarf5_split_archive(self):
        self.split_archive('clang', 5)

    def split_archive(self, compiler, version):
        image, pdb, source, rva = self.build(compiler, version, split=True)
        original = image.parent
        runner = self.root / 'runner'
        (runner / 'bin').mkdir(parents=True)
        target = runner / 'bin/module'
        shutil.copyfile(image, target)
        self.expected_lines[target] = self.expected_lines[image]
        repo = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location('soda_symbols_inline', repo / '.github/soda-symbols.py')
        producer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(producer)
        bundle = self.root / 'bundle'
        producer.stage(runner, bundle, PACKAGE / 'lib/eagle/native', 'owned-inline', ['bin/module'], debug_roots=[original])
        shutil.copytree(bundle, runner, dirs_exist_ok=True)
        shutil.rmtree(original)
        result = self.check(target, pdb, source, rva, artifacts=True)
        self.assertEqual(result['split_dwarf']['status'], 'matched')
        package = runner / 'bin/.debug/module.debug.dwp'
        package.rename(package.with_suffix('.held'))
        result = symbols.query(target, rvas=[rva], inlines=True, artifacts=True)
        self.assertEqual(result['split_dwarf']['status'], 'incomplete')
        self.assertIn(result['resolved'][0]['inline_status'], ('not-reported', 'unavailable'))
        self.assertLessEqual(len(result['resolved'][0]['inline_frames']), 1)

    def test_pe_dwarf_both_architectures_and_versions(self):
        for architecture in ('i686', 'x86_64'):
            for version in (4, 5):
                with self.subTest(architecture=architecture, version=version):
                    self.check(*self.build(architecture + '-w64-mingw32-gcc', version))

    def test_matched_pdb_chains_on_static_pe_architectures(self):
        for target in ('i686', 'x86_64', 'aarch64'):
            with self.subTest(target=target):
                image, pdb, source, rva = self.build('pdb', target=target)
                before = image.read_bytes(), pdb.read_bytes()
                self.check(image, pdb, source, rva)
                self.assertEqual(before, (image.read_bytes(), pdb.read_bytes()))

    def test_missing_tool_preserves_default_result_with_an_explicit_inline_reason(self):
        image, pdb, source, rva = self.build()
        with patch.object(symbols, 'host_tool', return_value=None):
            plain = symbols.query(image, rvas=[rva])
            result = symbols.query(image, rvas=[rva], inlines=True)
        frame, = result['resolved']
        self.assertEqual(frame['inline_status'], 'unavailable')
        self.assertIn('llvm-symbolizer', frame['inline_reason'])
        self.assertEqual({key: value for key, value in frame.items() if not key.startswith('inline_')}, plain['resolved'][0])

    def test_wrong_gnu_debug_crc_and_wrong_pdb_do_not_supply_inline_contexts(self):
        image, _, source, rva = self.build()
        debug = image.parent / 'module.debug'
        subprocess.run(['objcopy', '--only-keep-debug', str(image), str(debug)], check=True, capture_output=True)
        subprocess.run(['objcopy', '--strip-unneeded', '--add-gnu-debuglink=' + str(debug), str(image)], check=True, capture_output=True)
        with debug.open('ab') as file:
            file.write(b'owned-corruption')
        frame, = symbols.query(image, rvas=[rva], inlines=True)['resolved']
        self.assertEqual(frame['inline_status'], 'unavailable')
        self.assertIn('CRC', frame['inline_reason'])
        image, pdb, _, rva = self.build('pdb')
        _, wrong, _, _ = self.build('pdb')
        with self.assertRaisesRegex(ValueError, 'GUID or age'):
            symbols.query(image, pdb=str(wrong), rvas=[rva], inlines=True)
        result = symbols.query(image, rvas=[rva], inlines=True)
        self.assertEqual(result['resolved'][0]['inline_status'], 'unavailable')
        self.assertIn('selected matching PDB', result['resolved'][0]['inline_reason'])

    def test_malformed_or_excessive_inline_frames_are_rejected(self):
        frame = {'FunctionName': 'owned', 'FileName': 'fixture.c', 'Line': 1, 'Column': 1}
        cases = [[], [frame] * 65, [dict(frame, Line=True)], [dict(frame, Column=-1)], [dict(frame, FunctionName=[])]]
        for frames in cases:
            response = subprocess.CompletedProcess([], 0, json.dumps([{'Address': '0x1000', 'Symbol': frames}]), '')
            with self.subTest(count=len(frames)), patch.object(symbols, 'inline_output', return_value=response):
                with self.assertRaisesRegex(ValueError, 'inline source resolver failed'):
                    symbols.resolve_llvm('owned-image', ['0x1000'], self.tool, 'owned', inlines=True)

    def test_inline_output_limit_and_timeout_reap_the_owned_tool(self):
        for mode in ('large', 'timeout'):
            tool = self.root / ('tool-' + mode)
            pid = self.root / ('pid-' + mode)
            tool.write_text('#!' + sys.executable + '\nimport os,sys,time\nfrom pathlib import Path\n' +
                            'Path(' + repr(str(pid)) + ').write_text(str(os.getpid()))\n' +
                            ('for _ in range(257): sys.stdout.buffer.write(b"x"*65536);sys.stdout.buffer.flush()\n' if mode == 'large' else '') +
                            'while True: time.sleep(1)\n')
            tool.chmod(0o700)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                symbols.inline_output([str(tool)], dict(os.environ))
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid.read_text()), 0)

    def test_inline_artifact_changes_during_resolution_are_unavailable(self):
        image, _, source, rva = self.build()
        debug = image.parent / 'module.debug'
        subprocess.run(['objcopy', '--only-keep-debug', str(image), str(debug)], check=True, capture_output=True)
        subprocess.run(['objcopy', '--strip-unneeded', '--add-gnu-debuglink=' + str(debug), str(image)], check=True, capture_output=True)
        original = symbols.resolve_llvm
        def changed(*arguments, **options):
            result = original(*arguments, **options)
            if options.get('inlines'):
                with debug.open('ab') as file:
                    file.write(b'owned-concurrent-change')
            return result
        with patch.object(symbols, 'resolve_llvm', side_effect=changed):
            frame, = symbols.query(image, rvas=[rva], inlines=True)['resolved']
        self.assertEqual(frame['inline_status'], 'unavailable')
        self.assertIn('changed', frame['inline_reason'])
        self.assertFalse(frame['inline_frames'])

    def test_cli_backend_and_invalid_inline_flag_recovery(self):
        image, _, source, rva = self.build()
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        cli = subprocess.run([*command, 'symbols', str(image), '--rva', rva, '--inlines'], capture_output=True, text=True, timeout=25)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        expected = json.loads(cli.stdout)['data']
        for options in [{'inlines': 'yes', 'rvas': [rva]}, {'inlines': True}]:
            with self.assertRaises(ValueError):
                symbols.query(image, **options)
        requests = [(1, 'initialize', {'schema': 1}), (2, 'symbols', {'path': str(image), 'rvas': [rva], 'inlines': True}),
                    (3, 'symbols', {'path': str(image), 'rvas': [rva], 'inlines': 'invalid'}),
                    (4, 'symbols', {'path': str(image), 'rvas': [rva], 'inlines': True}), (5, 'shutdown', {})]
        stream = io.BytesIO()
        for i, method, params in requests:
            write_message(stream, dict(id=i, method=method, params=params))
        process = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        stream = io.BytesIO(process.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertEqual(replies[1]['result'], expected)
        self.assertEqual(replies[3]['result'], expected)
        self.assertEqual(replies[2]['error']['code'], -32602)


if __name__ == '__main__':
    unittest.main()
