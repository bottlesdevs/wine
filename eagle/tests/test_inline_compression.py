import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zlib

import test_inline_packages as packages
import dwarf
import symbols
from protocol import read_message, write_message

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])


class InlineCompression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        packages.InlinePackages.setUpClass()
        cls.objcopy = symbols.host_tool('llvm-objcopy')
        cls.linker = symbols.host_tool('ld.lld')
        if not cls.objcopy or not cls.linker:
            raise unittest.SkipTest('compression fixtures require existing LLVM objcopy/linker')

    def setUp(self):
        self.fixture = packages.InlinePackages()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        before = set(Path(tempfile.gettempdir()).glob('eagle-inlines-*'))
        self.addCleanup(lambda: self.assertEqual(set(Path(tempfile.gettempdir()).glob('eagle-inlines-*')), before))

    def compress(self, image, detached=False):
        selected = image
        if detached:
            selected = image.parent / '.debug/module.debug'
            selected.parent.mkdir()
            subprocess.run(['objcopy', '--only-keep-debug', str(image), str(selected)], check=True, capture_output=True)
        subprocess.run(['objcopy', '--compress-debug-sections=zlib-gnu', str(selected)], check=True, capture_output=True)
        if detached:
            subprocess.run(['objcopy', '--strip-unneeded', '--add-gnu-debuglink=' + str(selected), str(image)], check=True, capture_output=True)
        return selected

    def check(self, image, selected, rva, files=None):
        before = image.read_bytes(), selected.read_bytes()
        result = symbols.query(image, rvas=[rva], inlines=True, debug_files=files)
        frame, = result['resolved']
        self.assertEqual(frame['inline_status'], 'available', frame)
        self.assertEqual([value['symbol'] for value in frame['inline_frames']], ['leaf', 'middle', 'outer'])
        normalized = result['inline_debug_image']
        self.assertEqual(normalized['path'], str(selected))
        self.assertEqual(normalized['sha256'], hashlib.sha256(before[1]).hexdigest())
        self.assertNotEqual(normalized['sha256'], normalized['normalized_sha256'])
        self.assertEqual(before, (image.read_bytes(), selected.read_bytes()))
        plain = symbols.query(image, rvas=[rva])
        self.assertEqual({key: value for key, value in frame.items() if not key.startswith('inline_')}, plain['resolved'][0])
        return result

    def test_gcc_clang_dwarf4_and5_embedded_and_crc_selected_debug_images(self):
        for compiler in ('gcc', 'clang'):
            for version in (4, 5):
                for detached in (False, True):
                    with self.subTest(compiler=compiler, version=version, detached=detached):
                        image, _, source, rva = self.fixture.fixture.build(compiler, version)
                        selected = self.compress(image, detached)
                        result = self.check(image, selected, rva)
                        self.assertEqual([value['line'] for value in result['resolved'][0]['inline_frames']], [11, 15, 19])
                        self.assertTrue(all(value['file'] == str(source) for value in result['resolved'][0]['inline_frames']))

    def test_compressed_split_images_keep_explicit_dwp_and_dwo_selection(self):
        for kind in ('dwp', 'dwo', 'adjacent', 'detached'):
            image, package, source, rva = self.fixture.build(remove=False)
            if kind == 'dwo':
                package = image.parent / 'reviewed.dwo'
                shutil.copyfile(next(source.parent.glob('*.dwo')), package)
            shutil.rmtree(source.parent)
            selected = self.compress(image, detached=kind == 'detached')
            files = [str(package)]
            if kind in ('adjacent', 'detached'):
                package.rename(Path(str(selected) + '.dwp'))
                files = None
            result = self.check(image, selected, rva, files=files)
            self.assertEqual(result['inline_artifacts']['status'], 'matched')
            self.assertEqual('inputs' in result['inline_artifacts'], kind == 'dwo')

    def test_arm64_compiler_debug_sections_use_the_same_lossless_conversion(self):
        self.cross_compression('aarch64', 183)

    def test_elf32_compiler_debug_sections_use_the_same_lossless_conversion(self):
        self.cross_compression('i386', 3)

    def cross_compression(self, architecture, machine):
        source = self.root / 'fixture.c'
        source.write_text(packages.fixtures.SOURCE)
        obj = self.root / 'fixture.o'
        image = self.root / 'module'
        subprocess.run(['clang', '--target=' + architecture + '-linux-gnu', '-O2', '-g', '-gdwarf-5', '-c', str(source), '-o', str(obj)],
                       check=True, capture_output=True, timeout=20)
        subprocess.run([self.linker, '-e', 'entry', str(obj), '-o', str(image)], check=True, capture_output=True, timeout=20)
        listing = subprocess.check_output([symbols.host_tool('llvm-nm'), '-n', str(image)], text=True)
        address = int(next(line.split()[0] for line in listing.splitlines() if line.endswith(' outer')), 16)
        metadata = symbols.image_metadata(image)
        self.assertEqual(metadata['machine'], machine)
        raw = subprocess.check_output([symbols.host_tool('llvm-symbolizer'), '--obj=' + str(image), '--output-style=JSON',
                                       '--no-debuginfod', *[hex(address + offset) for offset in range(32)]], text=True,
                                      env={key: value for key, value in os.environ.items() if key != 'LLVM_SYMBOLIZER_OPTS'})
        chosen = max(json.loads(raw), key=lambda row: len(row['Symbol']))
        rva = hex(int(chosen['Address'], 0) - int(metadata['image_base'], 0))
        expected = symbols.query(image, rvas=[rva], inlines=True)['resolved'][0]['inline_frames']
        text = subprocess.check_output(['readelf', '-SW', str(image)], text=True)
        names = re.findall(r'\[\s*\d+\] (\.debug_[A-Za-z0-9_]+)\s', text)
        self.assertTrue(names)
        arguments = []
        for index, name in enumerate(names):
            raw = self.root / ('raw-' + str(index))
            subprocess.run([self.objcopy, '--dump-section=' + name + '=' + str(raw), str(image)], check=True, capture_output=True)
            content = raw.read_bytes()
            raw.write_bytes(b'ZLIB' + len(content).to_bytes(8, 'big') + zlib.compress(content))
            arguments.extend(['--update-section=' + name + '=' + str(raw), '--rename-section=' + name + '=.zdebug_' + name[7:]])
        subprocess.run([self.objcopy, *arguments, str(image)], check=True, capture_output=True)
        result = self.check(image, image, rva)
        self.assertEqual(result['resolved'][0]['inline_frames'], expected)

    def test_standard_zlib_and_uncompressed_images_need_no_normalization_tool(self):
        for compressed in (False, True):
            image, _, _, rva = self.fixture.fixture.build()
            if compressed:
                subprocess.run(['objcopy', '--compress-debug-sections=zlib', str(image)], check=True, capture_output=True)
            tool = symbols.host_tool
            with patch.object(symbols, 'host_tool', side_effect=lambda name: None if name in ('llvm-objcopy', 'objcopy') else tool(name)):
                result = symbols.query(image, rvas=[rva], inlines=True)
            self.assertEqual(result['resolved'][0]['inline_status'], 'available')
            self.assertNotIn('inline_debug_image', result)

    def test_missing_normalizer_is_explicit_and_default_lookup_unchanged(self):
        image, _, _, rva = self.fixture.fixture.build()
        self.compress(image)
        plain = symbols.query(image, rvas=[rva])
        tool = symbols.host_tool
        with patch.object(symbols, 'host_tool', side_effect=lambda name: None if name in ('llvm-objcopy', 'objcopy') else tool(name)):
            result = symbols.query(image, rvas=[rva], inlines=True)
        frame, = result['resolved']
        self.assertEqual(frame['inline_status'], 'unavailable')
        self.assertIn('objcopy', frame['inline_reason'])
        self.assertEqual({key: value for key, value in frame.items() if not key.startswith('inline_')}, plain['resolved'][0])
        self.assertNotIn('inline_debug_image', result)

    def test_invalid_compressed_stream_and_declared_size_are_rejected(self):
        image, _, _, _ = self.fixture.fixture.build()
        self.compress(image)
        helper = PACKAGE / 'lib/eagle/native/eagle-elf'
        metadata = json.loads(subprocess.check_output([str(helper), '--debug-compression', str(image)], text=True))
        section = metadata['sections'][0]
        original = image.read_bytes()
        for mode in ('header', 'size', 'stream'):
            data = bytearray(original)
            offset = section['offset']
            if mode == 'header':
                data[offset:offset + 4] = b'NOPE'
            elif mode == 'size':
                data[offset + 4:offset + 12] = (256 * 1024 * 1024 + 1).to_bytes(8, 'big')
            else:
                data[offset + 12] ^= 0xff
            image.write_bytes(data)
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    dwarf.normalize_debug_image(image, directory, time.monotonic() + 20, helper)
        image.write_bytes(original)

    def test_original_debug_image_change_discards_normalized_chain(self):
        image, _, _, rva = self.fixture.fixture.build()
        self.compress(image)
        original = symbols.resolve_llvm
        def changed(*arguments, **options):
            result = original(*arguments, **options)
            if options.get('inlines'):
                with image.open('ab') as file:
                    file.write(b'owned-concurrent-change')
            return result
        with patch.object(symbols, 'resolve_llvm', side_effect=changed):
            result = symbols.query(image, rvas=[rva], inlines=True)
        self.assertEqual(result['resolved'][0]['inline_status'], 'unavailable')
        self.assertFalse(result['resolved'][0]['inline_frames'])
        self.assertNotIn('inline_debug_image', result)

    def test_cli_backend_normalization_identity_matches(self):
        image, _, _, rva = self.fixture.fixture.build()
        self.compress(image, detached=True)
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        cli = subprocess.run([*command, 'symbols', str(image), '--rva', rva, '--inlines'], capture_output=True, text=True, timeout=30)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        expected = json.loads(cli.stdout)['data']
        stream = io.BytesIO()
        for i, method, params in [(1, 'initialize', {'schema': 1}), (2, 'symbols', {'path': str(image), 'rvas': [rva], 'inlines': True}), (3, 'shutdown', {})]:
            write_message(stream, dict(id=i, method=method, params=params))
        result = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        stream = io.BytesIO(result.stdout)
        read_message(stream)
        self.assertEqual(read_message(stream)['result'], expected)


if __name__ == '__main__':
    unittest.main()
