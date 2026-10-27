import io
import json
import os
from pathlib import Path
import struct
import shutil
import subprocess
import sys
import tempfile
import unittest


PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import symbols
from protocol import read_message, write_message


class ExportSymbols(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def build(self, architecture, stripped=True):
        root = self.root / (architecture + str(stripped))
        root.mkdir()
        source = root / 'fixture.c'
        source.write_text('__declspec(dllexport) __declspec(noinline) int eagle_export_add(int value)\n'
                          '{\n    return value + 7;\n}\n'
                          'int eagle_ordinal(void) { return 31; }\n'
                          '__declspec(dllexport) int eagle_export_second(void) { return 19; }\n'
                          '__declspec(dllexport) int eagle_data = 11;\n')
        definition = root / 'fixture.def'
        definition.write_text('EXPORTS\n z_eagle_alias=eagle_export_add\n'
                              ' eagle_forwarded=KERNEL32.Sleep\n eagle_ordinal @17 NONAME\n')
        image = root / 'fixture.dll'
        prefix = architecture + '-w64-mingw32-'
        subprocess.run([prefix + 'gcc', '-shared', '-O0', '-g', str(source), str(definition), '-o', str(image)],
                       check=True, capture_output=True, timeout=30)
        metadata = symbols.image_metadata(image)
        listing = subprocess.check_output([prefix + 'nm', '-n', str(image)], text=True)
        addresses = {}
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[2].lstrip('_').startswith('eagle_'):
                addresses[fields[2].lstrip('_')] = int(fields[0], 16) - int(metadata['image_base'], 0)
        if stripped:
            subprocess.run([prefix + 'objcopy', '--strip-all', str(image)], check=True, capture_output=True)
        return image, source, addresses

    def test_stripped_exports_resolve_at_entry_and_inside_on_both_architectures(self):
        for architecture in ('i686', 'x86_64'):
            with self.subTest(architecture=architecture):
                image, _, addresses = self.build(architecture)
                start = addresses['eagle_export_add']
                frames = symbols.query(image, rvas=[start, start+1])['resolved']
                for displacement, frame in enumerate(frames):
                    self.assertEqual(frame['symbol'], 'eagle_export_add')
                    self.assertEqual(frame['resolver'], 'pe-export')
                    self.assertEqual(frame['displacement'], displacement)
                    self.assertEqual(frame['export_rva'], hex(start))
                    self.assertEqual(frame['status'], 'symbol-only')
                    self.assertIsNone(frame['source'])
                    self.assertNotIn('file', frame)
                    self.assertIn('function extent unavailable', frame['symbol_scope'])

    def test_data_headers_and_unnamed_exports_have_no_function_label(self):
        for architecture in ('i686', 'x86_64'):
            image, _, addresses = self.build(architecture)
            frames = symbols.query(image, rvas=[0, addresses['eagle_data'], addresses['eagle_ordinal']])['resolved']
            self.assertTrue(all(frame['symbol'] is None for frame in frames), frames)

    def test_forwarders_and_aliases_do_not_create_ambiguous_ranges(self):
        image, _, addresses = self.build('x86_64')
        tool = PACKAGE / 'lib/eagle/native/eagle-pe'
        entries = json.loads(subprocess.check_output([str(tool), '--exports', str(image)], text=True))['exports']
        names = [entry['name'] for entry in entries]
        self.assertNotIn('eagle_forwarded', names)
        self.assertNotIn('eagle_data', names)
        self.assertNotIn('z_eagle_alias', names)
        self.assertEqual(names.count('eagle_export_add'), 1)
        entry = next(value for value in entries if value['name'] == 'eagle_export_add')
        self.assertLessEqual(entry['end'], addresses['eagle_ordinal'])

    def test_private_debug_symbols_keep_their_source_and_resolver(self):
        image, source, addresses = self.build('x86_64', stripped=False)
        frame, = symbols.query(image, rvas=[addresses['eagle_export_add']])['resolved']
        self.assertEqual((frame['symbol'], frame['file'], frame['line']), ('eagle_export_add', str(source), 2))
        self.assertEqual(frame['resolver'], 'binutils-exact-image')
        self.assertNotIn('export_rva', frame)

    def test_non_utf8_export_names_do_not_break_existing_unresolved_queries(self):
        image, _, _ = self.build('x86_64')
        data = bytearray(image.read_bytes())
        offset = data.index(b'eagle_export_add\0')
        data[offset] = 0xff
        image.write_bytes(data)
        frame, = symbols.query(image, rvas=[0])['resolved']
        self.assertIsNone(frame['symbol'])

    def test_export_count_and_ordinal_limits_are_checked(self):
        image, _, _ = self.build('x86_64')
        original = image.read_bytes()
        pe = struct.unpack_from('<I', original, 0x3c)[0]
        optional = pe+24
        export = struct.unpack_from('<I', original, optional+112)[0]
        sections = optional+struct.unpack_from('<H', original, pe+20)[0]
        def offset(rva):
            for index in range(struct.unpack_from('<H', original, pe+6)[0]):
                section = sections+index*40
                address, size, raw = struct.unpack_from('<III', original, section+12)
                if address <= rva < address+size:
                    return raw+rva-address
            self.fail('owned fixture RVA has no section')
        table = offset(export)
        ordinal = offset(struct.unpack_from('<I', original, table+36)[0])
        for position, format, value in [(table+20, '<I', 65537), (table+24, '<I', 65537),
                                        (table+28, '<I', 0xffffffff), (ordinal, '<H', 0xffff)]:
            with self.subTest(position=position):
                data = bytearray(original)
                struct.pack_into(format, data, position, value)
                image.write_bytes(data)
                result = subprocess.run([str(PACKAGE / 'lib/eagle/native/eagle-pe'), '--exports', str(image)],
                                        capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)

    def test_invalid_export_directory_is_rejected_without_changing_identity_queries(self):
        image, _, _ = self.build('x86_64')
        data = bytearray(image.read_bytes())
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        struct.pack_into('<I', data, pe+24+112, 0xffffffff)
        image.write_bytes(data)
        result = subprocess.run([str(PACKAGE / 'lib/eagle/native/eagle-pe'), '--exports', str(image)],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid export directory', result.stderr)
        self.assertEqual(symbols.image_metadata(image)['machine'], 0x8664)

    def test_arm_export_lookup_does_not_require_private_debug_information(self):
        linker = symbols.host_tool('lld-link')
        if not shutil.which('clang') or not linker:
            self.skipTest('static ARM fixture requires Clang and LLD')
        source = self.root / 'arm.c'
        source.write_text('__declspec(dllexport) int eagle_export_add(int value) { return value + 7; }\n')
        obj, image = self.root / 'arm.obj', self.root / 'arm.dll'
        subprocess.run(['clang', '--target=aarch64-w64-windows-gnu', '-O0', '-c', str(source), '-o', str(obj)],
                       check=True, capture_output=True, timeout=20)
        subprocess.run([linker, '/dll', '/noentry', '/nodefaultlib', '/out:' + str(image), str(obj)],
                       check=True, capture_output=True, timeout=20)
        frame, = symbols.query(image, rvas=['0x1001'])['resolved']
        self.assertEqual((frame['symbol'], frame['displacement']), ('eagle_export_add', 1))
        self.assertEqual(frame['resolver'], 'pe-export')

    def test_cli_and_backend_return_the_same_export_label(self):
        image, _, addresses = self.build('x86_64')
        offset = hex(addresses['eagle_export_add']+1)
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        result = subprocess.run([*command, 'symbols', str(image), '--rva', offset], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = json.loads(result.stdout)['data']
        stream = io.BytesIO()
        for request_id, method, params in [(1, 'initialize', {'schema':1}),
                                          (2, 'symbols', {'path':str(image), 'rvas':[offset]}),
                                          (3, 'shutdown', {})]:
            write_message(stream, dict(id=request_id, method=method, params=params))
        result = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = io.BytesIO(result.stdout)
        read_message(replies)
        self.assertEqual(read_message(replies)['result'], expected)
        self.assertEqual(expected['resolved'][0]['symbol'], 'eagle_export_add')


if __name__ == '__main__':
    unittest.main(verbosity=2)
