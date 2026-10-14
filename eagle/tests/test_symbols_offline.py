import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
sys.path.insert(0, str(PACKAGE))
from protocol import read_message, write_message
from session import identity
import symbols


class OfflineSymbols(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def build(self, name, dwarf=5, mode='embedded', pie=False, constant=7):
        root = self.root / name
        root.mkdir()
        source = root / 'fixture.c'
        source.write_text('int eagle_fixture(int value)\n{\n    return value + ' + str(constant) + ';\n}\nint main(void) { return eagle_fixture(1); }\n')
        image = root / 'fixture'
        command = ['gcc', '-O0', '-g', '-gdwarf-' + str(dwarf)]
        command += ['-fPIE', '-pie'] if pie else ['-fno-pie', '-no-pie']
        if mode == 'split':
            command.append('-gsplit-dwarf')
        subprocess.run([*command, str(source), '-o', str(image)], check=True, capture_output=True)
        if mode == 'separate':
            subprocess.run(['objcopy', '--only-keep-debug', str(image), str(root / 'fixture.debug')], check=True, capture_output=True)
            subprocess.run(['objcopy', '--strip-debug', str(image)], check=True, capture_output=True)
            subprocess.run(['objcopy', '--add-gnu-debuglink=' + str(root / 'fixture.debug'), str(image)], check=True, capture_output=True)
        listing = subprocess.check_output(['nm', '-n', str(image)], text=True)
        address = int(next(line.split()[0] for line in listing.splitlines() if line.endswith(' eagle_fixture')), 16)
        metadata = identity(image)
        return image, source, hex(address - int(metadata['image_base'], 0)), metadata

    def cli(self, image, *arguments):
        return subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'symbols', str(image), *arguments],
                              capture_output=True, text=True, timeout=10)

    def test_existing_identity_response_is_unchanged(self):
        image, source, rva, metadata = self.build('identity')
        result = self.cli(image)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['data'], metadata)

    def test_source_queries_cover_dwarf_layouts_and_pie(self):
        for dwarf in (4, 5):
            for mode in ('embedded', 'separate', 'split'):
                for pie in (False, True):
                    with self.subTest(dwarf=dwarf, mode=mode, pie=pie):
                        image, source, rva, metadata = self.build(f'{dwarf}-{mode}-{pie}', dwarf, mode, pie)
                        result = self.cli(image, '--rva', rva)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        data = json.loads(result.stdout)['data']
                        frame, = data.pop('resolved')
                        self.assertEqual(data, metadata)
                        self.assertEqual(frame['rva'], rva)
                        self.assertEqual(frame['symbol'], 'eagle_fixture')
                        self.assertEqual(frame['file'], str(source))
                        self.assertEqual(frame['line'], 2)
                        self.assertEqual(frame['status'], 'source-resolved')

    def test_missing_or_mismatched_debug_file_is_symbol_only(self):
        image, source, rva, metadata = self.build('separate', mode='separate')
        other, _, _, _ = self.build('different', mode='separate', constant=19)
        debug = image.parent / 'fixture.debug'
        original = debug.read_bytes()
        for label, content in [('missing', None), ('truncated', b'own fixture'),
                               ('mismatched', (other.parent / 'fixture.debug').read_bytes())]:
            with self.subTest(state=label):
                debug.unlink(missing_ok=True)
                if content is not None:
                    debug.write_bytes(content)
                result = self.cli(image, '--rva', rva)
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads(result.stdout)['data']
                frame, = data['resolved']
                self.assertEqual(data['sha256'], metadata['sha256'])
                self.assertEqual(frame['symbol'], 'eagle_fixture')
                self.assertIsNone(frame['source'])
                self.assertNotIn('file', frame)
                self.assertEqual(frame['status'], 'symbol-only')
        debug.write_bytes(original)

    def test_unknown_address_is_reported_without_a_symbol(self):
        image, _, _, _ = self.build('unknown')
        result = self.cli(image, '--rva', '0')
        self.assertEqual(result.returncode, 0, result.stderr)
        frame, = json.loads(result.stdout)['data']['resolved']
        self.assertIsNone(frame['symbol'])
        self.assertIsNone(frame['source'])
        self.assertEqual(frame['status'], 'unresolved')

    def test_invalid_addresses_return_structured_errors(self):
        image, _, _, metadata = self.build('invalid')
        for values in [('-1',), (str(metadata['size']),), ('not-an-address',), ('0',) * 257]:
            with self.subTest(values=values[:2]):
                args = [item for value in values for item in ('--rva', value)]
                result = self.cli(image, *args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertFalse(json.loads(result.stderr)['status'])

    def test_missing_resolver_is_an_explicit_failure(self):
        image, _, rva, _ = self.build('no-tool')
        with patch('symbols.shutil.which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'resolver unavailable or failed'):
                symbols.query(image, rvas=[rva])

    def test_pdb_inputs_are_regular_files(self):
        fifo = self.root / 'fixture.pdb'
        os.mkfifo(fifo)
        link = self.root / 'linked.pdb'
        link.symlink_to(fifo)
        code = 'import sys;sys.path.insert(0,sys.argv[1]);from symbols import pdb_identity;pdb_identity(sys.argv[2])'
        for path in (fifo, link, self.root):
            with self.subTest(path=path.name):
                result = subprocess.run([sys.executable, '-S', '-c', code, str(PACKAGE), str(path)],
                                        capture_output=True, text=True, timeout=2)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('PDB must be a regular file', result.stderr)

    def test_stdio_matches_cli_and_recovers_from_invalid_queries(self):
        image, _, rva, metadata = self.build('backend', mode='separate')
        expected = self.cli(image, '--rva', rva, '--rva', '0')
        self.assertEqual(expected.returncode, 0, expected.stderr)
        requests = [(1, 'initialize', {'schema': 1}),
                    (2, 'symbols', {'path': str(image), 'rvas': [rva, 0]}),
                    (3, 'symbols', {'path': str(image), 'rvas': [False]}),
                    (4, 'symbols', {'path': str(image), 'rvas': []}),
                    (5, 'capabilities', {}), (6, 'shutdown', {})]
        stream = io.BytesIO()
        for request_id, method, params in requests:
            write_message(stream, dict(id=request_id, method=method, params=params))
        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'serve'],
                                input=stream.getvalue(), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        messages = io.BytesIO(result.stdout)
        responses = [read_message(messages) for _ in requests]
        self.assertEqual([item['id'] for item in responses], list(range(1, 7)))
        self.assertEqual(responses[1]['result'], json.loads(expected.stdout)['data'])
        self.assertEqual(responses[2]['error']['code'], -32602)
        self.assertEqual(responses[3]['result'], dict(metadata, resolved=[]))
        self.assertEqual(responses[4]['result']['symbol_queries']['maximum'], 256)
        self.assertIsNone(responses[5]['result'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
