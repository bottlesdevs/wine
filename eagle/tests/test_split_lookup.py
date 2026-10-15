import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_split_bundle as fixtures
import symbols
from protocol import read_message, write_message

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])


class SplitLookup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.SplitBundle.setUpClass()

    def image(self, version=5, pie=True, names='none'):
        fixture = fixtures.SplitBundle()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        image, build, address = fixture.image(version)
        if not pie:
            subprocess.run(['gcc', '-no-pie', str(build / 'helper.o'), str(build / 'main.o'), '-o', str(image)],
                           check=True, capture_output=True)
            listing = subprocess.check_output(['nm', '-n', str(image)], text=True)
            address = '0x' + next(line.split()[0] for line in listing.splitlines() if line.split()[-1] == 'eagle_split')
        flags = ['--strip-all', '--keep-section=.debug*'] if names == 'none' else ['--strip-symbol=eagle_split']
        subprocess.run(['objcopy', *flags, str(image)], check=True, capture_output=True)
        metadata = symbols.image_metadata(image)
        rva = hex(int(address, 0) - int(metadata['image_base'], 0))
        manifest = fixture.stage([build])
        record = manifest['images']['bin/module']
        for relative in (record['debug_file'], record['split_dwarf']['file']):
            target = fixture.runner / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixture.bundle / relative, target)
        source = str(build / 'helper.c')
        shutil.rmtree(build)
        return image, rva, source, fixture.runner / record['split_dwarf']['file']

    def test_separated_dwarf4_and5_function_names_cover_pie_and_non_pie(self):
        for version in (4, 5):
            for pie in (False, True):
                with self.subTest(version=version, pie=pie):
                    image, rva, source, _ = self.image(version, pie)
                    result = symbols.query(image, rvas=[rva])
                    frame, = result['resolved']
                    self.assertEqual(frame['symbol'], 'eagle_split')
                    self.assertEqual((frame['file'], frame['line']), (source, 2))
                    self.assertEqual(frame['resolver'], 'llvm-exact-image')
                    self.assertEqual(frame['status'], 'source-resolved')
                    self.assertFalse(Path(source).exists())
                    cli = subprocess.run([sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle'), 'symbols', str(image), '--rva', rva],
                                         capture_output=True, text=True, timeout=20)
                    self.assertEqual(cli.returncode, 0, cli.stderr)
                    self.assertEqual(json.loads(cli.stdout)['data'], result)

    def test_missing_llvm_keeps_gnu_source_with_an_explicit_reason(self):
        image, rva, source, _ = self.image()
        with patch.object(symbols, 'host_tool', return_value=None):
            frame, = symbols.query(image, rvas=[rva])['resolved']
        self.assertIsNone(frame['symbol'])
        self.assertEqual((frame['file'], frame['line']), (source, 2))
        self.assertEqual(frame['resolver'], 'binutils-exact-image')
        self.assertEqual(frame['symbol_reason'], 'requires host llvm-symbolizer')

    def test_a_nearby_elf_symbol_does_not_override_the_dwarf_function_name(self):
        image, rva, source, _ = self.image(names='partial')
        with patch.object(symbols, 'host_tool', return_value=None):
            gnu, = symbols.query(image, rvas=[rva])['resolved']
        self.assertNotEqual(gnu['symbol'], 'eagle_split')
        frame, = symbols.query(image, rvas=[rva])['resolved']
        self.assertEqual(frame['symbol'], 'eagle_split')
        self.assertEqual((frame['file'], frame['line']), (source, 2))
        self.assertEqual(frame['resolver'], 'llvm-exact-image')

    def test_failed_llvm_keeps_gnu_source_with_an_explicit_reason(self):
        image, rva, source, _ = self.image()
        for error in (ValueError('owned malformed output'), subprocess.TimeoutExpired('llvm-symbolizer', 10), OSError('owned missing tool')):
            with self.subTest(error=type(error).__name__), patch.object(symbols, 'resolve_llvm', side_effect=error):
                frame, = symbols.query(image, rvas=[rva])['resolved']
            self.assertIsNone(frame['symbol'])
            self.assertEqual(frame['file'], source)
            self.assertEqual(frame['symbol_reason'], 'LLVM source resolver failed')

    def test_wrong_dwp_does_not_supply_a_function_name(self):
        image, rva, source, package = self.image()
        _, _, _, wrong = self.image()
        shutil.copyfile(wrong, package)
        frame, = symbols.query(image, rvas=[rva])['resolved']
        self.assertIsNone(frame['symbol'])
        self.assertEqual(frame['file'], source)
        self.assertEqual(frame['symbol_reason'], 'matching function name unavailable')

    def test_disagreeing_source_locations_do_not_replace_gnu_results(self):
        image, rva, source, _ = self.image()
        value = {'symbol': 'wrong_owned_fixture', 'file': source + '.different', 'line': 2, 'resolver': 'llvm-exact-image'}
        with patch.object(symbols, 'resolve_llvm', return_value=[value]):
            frame, = symbols.query(image, rvas=[rva])['resolved']
        self.assertIsNone(frame['symbol'])
        self.assertEqual(frame['file'], source)
        self.assertEqual(frame['symbol_reason'], 'resolver source locations disagree')

    def test_unknown_addresses_do_not_start_an_extra_resolver(self):
        image, _, _, _ = self.image()
        with patch.object(symbols, 'host_tool', side_effect=AssertionError('unexpected LLVM discovery')):
            frame, = symbols.query(image, rvas=['0'])['resolved']
        self.assertEqual(frame['status'], 'unresolved')
        self.assertNotIn('symbol_reason', frame)

    def test_backend_matches_cli_data_and_recovers_after_invalid_request(self):
        image, rva, _, _ = self.image()
        expected = symbols.query(image, rvas=[rva])
        requests = [(1, 'initialize', {'schema': 1}), (2, 'symbols', {'path': str(image), 'rvas': [rva]}),
                    (3, 'symbols', {'path': str(image), 'rvas': ['invalid']}),
                    (4, 'symbols', {'path': str(image), 'rvas': [rva]}), (5, 'shutdown', {})]
        stream = io.BytesIO()
        for request_id, method, params in requests:
            write_message(stream, dict(id=request_id, method=method, params=params))
        process = subprocess.run([sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle'), 'serve'],
                                 input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        stream = io.BytesIO(process.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertEqual([reply['id'] for reply in replies], [1, 2, 3, 4, 5])
        self.assertEqual(replies[1]['result'], expected)
        self.assertEqual(replies[3]['result'], expected)
        self.assertEqual(replies[2]['error']['code'], -32602)


if __name__ == '__main__':
    unittest.main()
