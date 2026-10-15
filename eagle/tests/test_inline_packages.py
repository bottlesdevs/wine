import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_inline_symbols as fixtures
import symbols
from protocol import read_message, write_message

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])


class InlinePackages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.InlineSymbols.setUpClass()
        cls.dumper = symbols.host_tool('llvm-dwarfdump')
        if not cls.dumper:
            raise unittest.SkipTest('inline packages require existing llvm-dwarfdump')

    def setUp(self):
        self.fixture = fixtures.InlineSymbols()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root

    def build(self, compiler='gcc', version=4, pie=True, remove=True):
        image, _, source, rva = self.fixture.build(compiler, version, pie, split=True)
        root = self.root / ('relocated-' + str(len(list(self.root.iterdir()))))
        root.mkdir()
        target = root / 'module'
        shutil.copyfile(image, target)
        package = root / 'reviewed symbols.data'
        subprocess.run([self.fixture.dwp, *map(str, image.parent.glob('*.dwo')), '-o', str(package)],
                       check=True, capture_output=True, timeout=10)
        if remove:
            shutil.rmtree(image.parent)
        return target, package, source, rva

    def check(self, image, package, rva, files=None):
        result = symbols.query(image, rvas=[rva], inlines=True,
                               debug_files=[str(path) for path in files] if files is not None else [str(package)])
        frame, = result['resolved']
        self.assertEqual(frame['inline_status'], 'available', frame)
        self.assertEqual([value['symbol'] for value in frame['inline_frames']], ['leaf', 'middle', 'outer'])
        selected = result['inline_artifacts']
        self.assertEqual(selected['status'], 'matched')
        self.assertEqual(selected['path'], str(package.resolve()))
        self.assertEqual(selected['sha256'], hashlib.sha256(package.read_bytes()).hexdigest())
        self.assertTrue(selected['dwo_ids'])
        plain = symbols.query(image, rvas=[rva])
        self.assertEqual({key: value for key, value in frame.items() if not key.startswith('inline_')}, plain['resolved'][0])
        return result

    def test_explicit_relocated_packages_override_wrong_adjacent_packages(self):
        for compiler, version in [('gcc', 4), ('clang', 5)]:
            for pie in (False, True):
                with self.subTest(compiler=compiler, version=version, pie=pie):
                    image, package, source, rva = self.build(compiler, version, pie)
                    _, wrong, _, _ = self.build(compiler, version, pie)
                    shutil.copyfile(wrong, Path(str(image) + '.dwp'))
                    result = self.check(image, package, rva)
                    self.assertEqual([frame['line'] for frame in result['resolved'][0]['inline_frames']], [11, 15, 19])
                    self.assertTrue(all(frame['file'] == str(source) for frame in result['resolved'][0]['inline_frames']))

    def test_automatic_adjacent_and_detached_packages_are_pinned(self):
        for detached in (False, True):
            with self.subTest(detached=detached):
                image, package, _, rva = self.build()
                selected = image
                if detached:
                    selected = image.parent / '.debug/module.debug'
                    selected.parent.mkdir()
                    subprocess.run(['objcopy', '--only-keep-debug', str(image), str(selected)], check=True, capture_output=True)
                    subprocess.run(['objcopy', '--strip-unneeded', '--add-gnu-debuglink=' + str(selected), str(image)],
                                   check=True, capture_output=True)
                adjacent = Path(str(selected) + '.dwp')
                package.rename(adjacent)
                self.check(image, adjacent, rva, files=[])

    def test_wrong_missing_and_invalid_selections_do_not_fall_back(self):
        image, package, _, rva = self.build(remove=False)
        _, wrong, _, _ = self.build()
        adjacent = Path(str(image) + '.dwp')
        shutil.copyfile(package, adjacent)
        invalid = self.root / 'truncated.dwp'
        invalid.write_bytes(b'owned-invalid-DWP')
        for selected in (wrong, self.root / 'missing.dwp', invalid):
            with self.subTest(selected=selected):
                result = symbols.query(image, rvas=[rva], inlines=True, debug_files=[str(selected)])
                frame, = result['resolved']
                self.assertEqual(frame['inline_status'], 'unavailable')
                self.assertIn('no matching inline DWP', frame['inline_reason'])
                self.assertEqual(frame['inline_frames'], [])
                self.assertNotIn('inline_artifacts', result)

    def test_partial_packages_do_not_cover_all_compilation_units(self):
        image, package, _, rva = self.build(remove=False)
        original = next(self.root.glob('[0-9]*/fixture.c'))
        extra = original.parent / 'extra.c'
        extra.write_text('int extra(int n) { return n + 8; }\n')
        objects = []
        for source in (original, extra):
            obj = source.with_suffix('.o')
            subprocess.run(['gcc', '-O2', '-g', '-gdwarf-4', '-gsplit-dwarf', '-c', str(source), '-o', str(obj)],
                           check=True, capture_output=True, timeout=10)
            objects.append(obj)
        subprocess.run(['gcc', *map(str, objects), '-o', str(image)], check=True, capture_output=True, timeout=10)
        address = int(next(line.split()[0] for line in subprocess.check_output(['nm', '-n', str(image)], text=True).splitlines()
                           if line.endswith(' outer')), 16) + 4
        rva = hex(address)
        partial = self.root / 'partial.dwp'
        subprocess.run([self.fixture.dwp, str(extra.with_suffix('.dwo')), '-o', str(partial)],
                       check=True, capture_output=True, timeout=10)
        result = symbols.query(image, rvas=[rva], inlines=True, debug_files=[str(partial)])
        self.assertEqual(result['resolved'][0]['inline_status'], 'unavailable')
        subprocess.run([self.fixture.dwp, str(original.with_suffix('.dwo')), str(extra.with_suffix('.dwo')), '-o', str(package)],
                       check=True, capture_output=True, timeout=10)
        shutil.rmtree(original.parent)
        result = self.check(image, package, rva)
        self.assertEqual(len(result['inline_artifacts']['dwo_ids']), 2)

    def test_identical_aliases_are_allowed_but_different_matching_packages_are_ambiguous(self):
        image, package, _, rva = self.build()
        alias = self.root / 'alias.dwp'
        alias.symlink_to(package)
        self.check(image, package, rva, files=[alias, package])
        other = self.root / 'other.dwp'
        shutil.copyfile(package, other)
        self.check(image, package, rva, files=[package, other])
        with other.open('ab') as file:
            file.write(b'owned-different-content')
        frame, = symbols.query(image, rvas=[rva], inlines=True, debug_files=[str(package), str(other)])['resolved']
        self.assertEqual(frame['inline_status'], 'unavailable')
        self.assertIn('ambiguous', frame['inline_reason'])

    def test_changed_package_during_lookup_does_not_return_a_chain(self):
        image, package, _, rva = self.build()
        original = symbols.resolve_llvm
        def changed(*arguments, **options):
            result = original(*arguments, **options)
            if options.get('dwp'):
                with package.open('ab') as file:
                    file.write(b'owned-concurrent-change')
            return result
        with patch.object(symbols, 'resolve_llvm', side_effect=changed):
            result = symbols.query(image, rvas=[rva], inlines=True, debug_files=[str(package)])
        frame, = result['resolved']
        self.assertEqual(frame['inline_status'], 'unavailable')
        self.assertIn('changed', frame['inline_reason'])
        self.assertFalse(frame['inline_frames'])
        self.assertNotIn('inline_artifacts', result)

    def test_missing_identity_tool_is_explicit_without_changing_default_lookup(self):
        image, package, _, rva = self.build()
        host_tool = symbols.host_tool
        with patch.object(symbols, 'host_tool', side_effect=lambda name: None if name == 'llvm-dwarfdump' else host_tool(name)):
            frame, = symbols.query(image, rvas=[rva], inlines=True, debug_files=[str(package)])['resolved']
            self.assertEqual(frame['inline_status'], 'unavailable')
            self.assertIn('llvm-dwarfdump', frame['inline_reason'])
            self.assertTrue(symbols.query(image, rvas=[rva])['resolved'])

    def test_unreferenced_adjacent_package_does_not_replace_embedded_inline_data(self):
        image, _, _, rva = self.fixture.build()
        _, package, _, _ = self.build()
        shutil.copyfile(package, Path(str(image) + '.dwp'))
        result = symbols.query(image, rvas=[rva], inlines=True)
        self.assertEqual(result['resolved'][0]['inline_status'], 'available')
        self.assertEqual([frame['symbol'] for frame in result['resolved'][0]['inline_frames']], ['leaf', 'middle', 'outer'])
        self.assertNotIn('inline_artifacts', result)

    def test_cli_backend_selected_package_agreement_and_request_recovery(self):
        image, package, _, rva = self.build()
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        cli = subprocess.run([*command, 'symbols', str(image), '--rva', rva, '--inlines', '--debug-file', str(package)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        expected = json.loads(cli.stdout)['data']
        requests = [(1, 'initialize', {'schema': 1}),
                    (2, 'symbols', {'path': str(image), 'rvas': [rva], 'inlines': True, 'debug_files': [str(package)]}),
                    (3, 'symbols', {'path': str(image), 'rvas': [rva], 'inlines': True, 'debug_files': [True]}),
                    (4, 'symbols', {'path': str(image), 'rvas': [rva], 'inlines': True, 'debug_files': [str(package)]}),
                    (5, 'shutdown', {})]
        stream = io.BytesIO()
        for i, method, params in requests:
            write_message(stream, dict(id=i, method=method, params=params))
        process = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        stream = io.BytesIO(process.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertEqual(replies[1]['result'], expected)
        self.assertEqual(replies[2]['error']['code'], -32602)
        self.assertEqual(replies[3]['result'], expected)


if __name__ == '__main__':
    unittest.main()
