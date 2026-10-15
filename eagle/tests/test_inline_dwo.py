import hashlib
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

import test_inline_packages as packages
import symbols
from protocol import read_message, write_message

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])


class InlineDwo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        packages.InlinePackages.setUpClass()

    def setUp(self):
        self.fixture = packages.InlinePackages()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.temporary = Path(tempfile.gettempdir())
        before = set(self.temporary.glob('eagle-inlines-*'))
        self.addCleanup(lambda: self.assertEqual(set(self.temporary.glob('eagle-inlines-*')), before))

    def build(self, compiler='gcc', version=4):
        image, _, source, rva = self.fixture.build(compiler, version, remove=False)
        dwo = next(source.parent.glob('*.dwo'))
        selected = image.parent / 'reviewed "unit".data'
        shutil.copyfile(dwo, selected)
        shutil.rmtree(source.parent)
        return image, selected, source, rva

    def query(self, image, selected, rva):
        return symbols.query(image, rvas=[rva], inlines=True, debug_files=[str(path) for path in selected])

    def check(self, image, selected, rva):
        before = {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in selected}
        result = self.query(image, selected, rva)
        frame, = result['resolved']
        self.assertEqual(frame['inline_status'], 'available', frame)
        self.assertEqual([value['symbol'] for value in frame['inline_frames']], ['leaf', 'middle', 'outer'])
        record = result['inline_artifacts']
        self.assertEqual(record['status'], 'matched')
        self.assertIn('temporary DWP assembly', record['scope'])
        self.assertNotIn('path', record)
        self.assertEqual({item['path']: item['sha256'] for item in record['inputs']}, before)
        self.assertEqual(before, {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in selected})
        plain = symbols.query(image, rvas=[rva])
        self.assertEqual({key: value for key, value in frame.items() if not key.startswith('inline_')}, plain['resolved'][0])
        return result

    def test_relocated_gcc4_and_clang5_dwo_inputs_resolve_after_build_removal(self):
        for compiler, version in [('gcc', 4), ('clang', 5)]:
            with self.subTest(compiler=compiler, version=version):
                image, selected, source, rva = self.build(compiler, version)
                result = self.check(image, [selected], rva)
                self.assertEqual([frame['line'] for frame in result['resolved'][0]['inline_frames']], [11, 15, 19])
                self.assertTrue(all(frame['file'] == str(source) for frame in result['resolved'][0]['inline_frames']))

    def test_all_compilation_units_are_required_and_used(self):
        image, _, source, _ = self.fixture.build(remove=False)
        extra = source.parent / 'extra.c'
        extra.write_text('int extra(int n) { return n + 8; }\n')
        objects = []
        for item in (source, extra):
            obj = item.with_suffix('.o')
            subprocess.run(['gcc', '-O2', '-g', '-gdwarf-4', '-gsplit-dwarf', '-c', str(item), '-o', str(obj)],
                           check=True, capture_output=True, timeout=10)
            objects.append(obj)
        subprocess.run(['gcc', *map(str, objects), '-o', str(image)], check=True, capture_output=True, timeout=10)
        address = int(next(line.split()[0] for line in subprocess.check_output(['nm', '-n', str(image)], text=True).splitlines()
                           if line.endswith(' outer')), 16) + 4
        selected = []
        for item in (source, extra):
            target = image.parent / item.with_suffix('.dwo').name
            shutil.copyfile(item.with_suffix('.dwo'), target)
            selected.append(target)
        shutil.rmtree(source.parent)
        frame, = self.query(image, selected[:1], hex(address))['resolved']
        self.assertEqual(frame['inline_status'], 'unavailable')
        result = self.check(image, selected, hex(address))
        self.assertEqual(len(result['inline_artifacts']['dwo_ids']), 2)

    def test_identical_aliases_are_deduplicated_and_different_matching_dwo_is_ambiguous(self):
        image, selected, _, rva = self.build()
        alias = self.root / 'alias.dwo'
        alias.symlink_to(selected)
        self.check(image, [selected, alias], rva)
        other = self.root / 'other.dwo'
        shutil.copyfile(selected, other)
        result = self.query(image, [selected, other], rva)
        self.assertEqual(result['resolved'][0]['inline_status'], 'available')
        self.assertEqual(len(result['inline_artifacts']['inputs']), 1)
        with other.open('ab') as file:
            file.write(b'owned-different-content')
        frame, = self.query(image, [selected, other], rva)['resolved']
        self.assertEqual(frame['inline_status'], 'unavailable')
        self.assertIn('ambiguous', frame['inline_reason'])

    def test_changed_dwo_during_symbolization_discards_chain_and_identity(self):
        image, selected, _, rva = self.build()
        original = symbols.resolve_llvm
        def changed(*arguments, **options):
            result = original(*arguments, **options)
            if options.get('dwp'):
                with selected.open('ab') as file:
                    file.write(b'owned-concurrent-change')
            return result
        with patch.object(symbols, 'resolve_llvm', side_effect=changed):
            result = self.query(image, [selected], rva)
        self.assertEqual(result['resolved'][0]['inline_status'], 'unavailable')
        self.assertFalse(result['resolved'][0]['inline_frames'])
        self.assertNotIn('inline_artifacts', result)

    def test_missing_packager_does_not_change_default_lookup(self):
        image, selected, _, rva = self.build()
        tool = symbols.host_tool
        with patch.object(symbols, 'host_tool', side_effect=lambda name: None if name == 'llvm-dwp' else tool(name)):
            frame, = self.query(image, [selected], rva)['resolved']
            self.assertEqual(frame['inline_status'], 'unavailable')
            self.assertIn('llvm-dwp', frame['inline_reason'])
            self.assertTrue(symbols.query(image, rvas=[rva])['resolved'])

    def test_owned_failed_and_timed_out_packagers_are_reaped_and_temporary_files_removed(self):
        image, selected, _, rva = self.build()
        tool = symbols.host_tool
        for mode in ('failure', 'timeout'):
            packager = self.root / ('packager-' + mode)
            pid = self.root / ('pid-' + mode)
            packager.write_text('#!' + sys.executable + '\nimport os,time\nfrom pathlib import Path\n' +
                                'Path(' + repr(str(pid)) + ').write_text(str(os.getpid()))\n' +
                                ('raise SystemExit(7)\n' if mode == 'failure' else 'while True: time.sleep(1)\n'))
            packager.chmod(0o700)
            with self.subTest(mode=mode), patch.object(symbols, 'host_tool', side_effect=lambda name: str(packager) if name == 'llvm-dwp' else tool(name)):
                frame, = self.query(image, [selected], rva)['resolved']
                self.assertEqual(frame['inline_status'], 'unavailable')
                self.assertIn('assembly', frame['inline_reason'])
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid.read_text()), 0)
            self.assertFalse(list(self.temporary.glob('eagle-inlines-*')))
        self.check(image, [selected], rva)

    def test_cli_backend_assembled_identity_and_invalid_request_recovery(self):
        image, selected, _, rva = self.build()
        command = [sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle')]
        cli = subprocess.run([*command, 'symbols', str(image), '--rva', rva, '--inlines', '--debug-file', str(selected)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        expected = json.loads(cli.stdout)['data']
        params = {'path': str(image), 'rvas': [rva], 'inlines': True, 'debug_files': [str(selected)]}
        requests = [(1, 'initialize', {'schema': 1}), (2, 'symbols', params),
                    (3, 'symbols', dict(params, debug_files=[True])), (4, 'symbols', params), (5, 'shutdown', {})]
        stream = io.BytesIO()
        for i, method, item in requests:
            write_message(stream, dict(id=i, method=method, params=item))
        process = subprocess.run([*command, 'serve'], input=stream.getvalue(), capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        stream = io.BytesIO(process.stdout)
        replies = [read_message(stream) for _ in requests]
        self.assertEqual(replies[1]['result'], expected)
        self.assertEqual(replies[2]['error']['code'], -32602)
        self.assertEqual(replies[3]['result'], expected)


if __name__ == '__main__':
    unittest.main()
