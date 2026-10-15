import importlib.util
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
from symbols import host_tool

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('soda_symbols', os.environ.get('EAGLE_TEST_SYMBOL_PRODUCER', ROOT / '.github/soda-symbols.py'))
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)
sys.path.remove(str(ROOT / 'eagle'))


class SplitBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all((host_tool('llvm-dwarfdump'), host_tool('llvm-dwp'), host_tool('llvm-symbolizer'), shutil.which('gcc'), shutil.which('readelf'))):
            raise unittest.SkipTest('split bundle fixtures require existing GCC,binutils and LLVM tools')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.runner = self.root / 'runner'
        self.bundle = self.root / 'symbols'
        self.build = self.root / 'build'
        self.build.mkdir()
        (self.runner / 'bin').mkdir(parents=True)
        self.tools = PACKAGE / 'lib/eagle/native'

    def image(self, version=5, inside=False):
        build = self.runner / 'objects' if inside else self.build
        build.mkdir(exist_ok=True)
        (build / 'helper.c').write_text('int eagle_split(int n)\n{\n    return n + 7;\n}\n')
        (build / 'main.c').write_text('int eagle_split(int);\nint main(void) { return eagle_split(1); }\n')
        objects = []
        for name in ('helper', 'main'):
            source = build / (name + '.c')
            obj = build / (name + '.o')
            subprocess.run(['gcc', '-O0', '-g', '-gdwarf-' + str(version), '-gsplit-dwarf', '-c', str(source), '-o', str(obj)],
                           check=True, capture_output=True, timeout=30)
            objects.append(str(obj))
        image = self.runner / 'bin/module'
        subprocess.run(['gcc', *objects, '-o', str(image)], check=True, capture_output=True, timeout=30)
        listing = subprocess.check_output(['nm', '-n', str(image)], text=True)
        address = next(line.split()[0] for line in listing.splitlines() if line.split()[-1] == 'eagle_split')
        return image, build, '0x' + address

    def stage(self, roots=()):
        return producer.stage(self.runner, self.bundle, self.tools, 'split-fixture', ['bin/module'], debug_roots=roots)

    def test_dwarf4_and5_are_retained_and_resolve_after_archive_relocation(self):
        for version in (4, 5):
            with self.subTest(version=version):
                image, build, address = self.image(version)
                manifest = self.stage([build])
                record = manifest['images']['bin/module']
                split = record['split_dwarf']
                self.assertEqual(len(split['dwo_ids']), 2)
                self.assertEqual(len(split['inputs']), 2)
                self.assertEqual(split['file'], record['debug_file'] + '.dwp')
                self.assertEqual(producer.verify(self.runner, self.bundle, self.tools), manifest)
                archive = self.root / 'symbols.tar'
                subprocess.run(['tar', '-cf', str(archive), '-C', str(self.bundle), '.'], check=True)
                relocated = self.root / 'relocated'
                shutil.copytree(self.runner, relocated)
                subprocess.run(['tar', '-xf', str(archive), '-C', str(relocated)], check=True)
                shutil.rmtree(build)
                shutil.rmtree(self.runner)
                shutil.rmtree(self.bundle)
                output = subprocess.check_output([host_tool('llvm-symbolizer'), '--no-debuginfod', '--output-style=JSON',
                                                  '--obj=' + str(relocated / 'bin/module'), address], text=True)
                self.assertIn('eagle_split', output)
                self.assertIn('helper.c', output)
                self.assertEqual(json.loads(output)[0]['Symbol'][0]['Line'], 2)
                shutil.rmtree(relocated)
                self.build.mkdir()
                (self.runner / 'bin').mkdir(parents=True)

    def test_encoded_external_dwo_paths_require_an_explicit_build_root(self):
        image, build, _ = self.image()
        original = image.read_bytes()
        with self.assertRaisesRegex(ValueError, 'missing matching split unit'):
            self.stage()
        self.assertEqual(image.read_bytes(), original)
        self.assertFalse(self.bundle.exists())
        self.assertEqual(len(list(build.glob('*.dwo'))), 2)

    def test_runner_dwo_inputs_are_removed_but_external_inputs_are_preserved(self):
        _, build, _ = self.image(inside=True)
        self.stage()
        self.assertFalse(list(build.glob('*.dwo')))
        self.assertTrue((self.bundle / 'bin/.debug/module.debug.dwp').is_file())

    def test_existing_dwp_is_moved_beside_a_proton_style_debug_image(self):
        image, build, _ = self.image()
        debug = image.parent / '.debug/module.debug'
        debug.parent.mkdir()
        subprocess.run(['objcopy', '--only-keep-debug', str(image), str(debug)], check=True)
        subprocess.run(['objcopy', '--strip-unneeded', '--add-gnu-debuglink=' + str(debug), str(image)], check=True)
        package = image.parent / 'module.dwp'
        subprocess.run([host_tool('llvm-dwp'), *map(str, build.glob('*.dwo')), '-o', str(package)], check=True)
        shutil.rmtree(build)
        manifest = self.stage()
        self.assertFalse(package.exists())
        self.assertEqual(manifest['images']['bin/module']['split_dwarf']['file'], 'bin/.debug/module.debug.dwp')
        self.assertTrue((self.bundle / 'bin/.debug/module.debug.dwp').is_file())

    def test_same_unit_id_with_different_bytes_is_ambiguous(self):
        _, build, _ = self.image()
        other = self.root / 'other'
        other.mkdir()
        original = build / 'helper.dwo'
        (other / original.name).write_bytes(original.read_bytes() + b'owned-extra-bytes')
        with self.assertRaisesRegex(ValueError, 'ambiguous split units'):
            self.stage([build, other])
        self.assertFalse(self.bundle.exists())

    def test_symlink_inputs_and_roots_are_rejected(self):
        _, build, _ = self.image()
        alias = self.root / 'alias'
        alias.symlink_to(build, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'without symlinks'):
            self.stage([alias])
        dwo = build / 'helper.dwo'
        dwo.rename(build / 'original-unit')
        dwo.symlink_to(build / 'original-unit')
        with self.assertRaisesRegex(ValueError, 'must not use symlinks'):
            self.stage([build])

    def test_corrupt_dwp_bundle_is_rejected(self):
        _, build, _ = self.image()
        manifest = self.stage([build])
        path = self.bundle / manifest['images']['bin/module']['split_dwarf']['file']
        with path.open('ab') as file:
            file.write(b'owned-corruption')
        with self.assertRaisesRegex(ValueError, 'split symbol bundle does not match'):
            producer.verify(self.runner, self.bundle, self.tools)

    def test_manifest_cannot_omit_or_change_required_unit_ids(self):
        _, build, _ = self.image()
        manifest = self.stage([build])
        record = manifest['images']['bin/module']
        original = record['split_dwarf']
        for replacement in (None, dict(original, dwo_ids=[]), dict(original, dwo_ids=['0x0000000000000001'])):
            if replacement is None:
                del record['split_dwarf']
            else:
                record['split_dwarf'] = replacement
            for root in (self.runner, self.bundle):
                (root / 'share/soda/symbols.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'split manifest does not match debug image'):
                producer.verify(self.runner, self.bundle, self.tools)
        record['split_dwarf'] = original

    def test_inputs_changed_during_packaging_leave_the_image_unstripped(self):
        image, build, _ = self.image()
        before = image.read_bytes()
        run = subprocess.run
        def changed(arguments, **options):
            result = run(arguments, **options)
            if arguments[0] == host_tool('llvm-dwp'):
                with (build / 'helper.dwo').open('ab') as file:
                    file.write(b'owned-concurrent-change')
            return result
        with patch.object(producer.subprocess, 'run', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'split input changed during staging'):
                self.stage([build])
        self.assertEqual(image.read_bytes(), before)
        self.assertFalse((self.runner / 'share/soda/symbols.json').exists())

    def test_fifo_split_input_is_rejected_without_blocking(self):
        _, build, _ = self.image()
        dwo = build / 'helper.dwo'
        dwo.unlink()
        os.mkfifo(dwo)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.stage([build])
        self.assertFalse(self.bundle.exists())

    def test_relocated_inputs_with_spaces_quotes_and_unicode_are_packed(self):
        _, build, _ = self.image()
        relocated = self.root / 'moved build "units" \u00e8'
        build.rename(relocated)
        manifest = self.stage([relocated])
        self.assertEqual(len(manifest['images']['bin/module']['split_dwarf']['dwo_ids']), 2)
        self.assertTrue((relocated / 'helper.dwo').is_file())

    def test_ordinary_elf_dwarf_does_not_require_llvm_tools(self):
        source = self.build / 'ordinary.c'
        source.write_text('int main(void) { return 0; }\n')
        subprocess.run(['gcc', '-g', str(source), '-o', str(self.runner / 'bin/module')], check=True, capture_output=True)
        with patch.object(producer, 'host_tool', return_value=None):
            manifest = self.stage()
            self.assertEqual(producer.verify(self.runner, self.bundle, self.tools), manifest)
        self.assertNotIn('split_dwarf', manifest['images']['bin/module'])

    def test_builder_retains_more_units_than_the_interactive_query_limit(self):
        objects = []
        for number in range(257):
            source = self.build / ('unit' + str(number) + '.c')
            source.write_text('int ' + ('main' if number == 0 else 'unit' + str(number)) + '(void) { return 0; }\n')
            obj = source.with_suffix('.o')
            subprocess.run(['gcc', '-O0', '-g', '-gdwarf-5', '-gsplit-dwarf', '-c', str(source), '-o', str(obj)],
                           check=True, capture_output=True, timeout=30)
            objects.append(str(obj))
        image = self.runner / 'bin/module'
        subprocess.run(['gcc', *objects, '-o', str(image)], check=True, capture_output=True, timeout=30)
        manifest = self.stage([self.build])
        self.assertEqual(len(manifest['images']['bin/module']['split_dwarf']['dwo_ids']), 257)
        self.assertEqual(producer.verify(self.runner, self.bundle, self.tools), manifest)


if __name__ == '__main__':
    unittest.main()
