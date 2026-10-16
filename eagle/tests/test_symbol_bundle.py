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
from symbols import query

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('soda_symbols', ROOT / '.github/soda-symbols.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)
sys.path.remove(str(ROOT / 'eagle'))


class SymbolBundle(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.runner = self.root / 'runner'
        self.bundle = self.root / 'symbols'
        self.tools = PACKAGE / 'lib/eagle/native'
        (self.runner / 'bin').mkdir(parents=True)

    def image(self, name='fixture', machine='elf', dwarf=5, debug=True, build_id=False):
        compiler = 'gcc' if machine == 'elf' else machine + '-w64-mingw32-gcc'
        if not shutil.which(compiler):
            self.skipTest('owned fixtures require ' + compiler)
        source = self.root / (name + '.c')
        source.write_text('__attribute__((noinline)) int eagle_fixture(int value)\n{\n    return value + 7;\n}\nint main(void) { return eagle_fixture(1); }\n')
        image = self.runner / 'bin' / (name + ('.exe' if machine != 'elf' else ''))
        command = [compiler, '-O2'] + (['-g', '-gdwarf-' + str(dwarf)] if debug else [])
        if machine != 'elf':
            command.append('-Wl,--no-insert-timestamp')
        if build_id:
            command.append('-Wl,--build-id')
        subprocess.run([*command, str(source), '-o', str(image)], check=True, capture_output=True, timeout=30)
        return image

    def stage(self, **options):
        return producer.stage(self.runner, self.bundle, self.tools, 'soda-fixture', **options)

    def test_source_lines_survive_optional_bundle_for_elf_and_both_pe_architectures(self):
        for machine in ('elf', 'i686', 'x86_64'):
            for dwarf in (4, 5):
                self.image(machine + str(dwarf), machine, dwarf)
        before = {}
        for image in (self.runner / 'bin').iterdir():
            machine = 'i686' if image.name.startswith('i686') else 'x86_64' if image.suffix else 'elf'
            nm = 'nm' if machine == 'elf' else machine + '-w64-mingw32-nm'
            listing = subprocess.check_output([nm, '-n', str(image)], text=True)
            address = int(next(line.split()[0] for line in listing.splitlines() if line.split()[-1].lstrip('_') == 'eagle_fixture'), 16)
            metadata = producer.inspect(image, self.tools)
            rva = hex(address - int(metadata['image_base'], 0))
            before[image.name] = query(image, rvas=[rva])['resolved'][0]
        result = self.stage(required=['bin/' + name for name in before])
        self.assertEqual(result['retained'], 6)
        self.assertEqual(result['unavailable'], 0)
        for name, frame in before.items():
            image = self.runner / 'bin' / name
            self.assertNotEqual(query(image, rvas=[frame['rva']])['resolved'][0]['status'], 'source-resolved')
            record = result['images']['bin/' + name]
            debug = self.runner / record['debug_file']
            debug.parent.mkdir(exist_ok=True)
            shutil.copy2(self.bundle / record['debug_file'], debug)
            after = query(image, rvas=[frame['rva']])['resolved'][0]
            self.assertEqual((after['symbol'], after['file'], after['line']), (frame['symbol'], frame['file'], frame['line']))
            self.assertEqual(after['status'], 'source-resolved')
        self.assertEqual(producer.verify(self.runner, self.bundle, self.tools), result)

    def test_eagle_build_identity_tracks_separated_symbols(self):
        from provenance import capture_identity
        for machine in ('elf', 'i686', 'x86_64'):
            self.image(machine, machine)
        metadata = {'schema': 1,
                    'source': {'revision': 'a' * 40, 'dirty': False, 'tree_sha256': 'b' * 64},
                    'tools': {}, 'files': {}, 'symbols': {}}
        for image in (self.runner / 'bin').iterdir():
            relative = str(image.relative_to(self.runner))
            metadata['files'][relative] = producer.digest(image)
            identity = producer.inspect(image, self.tools)
            metadata['symbols'][relative] = {'sha256': producer.digest(image),
                **{key: identity[key] for key in ('format', 'machine', 'size', 'debug_info') if key in identity}}
        path = self.runner / 'share/eagle/build.json'
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(metadata))
        self.image('wine')
        result = self.stage()
        after = json.loads(path.read_text())
        self.assertEqual(after['source'], metadata['source'])
        self.assertNotIn('bin/wine', after['files'])
        for relative in metadata['files']:
            image = self.runner / relative
            record = result['images'][relative]
            self.assertNotEqual(metadata['files'][relative], after['files'][relative])
            self.assertEqual(after['files'][relative], producer.digest(image))
            self.assertEqual(after['symbols'][relative]['sha256'], producer.digest(image))
            identity = producer.inspect(image, self.tools)
            for key in ('format', 'machine', 'size', 'debug_info'):
                self.assertEqual(after['symbols'][relative].get(key), identity.get(key))
            self.assertEqual(after['symbols'][relative]['debuglink_crc'], record['debuglink_crc32'])
            self.assertEqual(capture_identity(self.runner, image, image)['status'], 'matched')

    def test_eagle_manifest_rejects_a_different_input(self):
        path = self.runner / 'share/eagle/build.json'
        path.parent.mkdir(parents=True)
        original = json.dumps({'files': {'bin/fixture': 'a' * 64}, 'symbols': {}})
        path.write_text(original)
        with self.assertRaisesRegex(ValueError, 'Eagle build input does not match image'):
            producer.refresh_eagle_manifest(self.runner, {
                'bin/fixture': {'input_sha256': 'b' * 64, 'image_sha256': 'c' * 64}}, self.tools)
        self.assertEqual(path.read_text(), original)

    def test_existing_proton_style_debuglink_is_moved_without_changing_image(self):
        for machine in ('elf', 'i686', 'x86_64'):
            image = self.image(machine, machine)
            debug = image.with_name(image.name + '.debug')
            objcopy = 'objcopy' if machine == 'elf' else machine + '-w64-mingw32-objcopy'
            subprocess.run([objcopy, '--only-keep-debug', str(image), str(debug)], check=True)
            subprocess.run([objcopy, '--strip-debug', '--add-gnu-debuglink=' + str(debug), str(image)], check=True)
        images = {p.name: producer.digest(p) for p in (self.runner / 'bin').iterdir() if p.suffix != '.debug'}
        result = self.stage(objcopy='/nonexistent/objcopy')
        self.assertEqual(result['retained'], 3)
        for name, expected in images.items():
            self.assertEqual(producer.digest(self.runner / 'bin' / name), expected)
            self.assertFalse((self.runner / 'bin' / (name + '.debug')).exists())
            self.assertTrue((self.bundle / 'bin' / (name + '.debug')).is_file())

    def test_pe_build_id_without_pdb_name_retains_dwarf(self):
        for machine in ('i686', 'x86_64'):
            image = self.image(machine, machine, build_id=True)
            metadata = producer.inspect(image, self.tools)
            self.assertTrue(metadata['debug_info'])
            self.assertTrue(metadata['codeview'])
            self.assertTrue(all(entry['pdb'] == '' for entry in metadata['codeview']))
        result = self.stage(required=['bin/i686.exe', 'bin/x86_64.exe'])
        self.assertEqual(result['retained'], 2)
        for record in result['images'].values():
            self.assertEqual(record['pdb_status'], 'unavailable')
            self.assertEqual(record['coverage'], 'dwarf')
        self.assertEqual(producer.verify(self.runner, self.bundle, self.tools), result)

    def test_gnu_objcopy_retains_symbols_when_llvm_is_absent(self):
        self.image()
        with patch.object(producer, 'host_tool', return_value=None):
            result = self.stage(required=['bin/fixture'])
        self.assertEqual(result['retained'], 1)
        self.assertEqual(producer.verify(self.runner, self.bundle, self.tools), result)

    def test_required_coverage_fails_before_mutation(self):
        image = self.image(debug=False)
        before = producer.digest(image)
        with self.assertRaisesRegex(ValueError, 'required image'):
            self.stage(required=['bin/fixture'])
        self.assertFalse(self.bundle.exists())
        self.assertEqual(producer.digest(image), before)

    def test_shared_gnu_companion_is_removed_once(self):
        image = self.image()
        debug = image.with_name(image.name + '.debug')
        subprocess.run(['objcopy', '--only-keep-debug', str(image), str(debug)], check=True)
        subprocess.run(['objcopy', '--strip-debug', '--add-gnu-debuglink=' + str(debug), str(image)], check=True)
        shutil.copyfile(image, image.with_name('copy'))
        result = self.stage()
        self.assertEqual(result['retained'], 2)
        self.assertFalse(debug.exists())
        self.assertEqual(result['images']['bin/fixture']['debug_file'], result['images']['bin/copy']['debug_file'])
        self.assertEqual(producer.verify(self.runner, self.bundle, self.tools), result)

    def test_unavailable_optional_image_is_explicit(self):
        self.image()
        self.image('no-debug', debug=False)
        result = self.stage()
        self.assertEqual(result['unavailable'], 1)
        self.assertEqual(result['images']['bin/no-debug']['status'], 'unavailable')

    def test_companion_without_dwarf_does_not_satisfy_required_source_coverage(self):
        image = self.image(machine='x86_64', debug=False)
        debug = image.with_name(image.name + '.debug')
        subprocess.run(['objcopy', '--strip-debug', str(image)], check=True)
        subprocess.run(['objcopy', '--only-keep-debug', str(image), str(debug)], check=True)
        subprocess.run(['objcopy', '--strip-debug', '--add-gnu-debuglink=' + str(debug), str(image)], check=True)
        with self.assertRaisesRegex(ValueError, 'required image'):
            self.stage(required=['bin/' + image.name])
        self.assertFalse(self.bundle.exists())
        result = self.stage()
        self.assertEqual(result['images']['bin/' + image.name]['coverage'], 'symbol-only')

    def test_wrong_debug_crc_is_rejected_before_mutation(self):
        image = self.image()
        debug = image.with_name('fixture.debug')
        subprocess.run(['objcopy', '--only-keep-debug', str(image), str(debug)], check=True)
        subprocess.run(['objcopy', '--strip-debug', '--add-gnu-debuglink=' + str(debug), str(image)], check=True)
        with debug.open('ab') as file:
            file.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.stage()
        self.assertFalse(self.bundle.exists())

    def test_symbol_destination_cannot_overlap_input(self):
        self.image()
        for path in (self.runner, self.runner / 'symbols', self.runner.parent):
            with self.assertRaises(ValueError):
                producer.stage(self.runner, path, self.tools, 'fixture')

    def test_metadata_symlink_and_nonregular_inputs_are_rejected(self):
        self.image()
        outside = self.root / 'outside'
        outside.mkdir()
        (self.runner / 'share').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.stage()
        (self.runner / 'share').unlink()
        os.mkfifo(self.runner / 'pipe')
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.stage()
        self.assertFalse(self.bundle.exists())

    def test_verify_rejects_changed_image_and_companion(self):
        image = self.image()
        result = self.stage()
        original = image.read_bytes()
        image.write_bytes(original + b'changed')
        with self.assertRaisesRegex(ValueError, 'runner image'):
            producer.verify(self.runner, self.bundle, self.tools)
        image.write_bytes(original)
        debug = self.bundle / result['images']['bin/fixture']['debug_file']
        debug.write_bytes(debug.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'companion'):
            producer.verify(self.runner, self.bundle, self.tools)

    def test_verify_rejects_fifo_without_opening_it(self):
        image = self.image()
        self.stage()
        image.unlink()
        os.mkfifo(image)
        with self.assertRaisesRegex(ValueError, 'regular file'):
            producer.verify(self.runner, self.bundle, self.tools)

    def test_staging_replaces_owned_image_without_mutating_hardlinked_baseline(self):
        image = self.image('fixture with spaces')
        baseline = self.root / 'baseline'
        os.link(image, baseline)
        original = producer.digest(baseline)
        self.stage()
        self.assertEqual(producer.digest(baseline), original)
        self.assertNotEqual(producer.digest(image), original)

    def test_pe_debug_names_are_resolved_without_changing_raw_section_names(self):
        image = self.image(machine='x86_64')
        metadata = producer.inspect(image, self.tools)
        self.assertTrue(metadata['debug_info'])
        self.assertTrue(any(section['name'].startswith('/') for section in metadata['sections']))
        raw = bytearray(image.read_bytes())
        pe = int.from_bytes(raw[60:64], 'little')
        raw[pe+12:pe+16] = (len(raw) + 4096).to_bytes(4, 'little')
        image.write_bytes(raw)
        with self.assertRaises(subprocess.CalledProcessError):
            producer.inspect(image, self.tools)

    def test_cli_verifies_and_rejects_wrong_runner(self):
        image = self.image()
        command = [sys.executable, '-S', str(ROOT / '.github/soda-symbols.py'), str(self.runner), str(self.bundle), '--tools', str(self.tools)]
        result = subprocess.run(command + ['--require', 'bin/fixture'], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['retained'], 1)
        self.assertEqual(subprocess.run(command + ['--verify'], capture_output=True, timeout=30).returncode, 0)
        image.write_bytes(image.read_bytes() + b'changed')
        self.assertNotEqual(subprocess.run(command + ['--verify'], capture_output=True, timeout=30).returncode, 0)


if __name__ == '__main__':
    unittest.main()
