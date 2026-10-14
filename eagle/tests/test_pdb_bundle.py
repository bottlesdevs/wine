import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
import symbols
import session

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('soda_symbols', ROOT / '.github/soda-symbols.py')
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)
sys.path.remove(str(ROOT / 'eagle'))


class PdbBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.linker = symbols.host_tool('lld-link')
        if not shutil.which('clang-cl') or not cls.linker or not symbols.pdb_resolver():
            raise unittest.SkipTest('owned PDB fixtures require existing Clang,LLD and LLVM symbolizer')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.runner = self.root / 'runner'
        self.runner.mkdir()
        self.bundle = self.root / 'symbols'
        self.tools = PACKAGE / 'lib/eagle/native'

    def build(self, name='fixture', target='x86_64'):
        source = self.root / (name + '.c')
        source.write_text('__declspec(noinline) int eagle_pdb_fixture(int value)\n{\n    return value + 7;\n}\nint entry(void) { return eagle_pdb_fixture(1); }\n')
        image, pdb = [self.runner / (name + suffix) for suffix in ('.exe', '.pdb')]
        obj = self.root / (name + '.obj')
        subprocess.run(['clang-cl', '--target=' + target + '-pc-windows-msvc', '/nologo', '/Od', '/Z7', '/c',
                        str(source), '/Fo' + str(obj)], check=True, capture_output=True, timeout=30)
        subprocess.run([self.linker, '/nologo', '/entry:entry', '/subsystem:console', '/nodefaultlib', '/debug',
                        '/timestamp:0', '/pdb:' + str(pdb), '/pdbaltpath:C:\\build\\' + pdb.name,
                        '/out:' + str(image), str(obj)], check=True, capture_output=True, timeout=30)
        return image, pdb, source

    def stage(self, **options):
        return producer.stage(self.runner, self.bundle, self.tools, 'owned-pdb-fixture',
                              objcopy='/nonexistent/objcopy', **options)

    def test_exact_pdb_files_move_and_resolve_on_static_pe_architectures(self):
        cases = [self.build(target, target) for target in ('i686', 'x86_64', 'aarch64')]
        before = {image.name: producer.digest(image) for image, _, _ in cases}
        result = self.stage()
        self.assertEqual(result['retained'], 3)
        self.assertEqual(result['unavailable'], 0)
        for image, pdb, source in cases:
            record = result['images'][image.name]
            self.assertFalse(pdb.exists())
            self.assertEqual(producer.digest(image), before[image.name])
            self.assertEqual(record['coverage'], 'pdb-identity')
            self.assertEqual(record['pdb_status'], 'matched')
            selected = self.bundle / record['pdb_file']
            frame, = symbols.query(image, pdb=selected, rvas=['0x1000'])['resolved']
            self.assertEqual((frame['symbol'], frame['file'], frame['line']), ('eagle_pdb_fixture', str(source), 2))
        self.assertEqual(producer.verify(self.runner, self.bundle, self.tools), result)

    def test_guid_and_age_mismatches_fail_before_mutation(self):
        image, pdb, _ = self.build()
        original = image.read_bytes()
        rsds = original.index(b'RSDS')
        for offset in (rsds + 4, rsds + 20):
            with self.subTest(offset=offset):
                raw = bytearray(original)
                raw[offset] ^= 1
                image.write_bytes(raw)
                before = producer.digest(image)
                with self.assertRaisesRegex(ValueError, 'does not match image'):
                    self.stage()
                self.assertFalse(self.bundle.exists())
                self.assertTrue(pdb.exists())
                self.assertEqual(producer.digest(image), before)

    def test_mixed_dwarf_and_codeview_keeps_both_companions(self):
        objcopy = symbols.host_tool('llvm-objcopy')
        if not objcopy or not shutil.which('clang'):
            self.skipTest('mixed PE fixture requires existing Clang and LLVM objcopy')
        source = self.root / 'mixed.c'
        source.write_text('int main(void) { return 7; }\n')
        obj = self.root / 'mixed.obj'
        image, pdb = self.runner / 'mixed.exe', self.runner / 'mixed.pdb'
        subprocess.run(['clang', '--target=x86_64-pc-windows-msvc', '-O0', '-g', '-gdwarf-5', '-c',
                        str(source), '-o', str(obj)], check=True, capture_output=True, timeout=30)
        link_args = [self.linker, '/entry:main', '/subsystem:console', '/nodefaultlib', '/debug', '/timestamp:0',
                     '/pdb:' + str(pdb), '/out:' + str(image), str(obj)]
        subprocess.run(link_args, check=True, capture_output=True, timeout=30)
        (self.runner / '.debug').mkdir()
        collision = self.runner / '.debug' / (image.name + '.debug')
        collision_args = ['/pdb:' + str(collision) if arg.startswith('/pdb:') else arg for arg in link_args]
        subprocess.run(collision_args, check=True, capture_output=True, timeout=30)
        expected = producer.digest(image)
        with self.assertRaisesRegex(ValueError, 'share an output path'):
            producer.stage(self.runner, self.bundle, self.tools, 'owned-mixed-fixture', objcopy=objcopy)
        self.assertFalse(self.bundle.exists())
        self.assertEqual(producer.digest(image), expected)
        self.assertTrue(collision.exists())
        collision.unlink()
        subprocess.run(link_args, check=True, capture_output=True, timeout=30)
        before = producer.inspect(image, self.tools)
        self.assertTrue(before['debug_info'])
        self.assertTrue(before['codeview'])
        result = producer.stage(self.runner, self.bundle, self.tools, 'owned-mixed-fixture',
                                required=[image.name], objcopy=objcopy)
        record = result['images'][image.name]
        self.assertEqual(record['coverage'], 'dwarf')
        self.assertIn('debug_file', record)
        self.assertIn('pdb_file', record)
        self.assertFalse(pdb.exists())
        self.assertEqual(producer.inspect(image, self.tools)['codeview'], before['codeview'])
        shutil.copytree(self.bundle, self.runner, dirs_exist_ok=True)
        frame, = symbols.query(image, rvas=['0x1000'])['resolved']
        self.assertEqual((frame['file'], frame['line']), (str(source), 1))
        producer.verify(self.runner, self.bundle, self.tools)

    def test_missing_optional_pdb_is_explicit(self):
        image, pdb, _ = self.build('missing')
        pdb.unlink()
        self.build('retained')
        result = self.stage()
        self.assertEqual(result['retained'], 1)
        self.assertEqual(result['unavailable'], 1)
        self.assertEqual(result['images'][image.name]['pdb_status'], 'unavailable')
        self.assertEqual(result['images'][image.name]['status'], 'unavailable')

    def test_pdb_identity_does_not_satisfy_the_required_dwarf_gate(self):
        image, pdb, _ = self.build()
        before = producer.digest(image)
        with self.assertRaisesRegex(ValueError, 'required image'):
            self.stage(required=[image.name])
        self.assertFalse(self.bundle.exists())
        self.assertTrue(pdb.exists())
        self.assertEqual(producer.digest(image), before)

    def test_shared_pdb_is_copied_and_removed_once(self):
        image, pdb, _ = self.build()
        shutil.copyfile(image, self.runner / 'copy.exe')
        result = self.stage()
        self.assertEqual(result['retained'], 2)
        self.assertEqual(result['images'][image.name]['pdb_file'], result['images']['copy.exe']['pdb_file'])
        self.assertEqual(len(list(self.bundle.glob('*.pdb'))), 1)
        self.assertFalse(pdb.exists())
        producer.verify(self.runner, self.bundle, self.tools)

    def test_duplicate_pdb_candidates_are_rejected(self):
        _, pdb, _ = self.build()
        (self.runner / '.debug').mkdir()
        shutil.copyfile(pdb, self.runner / '.debug' / pdb.name)
        with self.assertRaisesRegex(ValueError, 'ambiguous PDB companions'):
            self.stage()
        self.assertFalse(self.bundle.exists())

    def test_pdb_symlinks_and_fifos_are_rejected_without_reading_them(self):
        _, pdb, _ = self.build()
        outside = self.root / 'outside.pdb'
        pdb.rename(outside)
        pdb.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.stage()
        pdb.unlink()
        os.mkfifo(pdb)
        with self.assertRaisesRegex(ValueError, 'regular'):
            self.stage()
        self.assertFalse(self.bundle.exists())

    def test_verification_rejects_changed_pdb_identity_and_escape_paths(self):
        image, _, _ = self.build()
        result = self.stage()
        record = result['images'][image.name]
        pdb = self.bundle / record['pdb_file']
        data = pdb.read_bytes()
        pdb.write_bytes(data + b'changed-owned-fixture')
        with self.assertRaisesRegex(ValueError, 'PDB does not match'):
            producer.verify(self.runner, self.bundle, self.tools)
        pdb.write_bytes(data)
        record['pdb_identity']['age'] += 1
        for root in (self.runner, self.bundle):
            (root / 'share/soda/symbols.json').write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'PDB does not match'):
            producer.verify(self.runner, self.bundle, self.tools)
        record['pdb_file'] = '../outside.pdb'
        for root in (self.runner, self.bundle):
            (root / 'share/soda/symbols.json').write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'invalid symbol bundle path'):
            producer.verify(self.runner, self.bundle, self.tools)


if __name__ == '__main__':
    unittest.main()
