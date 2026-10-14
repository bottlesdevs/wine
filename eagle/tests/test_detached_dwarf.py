import hashlib
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
import dwarf
import symbols


class DetachedSplitDwarf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dumper = symbols.host_tool('llvm-dwarfdump')
        cls.packager = symbols.host_tool('llvm-dwp')
        if not all((cls.dumper, cls.packager, shutil.which('gcc'), shutil.which('objcopy'))):
            raise unittest.SkipTest('detached split fixtures require existing GCC,binutils and LLVM tools')

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def build(self, name='fixture', version=5, adjacent=False):
        root = self.root / name
        root.mkdir()
        source = root / 'fixture.c'
        source.write_text('int eagle_split(int value)\n{\n    return value + 7;\n}\nint main(void) { return eagle_split(1); }\n')
        original = root / 'original'
        subprocess.run(['gcc', '-O0', '-g', '-gdwarf-' + str(version), '-gsplit-dwarf', str(source), '-o', str(original)],
                       check=True, capture_output=True, timeout=30)
        dwo = root / 'original-fixture.dwo'
        if not dwo.exists():
            dwo = root / 'original.dwo'
        self.assertTrue(dwo.is_file())
        image = root / 'shipped' / 'module'
        image.parent.mkdir()
        debug = image.parent / 'module.debug' if adjacent else image.parent / '.debug/module.debug'
        debug.parent.mkdir(exist_ok=True)
        subprocess.run(['objcopy', '--only-keep-debug', str(original), str(debug)], check=True, capture_output=True)
        subprocess.run(['objcopy', '--strip-unneeded', '--add-gnu-debuglink=' + str(debug), str(original), str(image)],
                       check=True, capture_output=True)
        package = Path(str(debug) + '.dwp')
        subprocess.run([self.packager, str(dwo), '-o', str(package)], check=True, capture_output=True, timeout=20)
        dwo.rename(root / 'hidden-source-unit')
        return image, debug, package, source

    def report(self, image, files=()):
        return dwarf.artifacts(image, self.dumper, [str(path) for path in files])

    def test_dwarf4_and5_find_units_in_matching_separate_debug_files(self):
        for version in (4, 5):
            for adjacent in (False, True):
                with self.subTest(version=version, adjacent=adjacent):
                    image, debug, package, _ = self.build(str(version) + str(adjacent), version, adjacent)
                    report = self.report(image)
                    self.assertEqual(report['status'], 'matched', report)
                    unit, = report['units']
                    self.assertEqual(unit['status'], 'matched')
                    selected = [report['files'][index] for index in unit['matches']]
                    self.assertTrue(any(file['path'] == str(package) for file in selected))
                    self.assertEqual(report['debug_image']['path'], str(debug))
                    self.assertEqual(report['debug_image']['sha256'], hashlib.sha256(debug.read_bytes()).hexdigest())
                    result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'lib/eagle/eagle'), 'symbols', str(image), '--artifacts'],
                                            capture_output=True, text=True, timeout=25)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout)['data']['split_dwarf'], report)

    def test_missing_and_corrupt_debug_images_are_unavailable(self):
        image, debug, _, _ = self.build()
        original = debug.read_bytes()
        debug.unlink()
        missing = self.report(image)
        self.assertEqual(missing['status'], 'unavailable')
        self.assertIn('missing', missing['reason'])
        debug.write_bytes(original + b'changed-owned-fixture')
        changed = self.report(image)
        self.assertEqual(changed['status'], 'unavailable')
        self.assertIn('CRC', changed['reason'])

    def test_missing_or_wrong_dwp_does_not_hide_the_skeleton(self):
        image, debug, package, _ = self.build()
        _, _, other, _ = self.build('other')
        package.unlink()
        missing = self.report(image)
        self.assertEqual(missing['status'], 'incomplete')
        self.assertEqual(len(missing['units']), 1)
        self.assertEqual(missing['units'][0]['status'], 'missing')
        shutil.copyfile(other, package)
        wrong = self.report(image)
        self.assertEqual(wrong['status'], 'incomplete')
        self.assertEqual(wrong['units'][0]['status'], 'mismatched')

    def test_explicit_relocated_dwp_matches_the_detached_skeleton(self):
        image, _, package, _ = self.build()
        relocated = self.root / 'selected.dwp'
        package.rename(relocated)
        self.assertEqual(self.report(image)['status'], 'incomplete')
        self.assertEqual(self.report(image, [relocated])['status'], 'matched')

    def test_fifo_debug_image_is_rejected_without_opening_a_blocking_stream(self):
        image, debug, _, _ = self.build()
        debug.unlink()
        os.mkfifo(debug)
        result = self.report(image)
        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('regular file', result['reason'])

    def test_debug_image_changes_during_inspection_are_rejected(self):
        image, debug, _, _ = self.build()
        original_dump = dwarf.dump
        def changed(tool, path, deadline):
            text = original_dump(tool, path, deadline)
            if path == debug:
                with debug.open('ab') as file:
                    file.write(b'changed-owned-fixture')
            return text
        with patch('dwarf.dump', side_effect=changed):
            result = self.report(image)
        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('changed during inspection', result['reason'])


if __name__ == '__main__':
    unittest.main()
