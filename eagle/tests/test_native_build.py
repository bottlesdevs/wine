import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1]


class NativeBuild(unittest.TestCase):
    def invoke(self, script, *arguments):
        return subprocess.run(['sh', str(script), *map(str, arguments)],
                              capture_output=True, text=True, timeout=5)

    def test_existing_directories_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / 'package'
            work = root / 'work'
            for existing in (destination, work):
                existing.mkdir()
                marker = existing / 'marker'
                marker.write_text('keep')
                result = self.invoke(SOURCE / 'build-native.sh', destination, SOURCE, work)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('already exists', result.stderr)
                self.assertEqual(marker.read_text(), 'keep')
                marker.unlink()
                existing.rmdir()

    def test_changed_or_missing_data_fails_before_build(self):
        for changed in ('engine/eagle.yar', 'engine/eagle-intel-data-license.txt'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in ('build-native.sh', 'sources.json'):
                    shutil.copy2(SOURCE / name, root / name)
                pins = json.loads((SOURCE / 'sources.json').read_text())
                for name in pins['assets']:
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(SOURCE / name, target)
                if changed.endswith('.yar'):
                    (root / changed).write_text('changed fixture')
                else:
                    (root / changed).unlink()
                destination = root / 'package'
                work = root / 'work'
                result = self.invoke(root / 'build-native.sh', destination, SOURCE, work)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(destination.exists())
                self.assertFalse(work.exists())

    def test_wrong_yara_revision_is_rejected_without_build_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory) / 'build'
            result = self.invoke(SOURCE / 'prepare-yara.sh', SOURCE, build)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(build.exists())

    def test_build_tree_cannot_become_package_content(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'package'
            for work in (destination, destination / 'build'):
                result = self.invoke(SOURCE / 'build-native.sh', destination, SOURCE, work)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('outside the package', result.stderr)
                self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
