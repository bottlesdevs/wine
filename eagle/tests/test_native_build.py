import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
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

    def test_pinned_fetch_failure_never_creates_a_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / 'tools'
            tools.mkdir()
            calls = root / 'git.jsonl'
            git = tools / 'git'
            git.write_text('#!' + sys.executable + '\nimport json,sys\n'
                           'with open(' + repr(str(calls)) + ', "a") as file: file.write(json.dumps(sys.argv[1:])+"\\n")\n'
                           'raise SystemExit(73 if "fetch" in sys.argv else 0)\n')
            git.chmod(0o700)
            package, work = root / 'package', root / 'work'
            result = subprocess.run(['sh', str(SOURCE / 'build-native.sh'), str(package), '-', str(work)],
                                    env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH']),
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 73, result.stderr)
            self.assertFalse(package.exists())
            commands = [json.loads(line) for line in calls.read_text().splitlines()]
            revision = json.loads((SOURCE / 'sources.json').read_text())['yara_revision']
            self.assertEqual(next(command[2:] for command in commands if 'fetch' in command),
                             ['fetch', '--no-tags', '--depth=1', 'origin', revision])
            self.assertFalse(any('checkout' in command for command in commands))

    def test_runner_build_routes_through_requested_assembly_before_installation(self):
        for script, extra in (('build-eagle.sh', []), ('build-eagle-analyzer.sh', ['analyzer-only'])):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / '.github').mkdir()
                (root / 'eagle').mkdir()
                shutil.copyfile(SOURCE.parent / '.github' / script, root / '.github' / script)
                receipt = root / 'called.json'
                (root / 'eagle/build-native.sh').write_text('python3 - "$@" <<\'PYTHON\'\n'
                    'import json,sys,os\nfrom pathlib import Path\n'
                    'assert os.environ.get("PYTHONDONTWRITEBYTECODE") == "1"\n'
                    'Path(' + repr(str(receipt)) + ').write_text(json.dumps(sys.argv[1:]))\n'
                    'raise SystemExit(73)\nPYTHON\n')
                runner = root / 'runner'
                (runner / 'bin').mkdir(parents=True)
                wine = runner / 'bin/wine'
                wine.write_text('#!/bin/sh\nexit 99\n')
                wine.chmod(0o700)
                work = root / 'work'
                env = dict(os.environ)
                env.pop('PYTHONDONTWRITEBYTECODE', None)
                result = subprocess.run(['sh', str(root / '.github' / script), str(runner), str(work)],
                                        env=env, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 73, result.stderr)
                self.assertEqual(json.loads(receipt.read_text()), [str(work / 'package'), '-', str(work / 'native')] + extra)
                self.assertEqual(list(runner.iterdir()), [runner / 'bin'])
                self.assertEqual(wine.read_text(), '#!/bin/sh\nexit 99\n')

    def test_build_tree_cannot_become_package_content(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'package'
            for work in (destination, destination / 'build'):
                result = self.invoke(SOURCE / 'build-native.sh', destination, SOURCE, work)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('outside the package', result.stderr)
                self.assertFalse(destination.exists())

    def test_unknown_package_mode_fails_before_creating_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for script, arguments in (('build-native.sh', [root / 'package', '-', root / 'work']),
                                      ('build-debugger.sh', [root / 'package'])):
                with self.subTest(script=script):
                    result = self.invoke(SOURCE / script, *arguments, 'unknown')
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Unknown package mode', result.stderr)
                    self.assertEqual(list(root.iterdir()), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
