import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
ROOT = PACKAGE / 'lib/eagle'


class NativePackage(unittest.TestCase):
    def test_provenance_covers_every_package_file(self):
        manifest = PACKAGE / 'share/eagle/build.json'
        expected = json.loads(manifest.read_text())['files']
        actual = {str(path.relative_to(PACKAGE)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in PACKAGE.rglob('*') if path.is_file() and path != manifest}
        self.assertEqual(actual, expected)

    def cli(self, *arguments):
        return subprocess.run([sys.executable, str(ROOT / 'eagle'), *arguments],
                              capture_output=True, text=True, timeout=15)

    def test_data_and_notices_match_pins(self):
        pins = json.loads((PACKAGE / 'share/eagle/sources.json').read_text())
        for name in ('eagle.yar', 'eagle-intel.sqlite', 'eagle-intel-data-license.txt'):
            self.assertEqual(hashlib.sha256((ROOT / 'engine' / name).read_bytes()).hexdigest(),
                             pins['assets']['engine/' + name])
        self.assertEqual(hashlib.sha256((PACKAGE / 'share/eagle/licenses/YARA-COPYING').read_bytes()).hexdigest(),
                         pins['assets']['native/vendor/YARA-COPYING'])
        self.assertEqual({path.name for path in (ROOT / 'engine').iterdir()},
                         {'eagle.yar', 'eagle-intel.sqlite', 'eagle-intel-data-license.txt'})

    def test_native_helpers_have_no_shared_library_dependencies(self):
        for name in ('pe', 'elf', 'analysis', 'intel', 'driver', 'yara'):
            with self.subTest(helper=name):
                result = subprocess.run(['readelf', '-d', str(ROOT / 'native' / ('eagle-' + name))],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('(NEEDED)', result.stdout)

    def test_capabilities_enable_native_analysis(self):
        result = self.cli('capabilities')
        self.assertEqual(result.returncode, 0, result.stderr)
        capabilities = json.loads(result.stdout)['data']
        self.assertTrue(capabilities['native_static_analyzer'])
        self.assertTrue(capabilities['analysis']['available'])
        self.assertEqual(capabilities['analysis']['maximum_concurrent'], 2)

    def test_native_helpers_do_not_embed_local_build_directories(self):
        roots = (str(Path(__file__).resolve().parents[2]).encode(), str(PACKAGE.parent.resolve()).encode())
        for path in (ROOT / 'native').iterdir():
            with self.subTest(helper=path.name):
                data = path.read_bytes()
                for root in roots:
                    self.assertFalse(root in data, 'local build directory in ' + path.name)

    def test_packaged_scanner_matches_framework_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'marker.bin'
            target.write_bytes(b'GameAssembly.dll\0global-metadata.dat\0')
            result = subprocess.run([str(ROOT / 'native/eagle-yara'), str(ROOT / 'engine/eagle.yar'), str(target), '5'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Unity_IL2CPP', {match['rule'] for match in json.loads(result.stdout)['matches']})

    def test_native_reports_for_both_pe_architectures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'app.c'
            source.write_text('int main(void) { return 0; }\n')
            for compiler, architecture in (('i686', 'x86 (32-bit)'), ('x86_64', 'x86_64 (64-bit)')):
                with self.subTest(compiler=compiler):
                    target = root / (compiler + '.exe')
                    subprocess.run([compiler + '-w64-mingw32-gcc', str(source), '-o', str(target)],
                                   check=True, capture_output=True)
                    result = self.cli('analyze', str(target), '--progress', '--scan-limit', '1')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    messages = [json.loads(line) for line in result.stdout.splitlines()]
                    self.assertEqual(messages[0]['event'], 'step')
                    self.assertTrue(messages[-1]['status'])
                    self.assertEqual(messages[-1]['data']['arch'], architecture)


if __name__ == '__main__':
    unittest.main(verbosity=2)
