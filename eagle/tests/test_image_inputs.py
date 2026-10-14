import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PACKAGE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'


class ImageInputTests(unittest.TestCase):
    def test_nonregular_images_return_without_waiting_for_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fifo = root / 'input.fifo'
            os.mkfifo(fifo)
            link = root / 'linked.fifo'
            link.symlink_to(fifo)
            for path in (fifo, link, root):
                for command in ([str(PACKAGE / 'native/eagle-pe')],
                                [str(PACKAGE / 'native/eagle-elf')],
                                [sys.executable, '-S', str(PACKAGE / 'eagle'), 'symbols']):
                    with self.subTest(path=path.name, command=command):
                        result = subprocess.run([*command, str(path)], capture_output=True, text=True, timeout=2)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, '')
                        self.assertTrue(result.stderr.strip())

    def test_regular_images_and_symlinks_keep_the_same_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'main.c'
            source.write_text('int main(void) { return 0; }\n')
            for compiler, name in (('gcc', 'host'), ('i686-w64-mingw32-gcc', 'win32.exe'), ('x86_64-w64-mingw32-gcc', 'win64.exe')):
                with self.subTest(compiler=compiler):
                    target = root / name
                    subprocess.run([compiler, '-g', str(source), '-o', str(target)], check=True, capture_output=True)
                    link = root / ('linked-' + name)
                    link.symlink_to(target)
                    outputs = []
                    for path in (target, link):
                        result = subprocess.run([sys.executable, '-S', str(PACKAGE / 'eagle'), 'symbols', str(path)], check=True, capture_output=True, text=True, timeout=2)
                        outputs.append(json.loads(result.stdout))
                    self.assertTrue(outputs[0]['status'])
                    self.assertEqual(outputs[0], outputs[1])


if __name__ == '__main__':
    unittest.main(verbosity=2)
