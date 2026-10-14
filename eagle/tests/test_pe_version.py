import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


NATIVE = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle/native/eagle-pe'


class PEVersionTests(unittest.TestCase):
    def test_empty_version_strings_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'main.c'
            source.write_text('int main(void) { return 0; }\n')
            resource = root / 'version.rc'
            resource.write_text('''1 VERSIONINFO
FILEVERSION 1,2,3,4
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "040904b0"
  BEGIN
   VALUE "CompanyName", "Example"
   VALUE "LegalCopyright", ""
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x409, 1200
 END
END
''')
            for architecture in ('i686', 'x86_64'):
                with self.subTest(architecture=architecture):
                    target = root / (architecture + '.exe')
                    obj = root / (architecture + '.o')
                    subprocess.run([architecture + '-w64-mingw32-windres', str(resource), str(obj)], check=True, capture_output=True)
                    subprocess.run([architecture + '-w64-mingw32-gcc', str(source), str(obj), '-o', str(target)], check=True, capture_output=True)
                    original = target.read_bytes()
                    key = 'LegalCopyright'.encode('utf-16le') + b'\0\0'
                    self.assertEqual(original.count(key), 1)
                    offset = original.index(key) - 4
                    self.assertEqual(struct.unpack_from('<H', original, offset)[0], 1)
                    for length in (1, 0):
                        with self.subTest(value_length=length):
                            data = bytearray(original)
                            struct.pack_into('<H', data, offset, length)
                            target.write_bytes(data)
                            result = subprocess.run([str(NATIVE), str(target)], check=True, capture_output=True, text=True)
                            metadata = json.loads(result.stdout)
                            self.assertEqual(metadata['resource_error'], '')
                            self.assertEqual(metadata['version'], {'CompanyName': 'Example', 'LegalCopyright': ''})


if __name__ == '__main__':
    unittest.main(verbosity=2)
