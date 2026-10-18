import json
import os
from pathlib import Path
import subprocess
import unittest
import pefile
import hashlib

NATIVE = Path(os.environ["EAGLE_PACKAGE"]) / "lib/eagle/native/eagle-pe"
FIXTURES = Path(os.environ["EAGLE_TEST_ROOT"])
RUNNER = Path(os.environ["EAGLE_TEST_WINE"]).parents[1]

class NativePE(unittest.TestCase):
    def test_metadata_and_imports_against_current_parser(self):
        paths = list(FIXTURES.glob("*.exe")) + list((RUNNER / "lib/wine/x86_64-windows").glob("*.dll"))
        self.assertGreater(len(paths), 100)
        for path in paths:
            with self.subTest(path=path.name):
                result = subprocess.run([str(NATIVE), str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                native = json.loads(result.stdout)
                pe = pefile.PE(str(path))
                self.assertEqual(native["machine"], pe.FILE_HEADER.Machine)
                self.assertEqual(native["timestamp"], pe.FILE_HEADER.TimeDateStamp)
                self.assertEqual(native["size"], pe.OPTIONAL_HEADER.SizeOfImage)
                self.assertEqual(native["entry_rva"], pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                self.assertEqual(native["dll_characteristics"], pe.OPTIONAL_HEADER.DllCharacteristics)
                expected = [{"name": entry.dll.decode(), "delay": False} for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
                expected += [{"name": entry.dll.decode(), "delay": True} for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])]
                self.assertEqual(native["imports"], expected)
                material = native["imphash_material"]
                self.assertEqual(hashlib.md5(material.encode()).hexdigest() if expected else "", pe.get_imphash())
                if getattr(pe, "FileInfo", None):
                    expected_version = {}
                    for info in pe.FileInfo[0]:
                        if info.Key == b"StringFileInfo":
                            for table in info.StringTable:
                                expected_version.update({key.decode(): value.decode() for key, value in table.entries.items()})
                    self.assertEqual(native["version"], expected_version)
                pe.close()

    def test_bad_input_is_rejected(self):
        for name, data in [("empty", b""), ("dos", b"MZ" + bytes(100)), ("outside", b"MZ" + bytes(58) + b"\xff"*4)]:
            path = FIXTURES / (name + ".bad")
            path.write_bytes(data)
            result = subprocess.run([str(NATIVE), str(path)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(result.stderr)

if __name__ == "__main__":
    unittest.main(verbosity=2)
