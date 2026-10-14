import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(os.environ['EAGLE_PACKAGE']) / 'lib/eagle'
CONFIG = json.loads((ROOT / 'analysis.json').read_text())
# DLL_MAPPINGS from Bottles 41e363c7f8dba418f0b7b6f09fa787ca5aa8ff48.
MAPPING_SHA256 = '8a383b62246216c55b400524ed8e643aba4593435aa53e5c6dddeebcb8ced876'


def image(library, machine, delayed=False, legacy=False, fallback=False):
    wide = machine != 0x14c
    optional_size = 240 if wide else 224
    optional = 0x98
    directories = optional + (112 if wide else 96)
    data = bytearray(0x600)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    struct.pack_into('<4sHHIIIHH', data, 0x80, b'PE\0\0', machine, 2, 1700000000, 0, 0, optional_size, 2)
    struct.pack_into('<H', data, optional, 0x20b if wide else 0x10b)
    struct.pack_into('<II', data, optional + 4, 0x200, 0x200)
    struct.pack_into('<II', data, optional + 16, 0x1000, 0x1000)
    if not wide:
        struct.pack_into('<I', data, optional + 24, 0x2000)
    struct.pack_into('<Q' if wide else '<I', data, optional + (24 if wide else 28), 0x140000000 if wide else 0x400000)
    struct.pack_into('<II', data, optional + 32, 0x1000, 0x200)
    struct.pack_into('<HH', data, optional + 40, 10, 0)
    struct.pack_into('<II', data, optional + 56, 0x3000, 0x200)
    struct.pack_into('<HH', data, optional + 68, 3, 0x140)
    struct.pack_into('<I', data, directories - 4, 16)
    code = struct.pack('<II', 0x52800000, 0xd65f03c0) if machine == 0xaa64 else b'\x31\xc0\xc3'
    data[0x200:0x200 + len(code)] = code
    struct.pack_into('<8sIIIIIIHHI', data, optional + optional_size, b'.text\0\0\0',
                     len(code), 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into('<8sIIIIIIHHI', data, optional + optional_size + 40, b'.idata\0\0',
                     0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0xc0000040)
    struct.pack_into('<II', data, directories + (13 if delayed else 1) * 8, 0x2000, 64 if delayed else 40)
    if delayed:
        base = 0x400000 if legacy else 0
        struct.pack_into('<8I', data, 0x400, 0 if legacy else 1,
                         base + 0x2050, 0, base + 0x2080, base + 0x2080, 0, 0, 0)
    else:
        struct.pack_into('<5I', data, 0x400, 0 if fallback else 0x2080, 0, 0, 0x2050, 0x2080)
    name = library.encode('ascii') + b'\0'
    if len(name) > 48:
        raise ValueError('fixture library name exceeds reserved space')
    data[0x450:0x450 + len(name)] = name
    struct.pack_into('<Q' if wide else '<I', data, 0x480, 0x2090 + (0x400000 if legacy else 0))
    data[0x490:0x49e] = b'\0\0EagleMarker\0'
    return data


class ImportTests(unittest.TestCase):
    def parse(self, path):
        result = subprocess.run([str(ROOT / 'native/eagle-pe'), str(path)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def interpret(self, structure):
        request = dict(operation='pe-insights', structure=structure, basename='app.exe',
                       details={name: [] for name in {value[1] for value in CONFIG['mapping'].values()} | {'Warning'}},
                       metadata={}, compilers=CONFIG['compilers'], packers=CONFIG['packers'], mapping=CONFIG['mapping'])
        result = subprocess.run([str(ROOT / 'native/eagle-analysis')], input=json.dumps(request),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_mapping_matches_pinned_original(self):
        mapping = json.dumps(CONFIG['mapping'], sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(len(CONFIG['mapping']), 80)
        self.assertEqual(hashlib.sha256(mapping).hexdigest(), MAPPING_SHA256)

    def test_normal_and_delay_maps_on_all_machines(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'app.exe'
            for machine in (0x14c, 0x8664, 0xaa64):
                for library, (name, category) in CONFIG['mapping'].items():
                    for delayed in (False, True):
                        with self.subTest(machine=machine, library=library, delayed=delayed):
                            spelling = library.upper() if delayed else library
                            target.write_bytes(image(spelling, machine, delayed))
                            structure = self.parse(target)
                            self.assertEqual(structure['imports'], [{'name': spelling, 'delay': delayed}])
                            details = self.interpret(structure)['details']
                            self.assertEqual(details[category], [{'name': name, 'source': 'Imports'}])

    def test_legacy_delay_addresses_and_missing_original_thunk(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'app.exe'
            for delayed, legacy, fallback in ((True, True, False), (False, False, True)):
                with self.subTest(delayed=delayed, legacy=legacy, fallback=fallback):
                    target.write_bytes(image('D3D11.DLL', 0x14c, delayed, legacy, fallback))
                    structure = self.parse(target)
                    self.assertEqual(structure['imports'], [{'name': 'D3D11.DLL', 'delay': delayed}])
                    self.assertEqual(self.interpret(structure)['details']['Graphics'], [{'name': 'DirectX 11', 'source': 'Imports'}])

    def test_unknown_libraries_and_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'app.exe'
            target.write_bytes(image('EagleUnknown.dll', 0x8664))
            structure = self.parse(target)
            self.assertFalse(any(item.get('source') == 'Imports' for items in self.interpret(structure)['details'].values() for item in items))
            structure['imports'] = [{'name': name, 'delay': delayed} for name, delayed in (
                ('NVAPI.DLL', False), ('nvapi64.dll', True), ('NvApi.dll', True), ('EagleUnknown.dll', False))]
            result = self.interpret(structure)
            self.assertEqual(result['details']['Graphics'], [{'name': 'NVAPI', 'source': 'Imports'}])
            self.assertIn('Found 3 imported libraries', result['steps'])

    def test_runtime_suggestions_have_stable_order(self):
        names = ['.NET Core/5+', '.NET Core CLR']
        for runtimes in (names, names[::-1]):
            request = dict(operation='recommend', details={'Runtimes': runtimes},
                           metadata={'is_packed': False}, is_net=False,
                           dpi_aware=True, ue_shipping_exe=None, intel=None)
            result = subprocess.run([str(ROOT / 'native/eagle-analysis')], input=json.dumps(request),
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['suggestions'],
                             [{'key': 'dep_dotnet', 'value': False, 'label': name} for name in sorted(names)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
