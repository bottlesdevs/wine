import hashlib
import os
from pathlib import Path
import sys
import time
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
ROOT = Path(os.environ['EAGLE_HASH_TEST_ROOT'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.native import artifact_hashes, PE


class NativeHashes(unittest.TestCase):
    def test_file_and_import_digests_match_existing_algorithms(self):
        for index, content in enumerate((b'', b'abc', bytes(range(256)), b'abc\x00xyz' * 200000)):
            path = ROOT / f'file-{index}'
            path.write_bytes(content)
            for imports in ('', 'kernel32.createfilea,user32.messageboxa', 'test.ord17', 'test.\u00e9'):
                result = artifact_hashes(path, imports)
                self.assertEqual(result['sha256'], hashlib.sha256(content).hexdigest())
                self.assertEqual(result['imphash'], hashlib.md5(imports.encode()).hexdigest() if imports else '')

    def test_unreadable_and_nonregular_inputs_do_not_block(self):
        fifo = ROOT / 'fifo'
        os.mkfifo(fifo)
        started = time.monotonic()
        for path in (ROOT / 'missing', ROOT, fifo):
            result = artifact_hashes(path, 'kernel32.createfilea')
            self.assertEqual(result['sha256'], '')
            self.assertEqual(result['imphash'], hashlib.md5(b'kernel32.createfilea').hexdigest())
        self.assertLess(time.monotonic() - started, 3)

    def test_regular_symlink_and_real_pe_import_hash(self):
        target = Path(os.environ['EAGLE_TEST_ROOT']) / 'target64.exe'
        link = ROOT / 'target.exe'
        link.symlink_to(target)
        pe = PE(link)
        expected = hashlib.md5(pe.data['imphash_material'].encode()).hexdigest()
        self.assertEqual(pe.get_imphash(), expected)
        self.assertEqual(artifact_hashes(link)['sha256'], hashlib.sha256(target.read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main(verbosity=2)
