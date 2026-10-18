import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
ROOT = Path(os.environ['EAGLE_INTEL_STATUS_ROOT'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.intel import EagleIntel


class IntelStatus(unittest.TestCase):
    def compare(self, path):
        reference = EagleIntel(str(path))
        try:
            expected = reference.available, reference.has_artifacts
        finally:
            reference.close()
        before = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        result = subprocess.run([str(PACKAGE / 'lib/eagle/native/eagle-intel'), str(path)], input=json.dumps({'operation': 'status'}), capture_output=True, text=True, timeout=5)
        if expected[0]:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {'available': True, 'has_artifacts': expected[1], 'schema_version': '1'})
        else:
            self.assertNotEqual(result.returncode, 0)
        if before is not None:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def fixture(self, name, version='1', omit=None, artifact=False, typed=True):
        path = ROOT / name
        with sqlite3.connect(path) as database:
            database.execute('CREATE TABLE meta (key TEXT, value ' + ('TEXT' if typed else 'BLOB') + ')')
            if version is not None:
                database.execute('INSERT INTO meta VALUES (?, ?)', ('schema_version', version))
            for table in ('artifact', 'report_agg', 'software', 'trick', 'tweak'):
                if table != omit:
                    database.execute('CREATE TABLE ' + table + ' (id INTEGER)')
            if artifact:
                database.execute('INSERT INTO artifact VALUES (1)')
        return path

    def test_schema_and_artifact_flags_match_existing_database_gate(self):
        for path in (self.fixture('empty.sqlite'), self.fixture('artifact.sqlite', artifact=True),
                     self.fixture('missing.sqlite', omit='tweak'), self.fixture('version.sqlite', version='2'),
                     self.fixture('unversioned.sqlite', version=None), self.fixture('integer.sqlite', version=1, typed=False)):
            self.compare(path)
        self.compare(PACKAGE / 'lib/eagle/engine/eagle-intel.sqlite')

    def test_missing_corrupt_and_nonregular_inputs_do_not_create_files(self):
        path = ROOT / 'not-created.sqlite'
        self.compare(path)
        self.assertFalse(path.exists())
        corrupt = ROOT / 'corrupt.sqlite'
        corrupt.write_bytes(b'not a SQLite database')
        self.compare(corrupt)
        self.compare(ROOT)
        fifo = ROOT / 'database.fifo'
        os.mkfifo(fifo)
        self.compare(fifo)


if __name__ == '__main__':
    unittest.main(verbosity=2)
