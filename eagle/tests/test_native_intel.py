import json
import os
from pathlib import Path
import random
import sqlite3
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engine.intel import EagleIntel, PACKAGED_DB_PATH
from engine.intel import SOURCE_ATTRIBUTION, LAUNCH_FLAG_MAP, PROTON_ENV_MAP


class NativeIntelTests(unittest.TestCase):
    def test_plan_matches_existing_engine(self):
        reference = EagleIntel(PACKAGED_DB_PATH)
        self.addCleanup(reference.close)
        connection = sqlite3.connect(PACKAGED_DB_PATH)
        self.addCleanup(connection.close)
        names = [row[0] for row in connection.execute("SELECT name FROM software WHERE source = 'winetricks'")]
        community = [row[0] for row in connection.execute("SELECT DISTINCT s.name FROM software s JOIN tweak t ON t.software_id = s.id WHERE s.source != 'winetricks'")]
        names += random.Random(9283).sample(community, min(300, len(community)))
        constants = dict(sources=SOURCE_ATTRIBUTION, launch_flags=LAUNCH_FLAG_MAP, proton_env=PROTON_ENV_MAP, override_modes=EagleIntel._OVERRIDE_MODES)
        hits = [reference.lookup(product_name=name) for name in names]
        hits = [hit for hit in hits if hit]
        self.assertGreater(len(hits), 100)
        for hit in hits:
            with self.subTest(name=hit['software']['name']):
                request = dict(operation='plan', hit=hit, constants=constants)
                result = subprocess.run([os.environ['EAGLE_INTEL_NATIVE'], PACKAGED_DB_PATH], input=json.dumps(request), capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), reference.plan(hit))

    def test_lookup_matches_existing_engine(self):
        command = os.environ['EAGLE_INTEL_NATIVE']
        reference = EagleIntel(PACKAGED_DB_PATH)
        self.addCleanup(reference.close)
        connection = sqlite3.connect(PACKAGED_DB_PATH)
        self.addCleanup(connection.close)
        rows = connection.execute('SELECT name, steam_appid FROM software ORDER BY id').fetchall()
        sample = random.Random(9283).sample(rows, min(150, len(rows)))
        requests = [{'product_name': name} for name, _ in sample]
        requests += [{'product_name': name.swapcase()} for name, _ in sample[:30]]
        requests += [{'product_name': name + ' edition'} for name, _ in sample[:30]]
        requests += [{'steam_appid': str(appid)} for _, appid in sample if appid]
        requests += [{'product_name': value} for value in ('', 'Unknown', 'setup', 'game', 'launcher', 'Straße 2', 'APPLICATION', 'nonexistent application 9283')]
        requests += [{'names': ['Unknown', name]} for name, _ in sample[:20]]
        for sha256, imphash in connection.execute('SELECT sha256, imphash FROM artifact LIMIT 20'):
            if sha256:
                requests.append({'sha256': sha256})
            if imphash:
                requests.append({'imphash': imphash})
        for request in requests:
            with self.subTest(request=request):
                result = subprocess.run([command, PACKAGED_DB_PATH], input=json.dumps(request), capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), reference.lookup(**request))

    def test_invalid_requests_fail(self):
        for request in ('[]', '{', '{"names": [42]}', '{"product_name": 42}'):
            result = subprocess.run([os.environ['EAGLE_INTEL_NATIVE'], PACKAGED_DB_PATH], input=request, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
