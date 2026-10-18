import os
from pathlib import Path
import sys
import time
import unittest

PACKAGE = Path(os.environ['EAGLE_PACKAGE'])
ROOT = Path(os.environ['EAGLE_STEAM_TEST_ROOT'])
sys.path.insert(0, str(PACKAGE / 'lib/eagle'))
from engine.intel import EagleIntel


class SteamIdentification(unittest.TestCase):
    def compare(self, target):
        expected = EagleIntel.find_steam_appid_legacy(str(target))
        self.assertEqual(EagleIntel.find_steam_appid(str(target)), expected)
        return expected

    def test_text_file_tokens_unicode_and_parent_precedence(self):
        directory = ROOT / 'text/app'
        directory.mkdir(parents=True)
        target = directory / 'app.exe'
        local = directory / 'steam_appid.txt'
        parent = directory.parent / 'steam_appid.txt'
        parent.write_text('5678')
        for contents in ('', 'abc', '1234', ' 1234 trailing', '\u20031234\u001ctrailing', '\u0661\u0662', '\u00b2\u00b3', '\ufeff1234', '1234 \x00ignored', '1234\x00'):
            local.write_text(contents)
            self.compare(target)
        local.unlink()
        self.assertEqual(self.compare(target), '5678')
        parent.unlink()
        self.assertEqual(self.compare(target), '')
        for character in (chr(i) for i in range(0x110000) if chr(i).isdigit()):
            local.write_text(character)
            self.assertEqual(self.compare(target), character)

    def test_manifest_matching_invalid_bytes_nuls_and_casefold(self):
        steamapps = ROOT / 'manifests/steamapps'
        directory = steamapps / 'common/STRASSE/bin'
        directory.mkdir(parents=True)
        target = directory / 'app.exe'
        manifest = steamapps / 'appmanifest_1234.acf'
        cases = [b'"installdir" "Other" "appid" "1234"',
                 '"installdir" "Stra\u00dfe" "appid" "1234"'.encode(),
                 b'\xff"installdir" "STRASSE" "appid" "12\xff34"',
                 b'\x00"installdir" "STRASSE" "appid" "1234"',
                 b'"installdir" "STRASSE\x00other" "appid" "1234"',
                 b'"installdir"\x1c"STRASSE" "appid"\x1f"1234"',
                 '"installdir" "STRASSE" "appid" "\u0661\u0662"'.encode(),
                 b'"installdir" "STRASSE" "appid" "bad"']
        for contents in cases:
            manifest.write_bytes(contents)
            self.compare(target)
        manifest.write_text('"installdir" "STRASSE" "appid" "1234"')
        (directory / 'steam_appid.txt').write_text('9999')
        self.assertEqual(self.compare(target), '9999')

    def test_missing_metadata_fifo_and_size_controls(self):
        directory = ROOT / 'bounds'
        directory.mkdir()
        target = directory / 'app.exe'
        self.assertEqual(self.compare(target), '')
        metadata = directory / 'steam_appid.txt'
        os.mkfifo(metadata)
        started = time.monotonic()
        self.assertEqual(EagleIntel.find_steam_appid(str(target)), '')
        self.assertLess(time.monotonic() - started, 2)
        metadata.unlink()
        metadata.write_bytes(b'1' * (1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, 'exceeds byte limit'):
            EagleIntel.find_steam_appid(str(target))


if __name__ == '__main__':
    unittest.main(verbosity=2)
