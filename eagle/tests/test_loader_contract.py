from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from session import fingerprint


class LoaderContract(unittest.TestCase):
    def event(self, **changes):
        data = dict(provider=32, event='loader.GetProcAddress', hresult='0x00000000',
                    name='EagleLoaderValue', ordinal=0, module='0x10000000', address='0x10001234', caller='0x4567')
        data.update(changes)
        return dict(kind='provider', data=data)

    def test_comparison_ignores_mapped_addresses(self):
        self.assertEqual(fingerprint(self.event()),
                         fingerprint(self.event(module='0x20000000', address='0x20001234', caller='0x7890')))

    def test_native_comparison_ignores_mapped_addresses(self):
        event = self.event(provider=64, event='loader.LdrGetProcedureAddress', ntstatus='0x00000000')
        moved = self.event(provider=64, event='loader.LdrGetProcedureAddress', ntstatus='0x00000000',
                           module='0x20000000', address='0x20001234', caller='0x7890')
        self.assertEqual(fingerprint(event), fingerprint(moved))
        self.assertNotEqual(fingerprint(event), fingerprint(self.event(provider=64,
                            event='loader.LdrGetProcedureAddress', ntstatus='0xc000007a')))

    def test_comparison_keeps_requested_symbols_and_results(self):
        original = fingerprint(self.event())
        for change in ({'name': 'OtherExport'}, {'ordinal': 9}, {'hresult': '0x8007007f'}):
            self.assertNotEqual(original, fingerprint(self.event(**change)))


if __name__ == '__main__':
    unittest.main()
