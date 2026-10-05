#define COBJMACROS
#define INITGUID
#include <windows.h>
#include <objbase.h>
#include <objidl.h>
#include <stdio.h>

static const CLSID global_interface_table = {0x00000323,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const CLSID missing_class = {0xc0decafe,0x1234,0x4321,{0x80,0x01,0x00,0x01,0x02,0x03,0x04,0x05}};

int main(int argc, char **argv)
{
    HRESULT hr;
    IClassFactory *factory = NULL;
    MULTI_QI interfaces[2] = {{&IID_IUnknown, NULL, 0}, {&IID_IGlobalInterfaceTable, NULL, 0}};
    MULTI_QI partial[3] = {{&IID_IUnknown, NULL, 0}, {&IID_IGlobalInterfaceTable, NULL, 0}, {&missing_class, NULL, 0}};
    DWORD error;
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr != S_OK) return 1;
    if (CoInitializeEx(NULL, COINIT_APARTMENTTHREADED) != RPC_E_CHANGED_MODE) return 2;
    SetLastError(0x12345678);
    hr = CoGetClassObject(&missing_class, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&factory);
    error = GetLastError();
    if (hr != CLASS_E_CLASSNOTAVAILABLE) return 3;
    hr = CoCreateInstanceEx(&global_interface_table, NULL, CLSCTX_INPROC_SERVER, NULL, 2, interfaces);
    if (hr != S_OK || interfaces[0].hr != S_OK || interfaces[1].hr != S_OK || !interfaces[0].pItf || !interfaces[1].pItf) return 4;
    IUnknown_Release(interfaces[0].pItf); IUnknown_Release(interfaces[1].pItf);
    hr = CoCreateInstanceEx(&global_interface_table, NULL, CLSCTX_INPROC_SERVER, NULL, 3, partial);
    if (hr != CO_S_NOTALLINTERFACES || partial[0].hr != S_OK || partial[1].hr != S_OK || partial[2].hr != E_NOINTERFACE || partial[2].pItf) return 7;
    IUnknown_Release(partial[0].pItf); IUnknown_Release(partial[1].pItf);
    CoUninitialize();
    if (argc > 1)
    {
        FILE *output = fopen(argv[1], "wb");
        if (!output) return 5;
        if (fwrite(&error, sizeof(error), 1, output) != 1) return 6;
        fclose(output);
    }
    return 0;
}
