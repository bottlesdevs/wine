#define COBJMACROS
#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#include <stdio.h>

struct waveforms;
struct waveform_vtbl
{
    HRESULT (WINAPI *QueryInterface)(struct waveforms *, REFIID, void **);
    ULONG (WINAPI *AddRef)(struct waveforms *);
    ULONG (WINAPI *Release)(struct waveforms *);
    HRESULT (WINAPI *GetIids)(struct waveforms *, ULONG *, IID **);
    HRESULT (WINAPI *GetRuntimeClassName)(struct waveforms *, HSTRING *);
    HRESULT (WINAPI *GetTrustLevel)(struct waveforms *, TrustLevel *);
    HRESULT (WINAPI *get_Click)(struct waveforms *, USHORT *);
    HRESULT (WINAPI *get_BuzzContinuous)(struct waveforms *, USHORT *);
    HRESULT (WINAPI *get_RumbleContinuous)(struct waveforms *, USHORT *);
    HRESULT (WINAPI *get_Press)(struct waveforms *, USHORT *);
    HRESULT (WINAPI *get_Release)(struct waveforms *, USHORT *);
};
struct waveforms { const struct waveform_vtbl *lpVtbl; };
static const GUID iid_waveforms = {0x3d577ef7,0x4cee,0x11e6,{0xb5,0x35,0x00,0x1b,0xdc,0x06,0xab,0x3b}};

int wmain(int argc, WCHAR **argv)
{
    const WCHAR *name = L"Windows.Devices.Haptics.KnownSimpleHapticsControllerWaveforms";
    struct waveforms *iface = NULL;
    HSTRING classid = NULL, runtime_name = NULL;
    HRESULT hr;
    USHORT value;
    ULONG count = 0;
    IID *iids = NULL;
    if (argc > 2 || (argc == 2 && !_wfreopen(argv[1], L"w", stdout))) return 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("POINTER_BITS=%u\n", (unsigned int)(sizeof(void *) * 8));
    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr)) return 3;
    hr = WindowsCreateString(name, wcslen(name), &classid);
    if (FAILED(hr)) goto done;
    hr = RoGetActivationFactory(classid, &iid_waveforms, (void **)&iface);
    printf("HAPTICS_FACTORY=%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) goto done;
#define CHECK_GETTER(property, expected) \
    value = 0; \
    hr = iface->lpVtbl->get_##property(iface, &value); \
    printf(#property "=%08lx VALUE=%04x\n", (unsigned long)hr, value); \
    if (FAILED(hr) || value != expected) { hr = E_FAIL; goto done; } \
    hr = iface->lpVtbl->get_##property(iface, NULL); \
    if (hr != E_POINTER) { hr = E_FAIL; goto done; }
    CHECK_GETTER(Click, 0x1003);
    CHECK_GETTER(BuzzContinuous, 0x1004);
    CHECK_GETTER(RumbleContinuous, 0x1005);
    CHECK_GETTER(Press, 0x1006);
    CHECK_GETTER(Release, 0x1007);
#undef CHECK_GETTER
    hr = iface->lpVtbl->GetRuntimeClassName(iface, &runtime_name);
    if (FAILED(hr) || wcscmp(WindowsGetStringRawBuffer(runtime_name, NULL), name))
    { hr = E_FAIL; goto done; }
    printf("RUNTIME_CLASS=PASS\n");
    hr = iface->lpVtbl->GetIids(iface, &count, &iids);
    if (FAILED(hr) || count != 1 || !IsEqualGUID(iids, &iid_waveforms))
    { hr = E_FAIL; goto done; }
    printf("STATICS_IID=PASS\n");
    hr = S_OK;
done:
    if (iface) iface->lpVtbl->Release(iface);
    CoTaskMemFree(iids);
    WindowsDeleteString(runtime_name);
    WindowsDeleteString(classid);
    RoUninitialize();
    printf("RESULT=%08lx\n", (unsigned long)hr);
    return FAILED(hr) ? 1 : 0;
}
