#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <stdio.h>

#ifndef BUILD_MIME_PROVIDER
static const CLSID test_class = {0x79f2a84b, 0xf5de, 0x4c47, {0x81, 0x92, 0x93, 0x40, 0xe7, 0x14, 0x50, 0x68}};
#endif
#ifndef BUILD_MAPI_PROVIDER
static const CLSID mime_class = {0x79f2a84d, 0xf5de, 0x4c47, {0x81, 0x92, 0x93, 0x40, 0xe7, 0x14, 0x50, 0x68}};
#endif

static LONG references;

static HRESULT WINAPI factory_QueryInterface(IClassFactory *iface, REFIID iid, void **object)
{
    *object = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_IClassFactory))
        return E_NOINTERFACE;
    *object = iface;
    IClassFactory_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI factory_AddRef(IClassFactory *iface)
{
    (void)iface;
    return InterlockedIncrement(&references);
}

static ULONG WINAPI factory_Release(IClassFactory *iface)
{
    (void)iface;
    return InterlockedDecrement(&references);
}

static HRESULT WINAPI factory_CreateInstance(IClassFactory *iface, IUnknown *outer, REFIID iid, void **object)
{
    (void)iface;
    (void)outer;
    (void)iid;
    *object = NULL;
    return E_NOTIMPL;
}

static HRESULT WINAPI factory_LockServer(IClassFactory *iface, BOOL lock)
{
    (void)iface;
    (void)lock;
    return S_OK;
}

static IClassFactoryVtbl factory_vtbl =
{
    factory_QueryInterface,
    factory_AddRef,
    factory_Release,
    factory_CreateInstance,
    factory_LockServer
};

static IClassFactory factory = {&factory_vtbl};

#if defined(BUILD_MAPI_PROVIDER) || defined(BUILD_MIME_PROVIDER)
__declspec(dllexport) HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **object)
{
    *object = NULL;
#ifdef BUILD_MIME_PROVIDER
    if (!IsEqualCLSID(clsid, &mime_class)) return CLASS_E_CLASSNOTAVAILABLE;
#else
    if (!IsEqualCLSID(clsid, &test_class)) return CLASS_E_CLASSNOTAVAILABLE;
#endif
    return IClassFactory_QueryInterface(&factory, iid, object);
}
#ifdef BUILD_MIME_PROVIDER
__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void)
{
    return references ? S_FALSE : S_OK;
}
#endif
#else
static const CLSID missing_class = {0x79f2a84c, 0xf5de, 0x4c47, {0x81, 0x92, 0x93, 0x40, 0xe7, 0x14, 0x50, 0x68}};

int main(int argc, char **argv)
{
    IClassFactory *object;
    IClassFactory *mime = NULL;
    HMODULE module;
    HRESULT hr;
    DWORD cookie = 0;
    unsigned int failures = 0;

    if (argc != 2 && argc != 3) return 2;
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return 3;

    object = NULL;
    hr = CoGetClassObject(&test_class, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&object);
    if (SUCCEEDED(hr) || object) ++failures;
    if (object) IClassFactory_Release(object);
    if (GetModuleHandleW(L"OLMAPI32.DLL")) ++failures;
    object = NULL;
    hr = CoGetClassObject(&mime_class, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&object);
    if (SUCCEEDED(hr) || object) ++failures;
    if (object) IClassFactory_Release(object);
    if (GetModuleHandleW(L"OUTLMIME.DLL")) ++failures;

    module = LoadLibraryA(argv[1]);
    if (!module) return 4;
    object = NULL;
    hr = CoGetClassObject(&test_class, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&object);
    printf("loaded_provider_class=%#lx\n", hr);
    if (FAILED(hr) || !object) ++failures;
    if (object) IClassFactory_Release(object);

    if (argc == 3)
    {
        object = NULL;
        hr = CoGetClassObject(&mime_class, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&object);
        if (hr != CLASS_E_CLASSNOTAVAILABLE || object) ++failures;
        if (object) IClassFactory_Release(object);
        if (GetModuleHandleW(L"OUTLMIME.DLL")) ++failures;
        FreeLibrary(module);
        CoUninitialize();
        printf("MAPI_CLIENT_ABSENT_MIME_RESULT failures=%u\n", failures);
        return failures != 0;
    }

    object = NULL;
    hr = CoGetClassObject(&mime_class, CLSCTX_LOCAL_SERVER, NULL, &IID_IClassFactory, (void **)&object);
    if (SUCCEEDED(hr) || object) ++failures;
    if (object) IClassFactory_Release(object);
    if (GetModuleHandleW(L"OUTLMIME.DLL")) ++failures;

    hr = CoGetClassObject(&mime_class, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&mime);
    printf("mime_provider_class=%#lx\n", hr);
    if (FAILED(hr) || !mime) ++failures;
    if (!GetModuleHandleW(L"OUTLMIME.DLL")) ++failures;
    object = NULL;
    hr = CoGetClassObject(&mime_class, CLSCTX_INPROC_SERVER, NULL, &IID_IStream, (void **)&object);
    if (hr != E_NOINTERFACE || object) ++failures;
    if (object) IClassFactory_Release(object);

    object = NULL;
    hr = CoGetClassObject(&missing_class, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&object);
    if (SUCCEEDED(hr) || object) ++failures;
    if (object) IClassFactory_Release(object);

    object = NULL;
    hr = CoGetClassObject(&test_class, CLSCTX_INPROC_SERVER, NULL, &IID_IStream, (void **)&object);
    if (hr != E_NOINTERFACE || object) ++failures;
    if (object) IClassFactory_Release(object);

    object = NULL;
    hr = CoGetClassObject(&test_class, CLSCTX_LOCAL_SERVER, NULL, &IID_IClassFactory, (void **)&object);
    if (SUCCEEDED(hr) || object) ++failures;
    if (object) IClassFactory_Release(object);

    hr = CoRegisterClassObject(&test_class, (IUnknown *)&factory, CLSCTX_INPROC_SERVER,
            REGCLS_MULTIPLEUSE, &cookie);
    if (FAILED(hr)) ++failures;
    else
    {
        object = NULL;
        hr = CoGetClassObject(&test_class, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&object);
        if (FAILED(hr) || object != &factory) ++failures;
        if (object) IClassFactory_Release(object);
        hr = CoRevokeClassObject(cookie);
        if (FAILED(hr)) ++failures;
    }

    FreeLibrary(module);
    if (GetModuleHandleW(L"OLMAPI32.DLL")) ++failures;
    if (mime)
    {
        CoFreeUnusedLibrariesEx(0, 0);
        if (!GetModuleHandleW(L"OUTLMIME.DLL")) ++failures;
        object = NULL;
        hr = IClassFactory_QueryInterface(mime, &IID_IUnknown, (void **)&object);
        if (FAILED(hr) || object != mime) ++failures;
        if (object) IClassFactory_Release(object);
        IClassFactory_Release(mime);
    }
    object = NULL;
    hr = CoGetClassObject(&test_class, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void **)&object);
    if (SUCCEEDED(hr) || object) ++failures;
    if (object) IClassFactory_Release(object);
    CoUninitialize();
    if (GetModuleHandleW(L"OUTLMIME.DLL")) ++failures;
    printf("MAPI_CLIENT_RESULT failures=%u\n", failures);
    return failures != 0;
}
#endif
