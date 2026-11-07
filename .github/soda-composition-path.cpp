#include <windows.h>
#include <roapi.h>
#include <windows.ui.composition.h>
#include <wrl.h>
#include <stdio.h>

using namespace ABI::Windows::Graphics;
using namespace ABI::Windows::UI::Composition;
using namespace Microsoft::WRL;

static LONG destroyed;

class GeometrySource : public RuntimeClass<RuntimeClassFlags<WinRt>, IGeometrySource2D>
{
    InspectableClass(L"Soda.GeometrySource", BaseTrust);

public:
    ~GeometrySource() { InterlockedIncrement(&destroyed); }
};

static void query(IUnknown *object, const char *name, REFIID iid)
{
    ComPtr<IUnknown> result;
    HRESULT hr = object->QueryInterface(iid, reinterpret_cast<void **>(result.GetAddressOf()));
    printf("case=%s hr=%#lx object=%d\n", name, hr, result != nullptr);
}

int main()
{
    const WCHAR class_name[] = L"Windows.UI.Composition.CompositionPath";
    ComPtr<ICompositionPathFactory> factory;
    ComPtr<ICompositionPath> path;
    ComPtr<IGeometrySource2D> source;
    HSTRING name = nullptr, runtime_name = nullptr;
    HRESULT hr;

    setvbuf(stdout, nullptr, _IONBF, 0);
    hr = RoInitialize(RO_INIT_MULTITHREADED);
    printf("case=initialize hr=%#lx\n", hr);
    if (FAILED(hr)) return 1;
    hr = WindowsCreateString(class_name, ARRAYSIZE(class_name) - 1, &name);
    if (FAILED(hr)) { RoUninitialize(); return 1; }
    hr = RoGetActivationFactory(name, IID_PPV_ARGS(factory.GetAddressOf()));
    WindowsDeleteString(name);
    printf("case=factory hr=%#lx object=%d\n", hr, factory != nullptr);
    if (FAILED(hr)) { RoUninitialize(); return 1; }
    query(factory.Get(), "factory-activation", __uuidof(IActivationFactory));
    query(factory.Get(), "factory-agile", __uuidof(IAgileObject));

    hr = factory->Create(nullptr, path.GetAddressOf());
    printf("case=null-source hr=%#lx object=%d\n", hr, path != nullptr);
    path.Reset();
    source = Make<GeometrySource>();
    if (!source) { factory.Reset(); RoUninitialize(); return 1; }
    hr = factory->Create(source.Get(), path.GetAddressOf());
    printf("case=owned-source hr=%#lx object=%d\n", hr, path != nullptr);
    if (path)
    {
        query(path.Get(), "path-geometry-source", __uuidof(IGeometrySource2D));
        query(path.Get(), "path-agile", __uuidof(IAgileObject));
        hr = path->GetRuntimeClassName(&runtime_name);
        printf("case=class-name hr=%#lx matches=%d\n", hr,
                runtime_name && !wcscmp(WindowsGetStringRawBuffer(runtime_name, nullptr), class_name));
        WindowsDeleteString(runtime_name);
        ComPtr<IUnknown> source_identity, path_identity;
        source.As(&source_identity);
        path.As(&path_identity);
        printf("case=source-identity shared=%d\n", source_identity.Get() == path_identity.Get());
    }
    source.Reset();
    printf("case=source-released destroyed=%ld\n", destroyed);
    path.Reset();
    printf("case=path-released destroyed=%ld\n", destroyed);
    factory.Reset();
    RoUninitialize();
    return 0;
}
