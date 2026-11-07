#include <windows.h>
#include <roapi.h>
#include <windows.ui.composition.h>
#include <windows.graphics.interop.h>
#include <d2d1.h>
#include <wrl.h>
#include <stdio.h>

using namespace ABI::Windows::Graphics;
using namespace ABI::Windows::UI::Composition;
using namespace Microsoft::WRL;

static LONG destroyed, geometry_calls, factory_calls;

class BareGeometrySource : public RuntimeClass<RuntimeClassFlags<WinRt>, IGeometrySource2D>
{
    InspectableClass(L"Soda.GeometrySource", BaseTrust);
};

class GeometrySource : public RuntimeClass<RuntimeClassFlags<WinRtClassicComMix>,
                                         IGeometrySource2D, IGeometrySource2DInterop>
{
    InspectableClass(L"Soda.GeometrySource", BaseTrust);
    ComPtr<ID2D1Geometry> geometry;

public:
    explicit GeometrySource(ID2D1Geometry *value) : geometry(value) {}
    ~GeometrySource() { InterlockedIncrement(&destroyed); }

    HRESULT STDMETHODCALLTYPE GetGeometry(ID2D1Geometry **value) override
    {
        InterlockedIncrement(&geometry_calls);
        return geometry.CopyTo(value);
    }

    HRESULT STDMETHODCALLTYPE TryGetGeometryUsingFactory(ID2D1Factory *factory, ID2D1Geometry **value) override
    {
        ComPtr<ID2D1Factory> owner;
        InterlockedIncrement(&factory_calls);
        if (!value) return E_POINTER;
        *value = nullptr;
        geometry->GetFactory(owner.GetAddressOf());
        return owner.Get() == factory ? geometry.CopyTo(value) : S_OK;
    }
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
    ComPtr<ID2D1Factory> d2d;
    ComPtr<ID2D1RectangleGeometry> geometry;
    HSTRING name = nullptr, runtime_name = nullptr;
    HRESULT hr;
    bool created;

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
    source = Make<BareGeometrySource>();
    if (!source) { factory.Reset(); RoUninitialize(); return 1; }
    hr = factory->Create(source.Get(), path.GetAddressOf());
    printf("case=bare-source hr=%#lx object=%d\n", hr, path != nullptr);
    path.Reset();
    source.Reset();
    hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, d2d.GetAddressOf());
    printf("case=d2d-factory hr=%#lx\n", hr);
    if (FAILED(hr)) { factory.Reset(); RoUninitialize(); return 1; }
    hr = d2d->CreateRectangleGeometry(D2D1::RectF(1, 2, 30, 40), geometry.GetAddressOf());
    printf("case=rectangle hr=%#lx\n", hr);
    if (FAILED(hr)) { d2d.Reset(); factory.Reset(); RoUninitialize(); return 1; }
    source = Make<GeometrySource>(geometry.Get());
    if (!source) { geometry.Reset(); d2d.Reset(); factory.Reset(); RoUninitialize(); return 1; }
    hr = factory->Create(source.Get(), path.GetAddressOf());
    printf("case=owned-source hr=%#lx object=%d\n", hr, path != nullptr);
    created = SUCCEEDED(hr) && path != nullptr;
    if (path)
    {
        query(path.Get(), "path-geometry-source", __uuidof(IGeometrySource2D));
        query(path.Get(), "path-agile", __uuidof(IAgileObject));
        query(path.Get(), "path-geometry-interop", __uuidof(IGeometrySource2DInterop));
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
    printf("case=source-calls geometry=%ld factory=%ld\n", geometry_calls, factory_calls);
    geometry.Reset();
    d2d.Reset();
    factory.Reset();
    RoUninitialize();
    return created ? 0 : 1;
}
