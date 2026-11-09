#include <windows.h>
#include <roapi.h>
#include <windows.ui.composition.h>
#include <windows.graphics.interop.h>
#include <DispatcherQueue.h>
#include <d2d1.h>
#include <wrl.h>
#include <stdio.h>
#include <string.h>

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

static bool geometry_bounds(ID2D1Geometry *geometry, ID2D1Factory *factory, const char *name)
{
    ComPtr<ID2D1Factory> owner;
    D2D1_RECT_F bounds = {};
    HRESULT hr = geometry->GetBounds(nullptr, &bounds);
    geometry->GetFactory(owner.GetAddressOf());
    printf("case=%s hr=%#lx bounds=%g,%g,%g,%g factory=%d\n", name, hr,
            bounds.left, bounds.top, bounds.right, bounds.bottom, owner.Get() == factory);
    return SUCCEEDED(hr) && bounds.left == 1 && bounds.top == 2 && bounds.right == 30 && bounds.bottom == 40;
}

static bool shapes(ICompositionPath *path, bool clear_path)
{
    ComPtr<ABI::Windows::System::IDispatcherQueueController> queue;
    ComPtr<IInspectable> instance;
    ComPtr<ICompositor5> compositor;
    ComPtr<ICompositionPathGeometry> geometry;
    ComPtr<ICompositionPath> returned_path;
    ComPtr<ICompositionGeometry> base, returned_geometry;
    ComPtr<ICompositionSpriteShape> sprite;
    ComPtr<IShapeVisual> visual;
    ComPtr<ICompositionBrush> brush;
    ComPtr<ICompositionShape> shape;
    ComPtr<ABI::Windows::Foundation::Collections::IVector<CompositionShape *>> shapes;
    ComPtr<ABI::Windows::Foundation::Collections::IIterable<CompositionShape *>> iterable;
    ComPtr<ABI::Windows::Foundation::Collections::IIterator<CompositionShape *>> iterator;
    ABI::Windows::Foundation::Numerics::Vector2 center = {}, offset = {}, scale = {};
    ABI::Windows::Foundation::Numerics::Matrix3x2 matrix = {};
    FLOAT miter = -1;
    UINT32 size = 0;
    boolean current = false;
    DispatcherQueueOptions options = {sizeof(options), DQTYPE_THREAD_CURRENT, DQTAT_COM_NONE};
    const WCHAR class_name[] = L"Windows.UI.Composition.Compositor";
    HSTRING name = nullptr;
    FLOAT thickness = -1;
    HRESULT hr;

    hr = CreateDispatcherQueueController(options, queue.GetAddressOf());
    printf("case=shape-queue hr=%#lx object=%d\n", hr, queue != nullptr);
    if (FAILED(hr)) return false;
    hr = WindowsCreateString(class_name, ARRAYSIZE(class_name) - 1, &name);
    if (FAILED(hr)) return false;
    hr = RoActivateInstance(name, instance.GetAddressOf());
    WindowsDeleteString(name);
    printf("case=shape-compositor hr=%#lx object=%d\n", hr, instance != nullptr);
    if (FAILED(hr)) return false;
    hr = instance.As(&compositor);
    printf("case=compositor5 hr=%#lx object=%d\n", hr, compositor != nullptr);
    if (FAILED(hr)) return false;

    hr = compositor->CreatePathGeometry(geometry.GetAddressOf());
    printf("case=empty-path-geometry hr=%#lx object=%d\n", hr, geometry != nullptr);
    if (FAILED(hr) || !geometry) return false;
    hr = geometry->get_Path(returned_path.GetAddressOf());
    printf("case=empty-path-value hr=%#lx object=%d\n", hr, returned_path != nullptr);
    if (FAILED(hr)) return false;
    returned_path.Reset();
    hr = geometry->put_Path(path);
    printf("case=put-path hr=%#lx\n", hr);
    if (FAILED(hr)) return false;
    hr = geometry->get_Path(returned_path.GetAddressOf());
    printf("case=get-path hr=%#lx same=%d\n", hr, returned_path.Get() == path);
    if (FAILED(hr)) return false;
    returned_path.Reset();
    if (clear_path)
    {
        hr = geometry->put_Path(nullptr);
        printf("case=clear-path hr=%#lx\n", hr);
    }
    geometry.Reset();

    hr = compositor->CreatePathGeometryWithPath(path, geometry.GetAddressOf());
    printf("case=path-geometry hr=%#lx object=%d\n", hr, geometry != nullptr);
    if (FAILED(hr) || !geometry) return false;
    hr = geometry.As(&base);
    printf("case=geometry-interface hr=%#lx object=%d\n", hr, base != nullptr);
    if (FAILED(hr)) return false;
    hr = compositor->CreateSpriteShapeWithGeometry(base.Get(), sprite.GetAddressOf());
    printf("case=sprite-geometry hr=%#lx object=%d\n", hr, sprite != nullptr);
    if (FAILED(hr) || !sprite) return false;
    hr = sprite->get_Geometry(returned_geometry.GetAddressOf());
    printf("case=sprite-geometry-value hr=%#lx same=%d\n", hr, returned_geometry.Get() == base.Get());
    if (FAILED(hr)) return false;
    hr = sprite->get_FillBrush(brush.GetAddressOf());
    printf("case=sprite-fill hr=%#lx object=%d\n", hr, brush != nullptr);
    brush.Reset();
    hr = sprite->get_StrokeBrush(brush.GetAddressOf());
    printf("case=sprite-stroke hr=%#lx object=%d\n", hr, brush != nullptr);
    hr = sprite->get_StrokeThickness(&thickness);
    printf("case=sprite-thickness hr=%#lx value=%g\n", hr, thickness);
    hr = sprite->get_StrokeMiterLimit(&miter);
    printf("case=sprite-miter hr=%#lx value=%g\n", hr, miter);
    hr = sprite.As(&shape);
    printf("case=shape-interface hr=%#lx object=%d\n", hr, shape != nullptr);
    if (FAILED(hr)) return false;
    hr = shape->get_CenterPoint(&center);
    printf("case=shape-center hr=%#lx value=%g,%g\n", hr, center.X, center.Y);
    hr = shape->get_Offset(&offset);
    printf("case=shape-offset hr=%#lx value=%g,%g\n", hr, offset.X, offset.Y);
    hr = shape->get_Scale(&scale);
    printf("case=shape-scale hr=%#lx value=%g,%g\n", hr, scale.X, scale.Y);
    hr = shape->get_TransformMatrix(&matrix);
    printf("case=shape-transform hr=%#lx value=%g,%g,%g,%g,%g,%g\n", hr,
            matrix.M11, matrix.M12, matrix.M21, matrix.M22, matrix.M31, matrix.M32);
    hr = compositor->CreateShapeVisual(visual.GetAddressOf());
    printf("case=shape-visual hr=%#lx object=%d\n", hr, visual != nullptr);
    if (FAILED(hr) || !visual) return false;
    hr = visual->get_Shapes(shapes.GetAddressOf());
    printf("case=shape-collection hr=%#lx object=%d\n", hr, shapes != nullptr);
    if (FAILED(hr) || !shapes) return false;
    hr = shapes->get_Size(&size);
    printf("case=shape-count hr=%#lx value=%u\n", hr, size);
    hr = shapes->Append(shape.Get());
    printf("case=shape-append hr=%#lx\n", hr);
    if (FAILED(hr)) return false;
    hr = shapes->get_Size(&size);
    printf("case=shape-appended-count hr=%#lx value=%u\n", hr, size);
    if (FAILED(hr) || size != 1) return false;
    hr = shapes.As(&iterable);
    printf("case=shape-iterable hr=%#lx object=%d\n", hr, iterable != nullptr);
    if (FAILED(hr)) return false;
    hr = iterable->First(iterator.GetAddressOf());
    printf("case=shape-first hr=%#lx object=%d\n", hr, iterator != nullptr);
    if (FAILED(hr)) return false;
    hr = iterator->get_HasCurrent(&current);
    printf("case=shape-current hr=%#lx value=%d\n", hr, current);
    hr = shapes->Clear();
    printf("case=shape-clear hr=%#lx\n", hr);
    if (FAILED(hr)) return false;
    hr = iterator->get_HasCurrent(&current);
    printf("case=shape-changed-iterator hr=%#lx value=%d\n", hr, current);
    return true;
}

int main(int argc, char **argv)
{
    const WCHAR class_name[] = L"Windows.UI.Composition.CompositionPath";
    ComPtr<ICompositionPathFactory> factory;
    ComPtr<ICompositionPath> path;
    ComPtr<IGeometrySource2D> source;
    ComPtr<ID2D1Factory> d2d;
    ComPtr<ID2D1RectangleGeometry> geometry;
    HSTRING name = nullptr, runtime_name = nullptr;
    HRESULT hr;
    bool created, bounds_ok = true;
    bool clear_path = argc > 1 && !strcmp(argv[1], "clear-path");

    setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
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
        ComPtr<IGeometrySource2DInterop> interop;
        ComPtr<ID2D1Geometry> returned;
        ComPtr<ID2D1Factory> other_factory;
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
        hr = path.As(&interop);
        if (SUCCEEDED(hr))
        {
            hr = interop->GetGeometry(returned.GetAddressOf());
            printf("case=get-geometry hr=%#lx same=%d\n", hr, returned.Get() == geometry.Get());
            if (SUCCEEDED(hr) && returned) bounds_ok &= geometry_bounds(returned.Get(), d2d.Get(), "get-geometry-bounds");
            else bounds_ok = false;
            returned.Reset();
            hr = interop->TryGetGeometryUsingFactory(d2d.Get(), returned.GetAddressOf());
            printf("case=same-factory hr=%#lx same=%d\n", hr, returned.Get() == geometry.Get());
            if (SUCCEEDED(hr) && returned) bounds_ok &= geometry_bounds(returned.Get(), d2d.Get(), "same-factory-bounds");
            else bounds_ok = false;
            returned.Reset();
            hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, other_factory.GetAddressOf());
            if (SUCCEEDED(hr))
            {
                hr = interop->TryGetGeometryUsingFactory(other_factory.Get(), returned.GetAddressOf());
                printf("case=other-factory hr=%#lx object=%d\n", hr, returned != nullptr);
                if (SUCCEEDED(hr) && returned) bounds_ok &= geometry_bounds(returned.Get(), other_factory.Get(), "other-factory-bounds");
                else bounds_ok = false;
            }
            else printf("case=other-factory-create hr=%#lx\n", hr);
        }
    }
    if (created && !shapes(path.Get(), clear_path)) created = false;
    source.Reset();
    printf("case=source-released destroyed=%ld\n", destroyed);
    path.Reset();
    printf("case=path-released destroyed=%ld\n", destroyed);
    printf("case=source-calls geometry=%ld factory=%ld\n", geometry_calls, factory_calls);
    geometry.Reset();
    d2d.Reset();
    factory.Reset();
    RoUninitialize();
    return created && bounds_ok ? 0 : 1;
}
