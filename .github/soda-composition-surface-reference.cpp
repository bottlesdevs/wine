#include <windows.h>
#include <roapi.h>
#include <windows.system.h>
#include <dispatcherqueue.h>
#include <windows.ui.composition.h>
#include <windows.ui.composition.interop.h>
#include <d3d11.h>
#include <d2d1_1.h>
#include <wrl.h>
#include <stdio.h>

using namespace ABI::Windows::UI::Composition;
using namespace Microsoft::WRL;

static bool check(const char *name, HRESULT hr)
{
    printf("case=%s hr=%#lx\n", name, hr);
    return SUCCEEDED(hr);
}

static void record(const char *surface, const char *api, unsigned round,
                   const char *operation, HRESULT hr)
{
    printf("surface=%s api=%s round=%u operation=%s hr=%#lx\n", surface, api, round, operation, hr);
}

static bool observe(ICompositionDrawingSurfaceInterop *surface, const char *kind,
                    const char *api, REFIID iid)
{
    bool began = false;
    for (unsigned round = 0; round < 2; ++round)
    {
        RECT rect = round ? RECT{4, 8, 36, 24} : RECT{0, 0, 128, 64};
        POINT offset = {};
        ComPtr<IUnknown> update;
        HRESULT hr = surface->BeginDraw(&rect, iid, reinterpret_cast<void **>(update.GetAddressOf()), &offset);
        record(kind, api, round, "begin", hr);
        printf("surface=%s api=%s round=%u object=%d offset=%ld,%ld\n",
                kind, api, round, update != nullptr, offset.x, offset.y);
        if (FAILED(hr)) continue;
        began = true;
        ComPtr<ID2D1DeviceContext> context;
        if (SUCCEEDED(update.As(&context)))
        {
            const D2D1_COLOR_F color = {0.2f, 0.4f, 0.6f, 1.0f};
            context->Clear(&color);
        }
        record(kind, api, round, "suspend", surface->SuspendDraw());
        if (round) record(kind, api, round, "resume", surface->ResumeDraw());
        record(kind, api, round, "end", surface->EndDraw());
        record(kind, api, round, "idle-end", surface->EndDraw());
    }
    return began;
}

static int run()
{
    ComPtr<ABI::Windows::System::IDispatcherQueueController> queue;
    ComPtr<IInspectable> instance;
    ComPtr<ICompositor> compositor;
    ComPtr<ICompositorInterop> interop;
    ComPtr<ICompositionGraphicsDevice> graphics;
    ComPtr<ICompositionGraphicsDevice2> graphics2;
    ComPtr<ID3D11Device> d3d;
    ComPtr<IDXGIDevice> dxgi;
    ComPtr<ID2D1Device> d2d;
    DispatcherQueueOptions options = {sizeof(options), DQTYPE_THREAD_CURRENT, DQTAT_COM_NONE};
    const WCHAR class_name[] = L"Windows.UI.Composition.Compositor";
    HSTRING name = nullptr;
    HRESULT hr;

    check("dispatcher-queue", CreateDispatcherQueueController(options, queue.GetAddressOf()));
    hr = WindowsCreateString(class_name, ARRAYSIZE(class_name) - 1, &name);
    if (!check("class-name", hr)) return 1;
    hr = RoActivateInstance(name, instance.GetAddressOf());
    WindowsDeleteString(name);
    if (!check("compositor", hr) || !check("compositor-interface", instance.As(&compositor))) return 1;
    if (!check("compositor-interop", compositor.As(&interop))) return 1;
    if (!check("d3d-device", D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION, d3d.GetAddressOf(),
            nullptr, nullptr))) return 1;
    if (!check("dxgi-device", d3d.As(&dxgi))) return 1;
    if (!check("d2d-device", D2D1CreateDevice(dxgi.Get(), nullptr, d2d.GetAddressOf()))) return 1;
    if (!check("graphics-device", interop->CreateGraphicsDevice(d2d.Get(), graphics.GetAddressOf()))) return 1;
    if (!check("graphics-device2", graphics.As(&graphics2))) return 1;
    for (unsigned tiled = 0; tiled < 2; ++tiled)
    {
        for (unsigned surface_api = 0; surface_api < 2; ++surface_api)
        {
            ComPtr<ICompositionDrawingSurface> regular;
            ComPtr<ICompositionVirtualDrawingSurface> virtual_surface;
            ComPtr<ICompositionDrawingSurfaceInterop> drawing;
            const char *kind = tiled ? "virtual" : "regular";
            if (tiled)
            {
                hr = graphics2->CreateVirtualDrawingSurface({128, 64},
                        ABI::Windows::Graphics::DirectX::DirectXPixelFormat_B8G8R8A8UIntNormalized,
                        ABI::Windows::Graphics::DirectX::DirectXAlphaMode_Premultiplied,
                        virtual_surface.GetAddressOf());
                if (!check("create-virtual", hr) || !check("virtual-interop", virtual_surface.As(&drawing))) return 1;
            }
            else
            {
                hr = graphics->CreateDrawingSurface({128.0f, 64.0f},
                        ABI::Windows::Graphics::DirectX::DirectXPixelFormat_B8G8R8A8UIntNormalized,
                        ABI::Windows::Graphics::DirectX::DirectXAlphaMode_Premultiplied, regular.GetAddressOf());
                if (!check("create-regular", hr) || !check("regular-interop", regular.As(&drawing))) return 1;
            }
            bool began = surface_api ? observe(drawing.Get(), kind, "dxgi", __uuidof(IDXGISurface))
                                     : observe(drawing.Get(), kind, "d2d", __uuidof(ID2D1DeviceContext));
            if (!surface_api && !began) return 1;
        }
    }
    return 0;
}

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("case=architecture bits=%u\n", static_cast<unsigned>(sizeof(void *) * 8));
    if (!check("initialize", RoInitialize(RO_INIT_SINGLETHREADED))) return 1;
    int result = run();
    RoUninitialize();
    return result;
}
