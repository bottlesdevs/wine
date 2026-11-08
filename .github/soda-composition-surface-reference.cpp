#include <windows.h>
#include <roapi.h>
#include <windows.system.h>
#include <dispatcherqueue.h>
#include <windows.ui.composition.h>
#include <windows.ui.composition.core.h>
#include <windows.ui.composition.desktop.h>
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

static void pump(unsigned milliseconds)
{
    ULONGLONG end = GetTickCount64() + milliseconds;
    MSG message;
    do
    {
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        MsgWaitForMultipleObjects(0, nullptr, FALSE, 10, QS_ALLINPUT);
    } while (GetTickCount64() < end);
}

static COLORREF desktop_pixel(HWND window, int x, int y)
{
    POINT point = {x, y};
    if (!ClientToScreen(window, &point)) return CLR_INVALID;
    HDC dc = GetDC(nullptr);
    if (!dc) return CLR_INVALID;
    COLORREF value = GetPixel(dc, point.x, point.y);
    ReleaseDC(nullptr, dc);
    return value;
}

static bool observe_layered_child(HWND parent)
{
    BITMAPINFO info = {};
    BLENDFUNCTION blend = {AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
    POINT origin = {8, 8}, source = {};
    SIZE size = {32, 32};
    HWND window = nullptr;
    HBITMAP bitmap = nullptr;
    HGDIOBJ previous = nullptr;
    HDC dc = CreateCompatibleDC(nullptr);
    DWORD *pixels = nullptr;
    bool success = false;

    if (!dc) return false;
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = size.cx;
    info.bmiHeader.biHeight = -size.cy;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, reinterpret_cast<void **>(&pixels), nullptr, 0);
    if (!bitmap) goto done;
    previous = SelectObject(dc, bitmap);
    if (!previous || previous == HGDI_ERROR) goto done;
    window = CreateWindowExW(WS_EX_LAYERED | WS_EX_NOACTIVATE, L"STATIC", nullptr,
            WS_CHILD | WS_DISABLED | WS_VISIBLE, 8, 8, size.cx, size.cy, parent, nullptr,
            GetModuleHandleW(nullptr), nullptr);
    if (!window || !ClientToScreen(parent, &origin)) goto done;
    for (unsigned round = 0; round < 2; ++round)
    {
        for (unsigned i = 0; i < 32 * 32; ++i) pixels[i] = round ? 0x80000080 : 0xff00ff00;
        if (!UpdateLayeredWindow(window, nullptr, &origin, &size, dc, &source, 0, &blend, ULW_ALPHA))
        {
            printf("case=layered-child-update error=%lu\n", GetLastError());
            goto done;
        }
        pump(200);
        printf("desktop=hybrid phase=%s background=%06lx visual=%06lx\n",
                round ? "layered-alpha" : "layered-opaque", desktop_pixel(parent, 110, 50),
                desktop_pixel(parent, 16, 16));
    }
    success = true;

done:
    if (window) DestroyWindow(window);
    if (previous && previous != HGDI_ERROR) SelectObject(dc, previous);
    if (bitmap) DeleteObject(bitmap);
    DeleteDC(dc);
    pump(200);
    return success;
}

static bool observe_desktop()
{
    ComPtr<Core::ICompositorController> controller;
    ComPtr<IInspectable> instance;
    ComPtr<ICompositor> compositor;
    ComPtr<Desktop::ICompositorDesktopInterop> desktop;
    ComPtr<Desktop::IDesktopWindowTarget> desktop_target;
    ComPtr<ICompositionTarget> target;
    ComPtr<ICompositionColorBrush> color;
    ComPtr<ICompositionBrush> brush;
    ComPtr<ISpriteVisual> sprite;
    ComPtr<IVisual> visual;
    const WCHAR class_name[] = L"Windows.UI.Composition.Core.CompositorController";
    HSTRING name = nullptr;
    WNDCLASSW cls = {};
    HWND window = nullptr;
    bool success = false;
    COLORREF background, foreground;

    if (!check("desktop-class-name", WindowsCreateString(class_name, ARRAYSIZE(class_name) - 1, &name))) return false;
    HRESULT hr = RoActivateInstance(name, instance.GetAddressOf());
    WindowsDeleteString(name);
    if (!check("desktop-controller", hr) || !check("desktop-controller-interface", instance.As(&controller)) ||
            !check("desktop-compositor", controller->get_Compositor(compositor.GetAddressOf())) ||
            !check("desktop-interop", compositor.As(&desktop))) return false;
    cls.hInstance = GetModuleHandleW(nullptr);
    cls.lpfnWndProc = DefWindowProcW;
    cls.lpszClassName = L"SodaCompositionBackground";
    cls.hbrBackground = CreateSolidBrush(RGB(255, 0, 0));
    if (!cls.hbrBackground) return false;
    if (!RegisterClassW(&cls)) goto done;
    window = CreateWindowExW(WS_EX_TOPMOST, cls.lpszClassName, L"Composition background control", WS_POPUP,
            20, 20, 128, 64, nullptr, nullptr, cls.hInstance, nullptr);
    if (!window) goto done;
    ShowWindow(window, SW_SHOWNOACTIVATE);
    UpdateWindow(window);
    pump(200);
    background = desktop_pixel(window, 110, 50);
    foreground = desktop_pixel(window, 16, 16);
    printf("desktop=hybrid phase=base background=%06lx visual=%06lx\n", background, foreground);
    if (background != RGB(255, 0, 0) || foreground != background) goto done;
    if (!observe_layered_child(window)) goto done;
    if (!check("desktop-target", desktop->CreateDesktopWindowTarget(window, TRUE, desktop_target.GetAddressOf())) ||
            !check("desktop-target-interface", desktop_target.As(&target)) ||
            !check("desktop-color", compositor->CreateColorBrushWithColor({255, 0, 255, 0}, color.GetAddressOf())) ||
            !check("desktop-brush", color.As(&brush)) ||
            !check("desktop-sprite", compositor->CreateSpriteVisual(sprite.GetAddressOf())) ||
            !check("desktop-visual", sprite.As(&visual)) ||
            !check("desktop-size", visual->put_Size({32.0f, 32.0f})) ||
            !check("desktop-offset", visual->put_Offset({8.0f, 8.0f, 0.0f})) ||
            !check("desktop-set-brush", sprite->put_Brush(brush.Get())) ||
            !check("desktop-root", target->put_Root(visual.Get()))) goto done;
    for (unsigned round = 0; round < 2; ++round)
    {
        if (round && !check("desktop-recolor", color->put_Color({255, 0, 0, 255}))) goto done;
        if (!check("desktop-commit", controller->Commit())) goto done;
        pump(500);
        background = desktop_pixel(window, 110, 50);
        foreground = desktop_pixel(window, 16, 16);
        printf("desktop=hybrid phase=%s background=%06lx visual=%06lx\n",
                round ? "blue" : "green", background, foreground);
        if (background == CLR_INVALID || foreground == CLR_INVALID) goto done;
    }
    if (!check("desktop-detach", target->put_Root(nullptr)) ||
            !check("desktop-detach-commit", controller->Commit())) goto done;
    pump(500);
    printf("desktop=hybrid phase=detached background=%06lx visual=%06lx\n",
            desktop_pixel(window, 110, 50), desktop_pixel(window, 16, 16));
    success = true;

done:
    if (target) target->put_Root(nullptr);
    target.Reset();
    desktop_target.Reset();
    if (window) DestroyWindow(window);
    UnregisterClassW(cls.lpszClassName, cls.hInstance);
    DeleteObject(cls.hbrBackground);
    return success;
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
    return observe_desktop() ? 0 : 1;
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
