#define COBJMACROS
#include <windows.h>
#include <d2d1.h>
#include <stdio.h>

static COLORREF screen_pixel(HWND window)
{
    POINT point = {12, 12};
    MSG message;
    HDC screen;
    COLORREF color;
    unsigned int i;

    for (i = 0; i < 10; ++i)
    {
        while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        Sleep(10);
    }
    ClientToScreen(window, &point);
    screen = GetDC(NULL);
    color = GetPixel(screen, point.x, point.y);
    ReleaseDC(NULL, screen);
    return color;
}

int wmain(void)
{
    WNDCLASSW cls = {0};
    D2D1_RENDER_TARGET_PROPERTIES properties = {0};
    D2D1_HWND_RENDER_TARGET_PROPERTIES hwnd_properties = {0};
    D2D1_COLOR_F red = {1, 0, 0, 1}, blue = {0, 0, 1, 1};
    ID2D1Factory *factory = NULL;
    ID2D1HwndRenderTarget *target = NULL;
    ID2D1RenderTarget *render_target;
    D2D1_TAG first = 0x1111, second = 0x2222;
    COLORREF before, flushed, ended;
    HRESULT flush_hr, end_hr;
    HWND window;
    RECT rect;

    setvbuf(stdout, NULL, _IONBF, 0);
    SetProcessDPIAware();
    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) return 1;
    cls.lpfnWndProc = DefWindowProcW;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    cls.lpszClassName = L"D2DFlushSmoke";
    if (!RegisterClassW(&cls)) return 2;
    window = CreateWindowW(cls.lpszClassName, L"Direct2D Flush",
            WS_OVERLAPPEDWINDOW, 0, 0, 320, 240, NULL, NULL, cls.hInstance, NULL);
    if (!window) return 3;
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    GetClientRect(window, &rect);
    before = screen_pixel(window);
    if (before != RGB(255, 255, 255)) return 8;
    if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED,
            &IID_ID2D1Factory, NULL, (void **)&factory))) return 4;
    hwnd_properties.hwnd = window;
    hwnd_properties.pixelSize.width = rect.right;
    hwnd_properties.pixelSize.height = rect.bottom;
    hwnd_properties.presentOptions = D2D1_PRESENT_OPTIONS_IMMEDIATELY;
    if (FAILED(ID2D1Factory_CreateHwndRenderTarget(factory, &properties,
            &hwnd_properties, &target))) return 5;
    render_target = (ID2D1RenderTarget *)target;
    ID2D1RenderTarget_BeginDraw(render_target);
    ID2D1RenderTarget_Clear(render_target, &red);
    flush_hr = ID2D1RenderTarget_Flush(render_target, &first, &second);
    flushed = screen_pixel(window);
    printf("flush:%08lx tags:%llx,%llx pixel:%06lx\n",
            (unsigned long)flush_hr, first, second, (unsigned long)flushed);
    ID2D1RenderTarget_Clear(render_target, &blue);
    end_hr = ID2D1RenderTarget_EndDraw(render_target, NULL, NULL);
    ended = screen_pixel(window);
    printf("end:%08lx pixel:%06lx\n", (unsigned long)end_hr, (unsigned long)ended);
    ID2D1RenderTarget_Release(render_target);
    ID2D1Factory_Release(factory);
    DestroyWindow(window);
    CoUninitialize();
    if (FAILED(flush_hr) || first || second || FAILED(end_hr)
            || ended != RGB(0, 0, 255)) return 6;
    return flushed == before ? 0 : 7;
}
