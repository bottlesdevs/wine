#define COBJMACROS
#include <windows.h>
#include <stdio.h>

int main(void)
{
    WNDCLASSW cls = {0};
    MSG message;
    HWND window;
    HDC dc, memory, screen;
    HBITMAP bitmap;
    HGDIOBJ previous;
    HBRUSH brush;
    RECT rect = {0, 0, 128, 128};
    POINT origin = {0, 0};
    unsigned int mode, failures = 0;

    cls.lpfnWndProc = DefWindowProcW;
    cls.hInstance = GetModuleHandleW(NULL);
    cls.hbrBackground = GetStockObject(BLACK_BRUSH);
    cls.lpszClassName = L"SodaGdiFlush";
    if (!RegisterClassW(&cls)) return 1;
    window = CreateWindowW(cls.lpszClassName, L"GdiFlush", WS_POPUP,
            0, 0, 128, 128, NULL, NULL, cls.hInstance, NULL);
    if (!window) return 2;
    ShowWindow(window, SW_SHOWNA);
    UpdateWindow(window);
    while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    dc = GetDC(window);
    memory = CreateCompatibleDC(dc);
    bitmap = CreateCompatibleBitmap(dc, 128, 128);
    if (!dc || !memory || !bitmap) return 3;
    previous = SelectObject(memory, bitmap);
    brush = CreateSolidBrush(RGB(255, 0, 0));
    if (!FillRect(memory, &rect, brush)) return 4;
    ClientToScreen(window, &origin);
    screen = GetDC(NULL);
    for (mode = 0; mode < 2; ++mode)
    {
        COLORREF color;
        BOOL copied;
        PatBlt(dc, 0, 0, 128, 128, BLACKNESS);
        copied = mode ? StretchBlt(dc, 0, 0, 128, 128, memory, 0, 0, 128, 128, SRCCOPY)
                : BitBlt(dc, 0, 0, 128, 128, memory, 0, 0, SRCCOPY);
        if (!copied || !GdiFlush()) return 5;
        Sleep(100);
        color = GetPixel(screen, origin.x + 64, origin.y + 64);
        printf("GDI_FLUSH mode=%u color=%06lx expected=%06lx\n", mode,
                (unsigned long)color, (unsigned long)RGB(255, 0, 0));
        if (color != RGB(255, 0, 0)) ++failures;
    }
    ReleaseDC(NULL, screen);
    SelectObject(memory, previous);
    DeleteObject(brush);
    DeleteObject(bitmap);
    DeleteDC(memory);
    ReleaseDC(window, dc);
    DestroyWindow(window);
    return failures ? 7 : 0;
}
