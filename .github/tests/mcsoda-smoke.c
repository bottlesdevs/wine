#include <stdio.h>
#include <windows.h>

static int painted;

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT paint;
        HDC context = BeginPaint(window, &paint);
        RECT bounds;

        GetClientRect(window, &bounds);
        FillRect(context, &bounds, (HBRUSH)(COLOR_WINDOW + 1));
        DrawTextA(context, "McSoda", -1, &bounds, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        EndPaint(window, &paint);
        painted = 1;
        return 0;
    }
    case WM_TIMER:
        DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcA(window, message, wparam, lparam);
    }
}

int main(void)
{
    HINSTANCE instance = GetModuleHandleA(NULL);
    WNDCLASSA window_class = {0};
    HWND window;
    MSG message;

    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorA(NULL, IDC_ARROW);
    window_class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    window_class.lpszClassName = "McSodaSmokeWindow";
    if (!RegisterClassA(&window_class)) return 1;

    window = CreateWindowExA(0, window_class.lpszClassName, "McSoda smoke test",
                             WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                             480, 320, NULL, NULL, instance, NULL);
    if (!window) return 2;

    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    if (!SetTimer(window, 1, 500, NULL)) return 3;

    while (GetMessageA(&message, NULL, 0, 0) > 0)
    {
        TranslateMessage(&message);
        DispatchMessageA(&message);
    }

    if (!painted) return 4;
    puts("McSoda window test");
    return 0;
}
