#include <windows.h>
#include <GL/gl.h>
#include <stdio.h>

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (message == WM_CLOSE) return 0;
    return DefWindowProcA(window, message, wparam, lparam);
}

int main(int argc, char **argv)
{
    WNDCLASSA cls = {0};
    PIXELFORMATDESCRIPTOR pfd = {0};
    HWND parent, child;
    HDC dc;
    HGLRC context;
    FILE *out;
    unsigned int i;
    int format;
    if (argc != 2 || !(out = fopen(argv[1], "w"))) return 2;
    cls.style = CS_OWNDC;cls.lpfnWndProc = window_proc;cls.hInstance = GetModuleHandleA(NULL);cls.lpszClassName = "SodaResizeFixture";
    if (!RegisterClassA(&cls)) return 3;
    parent = CreateWindowA(cls.lpszClassName, "Soda resize fixture", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 50, 50, 800, 600, NULL, NULL, cls.hInstance, NULL);
    child = CreateWindowA(cls.lpszClassName, "OpenGL child", WS_CHILD | WS_VISIBLE, 0, 0, 760, 540, parent, NULL, cls.hInstance, NULL);
    if (!parent || !child) return 4;
    dc = GetDC(child);
    pfd.nSize = sizeof(pfd);pfd.nVersion = 1;pfd.dwFlags = PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER | PFD_DRAW_TO_WINDOW;
    pfd.iPixelType = PFD_TYPE_RGBA;pfd.cColorBits = 32;pfd.iLayerType = PFD_MAIN_PLANE;
    format = ChoosePixelFormat(dc, &pfd);
    if (!format || !SetPixelFormat(dc, format, &pfd)) return 5;
    context = wglCreateContext(dc);
    if (!context || !wglMakeCurrent(dc, context)) return 6;
    fprintf(out, "GL_VERSION=%s\n", glGetString(GL_VERSION));fflush(out);
    for (i = 0; i < 240; ++i)
    {
        RECT rect;
        MSG msg;
        BYTE pixel[4] = {0};
        int width = 400 + (i * 37) % 700, height = 300 + (i * 53) % 400;
        if (!MoveWindow(parent, 50, 50, width, height, TRUE) || !GetClientRect(parent, &rect) ||
            !MoveWindow(child, 0, 0, rect.right, rect.bottom, TRUE)) return 7;
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&msg);DispatchMessageA(&msg); }
        glViewport(0, 0, rect.right, rect.bottom);
        glClearColor(32.0f/255, 96.0f/255, 160.0f/255, 1);glClear(GL_COLOR_BUFFER_BIT);
        glReadPixels(rect.right/2, rect.bottom/2, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
        if (glGetError() || abs(pixel[0]-32) > 1 || abs(pixel[1]-96) > 1 || abs(pixel[2]-160) > 1) return 8;
        if (!SwapBuffers(dc)) return 9;
        Sleep(20);
    }
    fprintf(out, "RESIZE_SWAP_READBACK_PASSED=%u\n", i);fflush(out);
    Sleep(1000);
    wglMakeCurrent(NULL, NULL);wglDeleteContext(context);ReleaseDC(child, dc);
    DestroyWindow(child);DestroyWindow(parent);fclose(out);
    return 0;
}
