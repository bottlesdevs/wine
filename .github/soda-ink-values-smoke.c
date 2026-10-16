/*
 * Copyright 2026 Mirko Brombin
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define COBJMACROS
#define CONST_VTABLE
#define _WIN32_WINNT 0x0602
#include <stdarg.h>
#include <stdio.h>
#include <math.h>
#include <windows.h>
#include <inspectable.h>
#include <winstring.h>
#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Numerics
#define WIDL_using_Windows_UI
#define WIDL_using_Windows_UI_Input_Inking
#include <initguid.h>
#include <roapi.h>
#include "windows.ui.input.inking.h"

static LONG checks, failures;
#define check(expr) do { InterlockedIncrement(&checks); if (!(expr)) { printf("FAIL line %u: %s\n", __LINE__, #expr); InterlockedIncrement(&failures); } } while (0)

struct thread_context
{
    IStream *drawing_stream, *point_stream;
    DWORD apartment;
    HANDLE start, done;
};

static DWORD WINAPI other_apartment(void *arg)
{
    struct thread_context *context = arg;
    IInkDrawingAttributes *drawing = NULL;
    IInkPoint2 *point = NULL;
    struct Size size;
    UINT64 timestamp;
    unsigned int i;
    HRESULT hr;

    check(CoInitializeEx(NULL, context->apartment) == S_OK);
    hr = CoGetInterfaceAndReleaseStream(context->drawing_stream, &IID_IInkDrawingAttributes, (void **)&drawing);
    check(hr == S_OK);
    hr = CoGetInterfaceAndReleaseStream(context->point_stream, &IID_IInkPoint2, (void **)&point);
    check(hr == S_OK);
    check(WaitForSingleObject(context->start, 10000) == WAIT_OBJECT_0);
    if (point)
    {
        check(IInkPoint2_get_Timestamp(point, &timestamp) == S_OK);
        check(timestamp == 0xfedcba9876543210ULL);
        IInkPoint2_Release(point);
    }
    if (drawing)
    {
        for (i = 0; i < 4096; ++i)
        {
            size.Width = i & 1 ? 3 : 1;
            size.Height = 2 * size.Width;
            check(IInkDrawingAttributes_put_Size(drawing, size) == S_OK);
        }
        IInkDrawingAttributes_Release(drawing);
    }
    CoUninitialize();
    SetEvent(context->done);
    return 0;
}

static void test_points(IInkPointFactory *factory, IInkPointFactory2 *factory2)
{
    IInkPoint *point;
    IInkPoint2 *extended;
    IUnknown *identity;
    struct Point input, output;
    float pressure, tilt;
    UINT64 timestamp;
    IID *iids;
    ULONG count;
    unsigned int i;
    HSTRING name;
    HRESULT hr;

    for (i = 0; i < 128; ++i)
    {
        input.X = (float)i - 64.5f;
        input.Y = 2 * input.X;
        hr = i & 1 ? IInkPointFactory2_CreateInkPointWithTiltAndTimestamp(factory2, input, .25f, 12.5f, -22.5f,
                0xfedcba9876543210ULL + i, &point) : IInkPointFactory_CreateInkPoint(factory, input, .75f, &point);
        check(hr == S_OK);
        if (FAILED(hr)) continue;
        check(IInkPoint_get_Position(point, &output) == S_OK);
        check(output.X == input.X && output.Y == input.Y);
        check(IInkPoint_get_Pressure(point, &pressure) == S_OK);
        check(pressure == (i & 1 ? .25f : .75f));
        check(IInkPoint_QueryInterface(point, &IID_IInkPoint2, (void **)&extended) == S_OK);
        check(IInkPoint2_get_TiltX(extended, &tilt) == S_OK);
        check(tilt == (i & 1 ? 12.5f : 0));
        check(IInkPoint2_get_TiltY(extended, &tilt) == S_OK);
        check(tilt == (i & 1 ? -22.5f : 0));
        check(IInkPoint2_get_Timestamp(extended, &timestamp) == S_OK);
        check(timestamp == (i & 1 ? 0xfedcba9876543210ULL + i : 0));
        check(IInkPoint2_QueryInterface(extended, &IID_IUnknown, (void **)&identity) == S_OK);
        check(identity == (IUnknown *)point);
        IUnknown_Release(identity);
        check(IInkPoint2_GetIids(extended, &count, &iids) == S_OK);
        check(count == 2 && IsEqualIID(&iids[0], &IID_IInkPoint) && IsEqualIID(&iids[1], &IID_IInkPoint2));
        CoTaskMemFree(iids);
        check(IInkPoint2_GetRuntimeClassName(extended, &name) == S_OK);
        check(!wcscmp(WindowsGetStringRawBuffer(name, NULL), RuntimeClass_Windows_UI_Input_Inking_InkPoint));
        WindowsDeleteString(name);
        IInkPoint2_Release(extended);
        IInkPoint_Release(point);
    }
}

int main(int argc, char **argv)
{
    HRESULT (WINAPI *can_unload)(void);
    HMODULE module;
    IInkPointFactory *point_factory = NULL;
    IInkPointFactory2 *point_factory2 = NULL;
    IActivationFactory *drawing_factory = NULL;
    IInkDrawingAttributes *drawing, *second;
    IInkDrawingAttributes2 *drawing2;
    IInkDrawingAttributes4 *drawing4;
    IInkPoint *point;
    IUnknown *identity;
    struct Point position = {1, 2};
    struct Size size;
    struct Color color;
    struct Matrix3x2 matrix, saved;
    enum PenTipShape shape;
    boolean value;
    struct thread_context context;
    HSTRING name;
    HANDLE thread;
    HRESULT hr;
    ULONG count;
    IID *iids;
    unsigned int i;
    BOOL sta = argc > 1 && argv[1][0] == 's';

    setvbuf(stdout, NULL, _IONBF, 0);
    check(RoInitialize(sta ? RO_INIT_SINGLETHREADED : RO_INIT_MULTITHREADED) == S_OK);
    check(WindowsCreateString(RuntimeClass_Windows_UI_Input_Inking_InkPoint,
            wcslen(RuntimeClass_Windows_UI_Input_Inking_InkPoint), &name) == S_OK);
    hr = RoGetActivationFactory(name, &IID_IInkPointFactory, (void **)&point_factory);
    printf("POINT_FACTORY=%#lx bits=%u apartment=%s\n", hr, (unsigned int)(8 * sizeof(void *)), sta ? "sta" : "mta");
    WindowsDeleteString(name);
    if (FAILED(hr)) return 2;
    module = LoadLibraryW(L"inkobjcore.dll");
    check(module != NULL);
    can_unload = (void *)GetProcAddress(module, "DllCanUnloadNow");
    check(can_unload != NULL);
    check(can_unload() == S_FALSE);
    check(IInkPointFactory_QueryInterface(point_factory, &IID_IInkPointFactory2, (void **)&point_factory2) == S_OK);
    test_points(point_factory, point_factory2);
    check(WindowsCreateString(RuntimeClass_Windows_UI_Input_Inking_InkDrawingAttributes,
            wcslen(RuntimeClass_Windows_UI_Input_Inking_InkDrawingAttributes), &name) == S_OK);
    check(RoGetActivationFactory(name, &IID_IActivationFactory, (void **)&drawing_factory) == S_OK);
    WindowsDeleteString(name);
    check(IActivationFactory_ActivateInstance(drawing_factory, (IInspectable **)&drawing) == S_OK);
    check(IActivationFactory_ActivateInstance(drawing_factory, (IInspectable **)&second) == S_OK);
    check(drawing != second);
    check(IInkDrawingAttributes_QueryInterface(drawing, &IID_IInkDrawingAttributes2, (void **)&drawing2) == S_OK);
    check(IInkDrawingAttributes_QueryInterface(drawing, &IID_IInkDrawingAttributes4, (void **)&drawing4) == S_OK);
    check(IInkDrawingAttributes4_QueryInterface(drawing4, &IID_IUnknown, (void **)&identity) == S_OK);
    check(identity == (IUnknown *)drawing);
    IUnknown_Release(identity);
    check(IInkDrawingAttributes2_GetIids(drawing2, &count, &iids) == S_OK);
    check(count == 3 && IsEqualIID(&iids[0], &IID_IInkDrawingAttributes)
            && IsEqualIID(&iids[1], &IID_IInkDrawingAttributes2) && IsEqualIID(&iids[2], &IID_IInkDrawingAttributes4));
    CoTaskMemFree(iids);
    check(IInkDrawingAttributes_get_Color(drawing, &color) == S_OK);
    check(color.A == 255 && !color.R && !color.G && !color.B);
    check(IInkDrawingAttributes_get_Size(drawing, &size) == S_OK);
    check(size.Width == 2 && size.Height == 2);
    check(IInkDrawingAttributes_get_PenTip(drawing, &shape) == S_OK && shape == PenTipShape_Circle);
    check(IInkDrawingAttributes_get_FitToCurve(drawing, &value) == S_OK && value);
    check(IInkDrawingAttributes_get_IgnorePressure(drawing, &value) == S_OK && !value);
    check(IInkDrawingAttributes2_get_DrawAsHighlighter(drawing2, &value) == S_OK && !value);
    check(IInkDrawingAttributes4_get_IgnoreTilt(drawing4, &value) == S_OK && !value);
    check(IInkDrawingAttributes2_get_PenTipTransform(drawing2, &matrix) == S_OK);
    check(matrix.M11 == 1 && matrix.M22 == 1 && !matrix.M12 && !matrix.M21 && !matrix.M31 && !matrix.M32);
    color.R = 255;
    color.G = 12;
    check(IInkDrawingAttributes_put_Color(drawing, color) == S_OK);
    check(IInkDrawingAttributes_get_Color(second, &color) == S_OK && !color.R && !color.G);
    check(IInkDrawingAttributes_put_PenTip(drawing, PenTipShape_Rectangle) == S_OK);
    check(IInkDrawingAttributes_put_PenTip(drawing, 2) == E_INVALIDARG);
    check(IInkDrawingAttributes_get_PenTip(drawing, &shape) == S_OK && shape == PenTipShape_Rectangle);
    size.Width = 0;
    size.Height = 3;
    check(IInkDrawingAttributes_put_Size(drawing, size) == E_INVALIDARG);
    size.Width = NAN;
    check(IInkDrawingAttributes_put_Size(drawing, size) == E_INVALIDARG);
    check(IInkDrawingAttributes_get_Size(drawing, &size) == S_OK && size.Width == 2 && size.Height == 2);
    matrix.M11 = 2;
    matrix.M12 = .5f;
    check(IInkDrawingAttributes2_put_PenTipTransform(drawing2, matrix) == S_OK);
    saved = matrix;
    matrix.M31 = 1;
    check(IInkDrawingAttributes2_put_PenTipTransform(drawing2, matrix) == E_INVALIDARG);
    matrix = saved;
    matrix.M22 = INFINITY;
    check(IInkDrawingAttributes2_put_PenTipTransform(drawing2, matrix) == E_INVALIDARG);
    check(IInkDrawingAttributes2_get_PenTipTransform(drawing2, &matrix) == S_OK && !memcmp(&matrix, &saved, sizeof(matrix)));
    check(IInkDrawingAttributes_put_IgnorePressure(drawing, TRUE) == S_OK);
    check(IInkDrawingAttributes_get_IgnorePressure(drawing, &value) == S_OK && value);
    check(IInkDrawingAttributes_put_FitToCurve(drawing, FALSE) == S_OK);
    check(IInkDrawingAttributes_get_FitToCurve(drawing, &value) == S_OK && !value);
    check(IInkDrawingAttributes2_put_DrawAsHighlighter(drawing2, TRUE) == S_OK);
    check(IInkDrawingAttributes2_get_DrawAsHighlighter(drawing2, &value) == S_OK && value);
    check(IInkDrawingAttributes4_put_IgnoreTilt(drawing4, TRUE) == S_OK);
    check(IInkDrawingAttributes4_get_IgnoreTilt(drawing4, &value) == S_OK && value);
    check(IInkPointFactory2_CreateInkPointWithTiltAndTimestamp(point_factory2, position, .5f, 10, -10,
            0xfedcba9876543210ULL, &point) == S_OK);
    context.apartment = sta ? COINIT_MULTITHREADED : COINIT_APARTMENTTHREADED;
    context.start = CreateEventW(NULL, TRUE, FALSE, NULL);
    context.done = CreateEventW(NULL, TRUE, FALSE, NULL);
    check(CoMarshalInterThreadInterfaceInStream(&IID_IInkDrawingAttributes, (IUnknown *)drawing, &context.drawing_stream) == S_OK);
    check(CoMarshalInterThreadInterfaceInStream(&IID_IInkPoint2, (IUnknown *)point, &context.point_stream) == S_OK);
    IInkPoint_Release(point);
    size.Width = 1;
    size.Height = 2;
    check(IInkDrawingAttributes_put_Size(drawing, size) == S_OK);
    thread = CreateThread(NULL, 0, other_apartment, &context, 0, NULL);
    check(thread != NULL);
    SetEvent(context.start);
    for (i = 0; i < 4096; ++i)
    {
        check(IInkDrawingAttributes_get_Size(drawing, &size) == S_OK);
        check(size.Height == 2 * size.Width && (size.Width == 1 || size.Width == 3));
    }
    check(WaitForSingleObject(context.done, 10000) == WAIT_OBJECT_0);
    check(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    CloseHandle(context.start);
    CloseHandle(context.done);
    IInkDrawingAttributes4_Release(drawing4);
    IInkDrawingAttributes2_Release(drawing2);
    IInkDrawingAttributes_Release(drawing);
    IInkDrawingAttributes_Release(second);
    IActivationFactory_Release(drawing_factory);
    IInkPointFactory2_Release(point_factory2);
    IInkPointFactory_Release(point_factory);
    RoUninitialize();
    check(can_unload() == S_OK);
    FreeLibrary(module);
    printf("INK_VALUE_RESULT checks=%ld failures=%ld\n", checks, failures);
    return failures ? 1 : 0;
}
