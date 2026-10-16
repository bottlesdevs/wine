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
#define INITGUID
#include <stdio.h>
#include "windows.h"
#include "winstring.h"
#include "roapi.h"
#include "d3d11.h"
#include "d2d1_1.h"
#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include "windows.foundation.h"
#define WIDL_using_Windows_Foundation_Numerics
#include "windows.foundation.numerics.h"
#define WIDL_using_Windows_Graphics
#include "windows.graphics.h"
#define WIDL_using_Windows_Graphics_DirectX
#define WIDL_using_Windows_UI
#include "windows.ui.h"
#define WIDL_using_Windows_UI_Composition
#include "windows.ui.composition.h"
#define WIDL_using_Windows_UI_Composition_Core
#include "windows.ui.composition.core.h"
#define WIDL_using_Windows_UI_Composition_Desktop
#include "windows.ui.composition.interop.h"

static LONG checks, failures;
#define check(expr) do { InterlockedIncrement(&checks); if (!(expr)) { printf("FAIL line %u: %s\n", __LINE__, #expr); InterlockedIncrement(&failures); } } while (0)

struct handler
{
    ITypedEventHandler_CompositorController_IInspectable iface;
    LONG ref, calls;
};

static HRESULT WINAPI handler_QueryInterface(ITypedEventHandler_CompositorController_IInspectable *iface, REFIID iid,
                                             void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) &&
        !IsEqualGUID(iid, &IID_ITypedEventHandler_CompositorController_IInspectable))
        return E_NOINTERFACE;
    *out = iface;
    IUnknown_AddRef((IUnknown *)iface);
    return S_OK;
}

static ULONG WINAPI handler_AddRef(ITypedEventHandler_CompositorController_IInspectable *iface)
{
    return InterlockedIncrement(&CONTAINING_RECORD(iface, struct handler, iface)->ref);
}

static ULONG WINAPI handler_Release(ITypedEventHandler_CompositorController_IInspectable *iface)
{
    return InterlockedDecrement(&CONTAINING_RECORD(iface, struct handler, iface)->ref);
}

static HRESULT WINAPI handler_Invoke(ITypedEventHandler_CompositorController_IInspectable *iface,
                                     ICompositorController *sender, IInspectable *args)
{
    struct handler *handler = CONTAINING_RECORD(iface, struct handler, iface);
    ++handler->calls;
    check(sender != NULL);
    check(ICompositorController_Commit(sender) == S_OK);
    return S_OK;
}

static const ITypedEventHandler_CompositorController_IInspectableVtbl handler_vtbl = {
    handler_QueryInterface, handler_AddRef, handler_Release, handler_Invoke};

static void paint(ICompositionDrawingSurfaceInterop *surface, const RECT *rect)
{
    D2D1_COLOR_F color = {0, 1, 0, 1};
    ID2D1DeviceContext *context = NULL;
    POINT offset;
    check(ICompositionDrawingSurfaceInterop_BeginDraw(surface, rect, &IID_ID2D1DeviceContext, (void **)&context,
                                                      &offset) == S_OK);
    if (!context) return;
    ID2D1DeviceContext_Clear(context, &color);
    check(ICompositionDrawingSurfaceInterop_EndDraw(surface) == S_OK);
    ID2D1DeviceContext_Release(context);
}
int main(void)
{
    struct handler handler = {{&handler_vtbl}, 1, 0};
    IInspectable *instance = NULL;
    ICompositorController *controller = NULL;
    ICompositor *compositor = NULL;
    ICompositorInterop *interop = NULL;
    ICompositionGraphicsDevice *graphics = NULL;
    ICompositionGraphicsDevice2 *graphics2 = NULL;
    ICompositionDrawingSurface *surface = NULL;
    ICompositionVirtualDrawingSurface *virtual = NULL;
    ICompositionDrawingSurfaceInterop *drawing[2] = {NULL};
    ID3D11Device *d3d = NULL;
    IDXGIDevice *dxgi = NULL;
    ID2D1Device *d2d = NULL;
    HRESULT (WINAPI *create_device)(IDXGIDevice *, const D2D1_CREATION_PROPERTIES *, ID2D1Device **);
    HMODULE module;
    HSTRING name = NULL;
    EventRegistrationToken token;
    RECT rect = {256, 256, 288, 272};
    DWORD apartment = COINIT_MULTITHREADED;
    setvbuf(stdout, NULL, _IONBF, 0);
    check(RoInitialize(apartment) == S_OK);
    check(WindowsCreateString(RuntimeClass_Windows_UI_Composition_Core_CompositorController,
                              ARRAYSIZE(RuntimeClass_Windows_UI_Composition_Core_CompositorController) - 1,
                              &name) == S_OK);
    check(RoActivateInstance(name, &instance) == S_OK);
    WindowsDeleteString(name);
    if (!instance) return 2;
    check(IInspectable_QueryInterface(instance, &IID_ICompositorController, (void **)&controller) == S_OK);
    IInspectable_Release(instance);
    check(ICompositorController_get_Compositor(controller, &compositor) == S_OK);
    check(ICompositor_QueryInterface(compositor, &IID_ICompositorInterop, (void **)&interop) == S_OK);
    check(D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                            D3D11_SDK_VERSION, &d3d, NULL, NULL) == S_OK);
    if (!d3d) return 2;
    check(ID3D11Device_QueryInterface(d3d, &IID_IDXGIDevice, (void **)&dxgi) == S_OK);
    module = LoadLibraryW(L"d2d1.dll");
    check(module != NULL);
    if (!module) return 2;
    create_device = (void *)GetProcAddress(module, "D2D1CreateDevice");
    check(create_device != NULL);
    if (!create_device) return 2;
    check(create_device(dxgi, NULL, &d2d) == S_OK);
    check(ICompositorInterop_CreateGraphicsDevice(interop, (IUnknown *)d2d, &graphics) == S_OK);
    check(ICompositionGraphicsDevice_QueryInterface(graphics, &IID_ICompositionGraphicsDevice2, (void **)&graphics2) ==
          S_OK);
    check(ICompositionGraphicsDevice_CreateDrawingSurface(graphics, (Size){32, 16},
                                                          DirectXPixelFormat_B8G8R8A8UIntNormalized,
                                                          DirectXAlphaMode_Premultiplied, &surface) == S_OK);
    check(ICompositionGraphicsDevice2_CreateVirtualDrawingSurface(graphics2, (struct SizeInt32){4096, 4096},
                                                                  DirectXPixelFormat_B8G8R8A8UIntNormalized,
                                                                  DirectXAlphaMode_Premultiplied, &virtual) == S_OK);
    check(ICompositionDrawingSurface_QueryInterface(surface, &IID_ICompositionDrawingSurfaceInterop,
                                                    (void **)&drawing[0]) == S_OK);
    check(ICompositionVirtualDrawingSurface_QueryInterface(virtual, &IID_ICompositionDrawingSurfaceInterop,
                                                           (void **)&drawing[1]) == S_OK);
    check(ICompositorController_add_CommitNeeded(controller, &handler.iface, &token) == S_OK && handler.ref == 2);
    ICompositionGraphicsDevice2_Release(graphics2);
    ICompositionGraphicsDevice_Release(graphics);
    check(handler.calls == 0);
    paint(drawing[0], NULL);
    check(handler.calls == 1 && handler.ref == 2);
    paint(drawing[1], &rect);
    check(handler.calls == 2 && handler.ref == 2);
    check(ICompositorController_remove_CommitNeeded(controller, token) == S_OK && handler.ref == 1);
    ICompositorInterop_Release(interop);
    ICompositor_Release(compositor);
    ICompositorController_Release(controller);
    paint(drawing[0], NULL);
    paint(drawing[1], &rect);
    check(handler.calls == 2 && handler.ref == 1);
    ICompositionDrawingSurfaceInterop_Release(drawing[0]);
    ICompositionDrawingSurfaceInterop_Release(drawing[1]);
    ICompositionDrawingSurface_Release(surface);
    ICompositionVirtualDrawingSurface_Release(virtual);
    ID2D1Device_Release(d2d);
    FreeLibrary(module);
    IDXGIDevice_Release(dxgi);
    ID3D11Device_Release(d3d);
    RoUninitialize();
    printf("SURFACE_COMMIT_RESULT checks=%ld failures=%ld\n", checks, failures);
    return failures ? 1 : 0;
}
