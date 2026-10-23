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
    ITypedEventHandler_CompositionGraphicsDevice_RenderingDeviceReplacedEventArgs iface;
    LONG ref, calls;
    EventRegistrationToken token;
    BOOL remove;
    IRenderingDeviceReplacedEventArgs *retained;
    ICompositionGraphicsDeviceInterop *interop;
    IUnknown *next;
};

static HRESULT WINAPI handler_QueryInterface(ITypedEventHandler_CompositionGraphicsDevice_RenderingDeviceReplacedEventArgs *iface, REFIID iid,
                                             void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) &&
        !IsEqualGUID(iid, &IID_ITypedEventHandler_CompositionGraphicsDevice_RenderingDeviceReplacedEventArgs))
        return E_NOINTERFACE;
    *out = iface;
    IUnknown_AddRef((IUnknown *)iface);
    return S_OK;
}

static ULONG WINAPI handler_AddRef(ITypedEventHandler_CompositionGraphicsDevice_RenderingDeviceReplacedEventArgs *iface)
{
    return InterlockedIncrement(&CONTAINING_RECORD(iface, struct handler, iface)->ref);
}

static ULONG WINAPI handler_Release(ITypedEventHandler_CompositionGraphicsDevice_RenderingDeviceReplacedEventArgs *iface)
{
    return InterlockedDecrement(&CONTAINING_RECORD(iface, struct handler, iface)->ref);
}

static HRESULT WINAPI handler_Invoke(ITypedEventHandler_CompositionGraphicsDevice_RenderingDeviceReplacedEventArgs *iface,
                                     ICompositionGraphicsDevice *sender, IRenderingDeviceReplacedEventArgs *args)
{
    struct handler *handler = CONTAINING_RECORD(iface, struct handler, iface);
    ++handler->calls;
    check(sender != NULL);
    {
        ICompositionGraphicsDevice *device = NULL;
        ICompositionObject *object = NULL;
        IClosable *closable = NULL;
        check(args != NULL);
        check(IRenderingDeviceReplacedEventArgs_QueryInterface(args, &IID_ICompositionObject,
                                                              (void **)&object) == S_OK);
        check(IRenderingDeviceReplacedEventArgs_QueryInterface(args, &IID_IClosable,
                                                              (void **)&closable) == S_OK);
        if (object) ICompositionObject_Release(object);
        if (closable) IClosable_Release(closable);
        check(IRenderingDeviceReplacedEventArgs_get_GraphicsDevice(args, &device) == S_OK);
        check(device == sender);
        if (device) ICompositionGraphicsDevice_Release(device);
        if (handler->retained) IRenderingDeviceReplacedEventArgs_Release(handler->retained);
        handler->retained = args;
        IRenderingDeviceReplacedEventArgs_AddRef(args);
        if (handler->remove)
            check(ICompositionGraphicsDevice_remove_RenderingDeviceReplaced(sender, handler->token) == S_OK);
        if (handler->next)
        {
            IUnknown *next = handler->next;
            handler->next = NULL;
            check(ICompositionGraphicsDeviceInterop_SetRenderingDevice(handler->interop, next) == S_OK);
        }
    }
    return S_OK;
}

static const ITypedEventHandler_CompositionGraphicsDevice_RenderingDeviceReplacedEventArgsVtbl handler_vtbl = {
    handler_QueryInterface, handler_AddRef, handler_Release, handler_Invoke};

int main(void)
{
    struct handler handler = {.iface = {&handler_vtbl}, .ref = 1};
    IInspectable *instance = NULL;
    ICompositorController *controller = NULL;
    ICompositor *compositor = NULL;
    ICompositorInterop *interop = NULL;
    ICompositionGraphicsDevice *graphics = NULL;
    ID3D11Device *d3d = NULL;
    IDXGIDevice *dxgi = NULL;
    ID2D1Device *d2d = NULL;
    HRESULT (WINAPI *create_device)(IDXGIDevice *, const D2D1_CREATION_PROPERTIES *, ID2D1Device **);
    HMODULE module;
    HSTRING name = NULL;
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
    {
        const GUID iid = {0xa116ff71,0xf8bf,0x4c8a,{0x9c,0x98,0x70,0x77,0x9a,0x32,0xa9,0xc8}};
        IUnknown *result = NULL;
        HRESULT hr = ICompositionGraphicsDevice_QueryInterface(graphics, &iid, (void **)&result);
        printf("graphics_device_interop:%08lx pointer:%p\n", hr, result);
        if (result)
        {
            ICompositionGraphicsDeviceInterop *native = (ICompositionGraphicsDeviceInterop *)result;
            IUnknown *got = NULL, *identity = NULL, *expected = NULL;
            ID2D1Device *replacement = NULL;
            check(ICompositionGraphicsDeviceInterop_GetRenderingDevice(native, NULL) == E_POINTER);
            check(ICompositionGraphicsDeviceInterop_GetRenderingDevice(native, &got) == S_OK);
            check(got == (IUnknown *)d2d);
            if (got) IUnknown_Release(got);
            check(ICompositionGraphicsDeviceInterop_QueryInterface(native, &IID_IUnknown, (void **)&identity) == S_OK);
            check(ICompositionGraphicsDevice_QueryInterface(graphics, &IID_IUnknown, (void **)&expected) == S_OK);
            check(identity == expected);
            if (identity) IUnknown_Release(identity);
            if (expected) IUnknown_Release(expected);
            check(ICompositionGraphicsDeviceInterop_SetRenderingDevice(native, NULL) == E_INVALIDARG);
            check(create_device(dxgi, NULL, &replacement) == S_OK);
            if (replacement)
            {
                ICompositionDrawingSurface *drawing = NULL;
                ICompositionDrawingSurfaceInterop *surface_interop = NULL;
                ID2D1DeviceContext *context = NULL;
                ID2D1Device *actual = NULL;
                POINT offset;
                check(ICompositionGraphicsDevice_CreateDrawingSurface(graphics, (Size){8,8},
                      DirectXPixelFormat_B8G8R8A8UIntNormalized, DirectXAlphaMode_Premultiplied, &drawing) == S_OK);
                check(drawing != NULL);
                if (!drawing) return 2;
                check(ICompositionDrawingSurface_QueryInterface(drawing, &IID_ICompositionDrawingSurfaceInterop,
                      (void **)&surface_interop) == S_OK);
                if (!surface_interop) return 2;
                check(ICompositionDrawingSurfaceInterop_BeginDraw(surface_interop, NULL, &IID_ID2D1DeviceContext,
                      (void **)&context, &offset) == S_OK);
                if (!context) return 2;
                check(ICompositionGraphicsDevice_add_RenderingDeviceReplaced(graphics, &handler.iface,
                      &handler.token) == S_OK);
                check(handler.ref == 2);
                check(ICompositionGraphicsDeviceInterop_SetRenderingDevice(native, (IUnknown *)replacement) == S_OK);
                check(handler.calls == 1);
                got = NULL;
                check(ICompositionGraphicsDeviceInterop_GetRenderingDevice(native, &got) == S_OK);
                check(got == (IUnknown *)replacement);
                if (got) IUnknown_Release(got);
                check(ICompositionGraphicsDeviceInterop_SetRenderingDevice(native, (IUnknown *)replacement) == S_OK);
                check(handler.calls == 1);
                ID2D1DeviceContext_GetDevice(context, &actual);
                check(actual == d2d);
                if (actual) ID2D1Device_Release(actual);
                {
                    ID2D1DeviceContext *nested = NULL;
                    check(ICompositionDrawingSurfaceInterop_BeginDraw(surface_interop, NULL,
                          &IID_ID2D1DeviceContext, (void **)&nested, &offset) == D2DERR_WRONG_STATE);
                    check(nested == NULL);
                }
                ID2D1DeviceContext_Release(context);
                context = NULL;
                check(ICompositionDrawingSurfaceInterop_EndDraw(surface_interop) == S_OK);
                check(ICompositionDrawingSurfaceInterop_BeginDraw(surface_interop, NULL, &IID_ID2D1DeviceContext,
                      (void **)&context, &offset) == S_OK);
                if (!context) return 2;
                ID2D1DeviceContext_GetDevice(context, &actual);
                check(actual == replacement);
                if (actual) ID2D1Device_Release(actual);
                ID2D1DeviceContext_Release(context);
                check(ICompositionDrawingSurfaceInterop_EndDraw(surface_interop) == S_OK);
                ICompositionDrawingSurfaceInterop_Release(surface_interop);
                ICompositionDrawingSurface_Release(drawing);
                handler.remove = TRUE;
                check(ICompositionGraphicsDeviceInterop_SetRenderingDevice(native, (IUnknown *)d2d) == S_OK);
                check(handler.calls == 2 && handler.ref == 1);
                check(ICompositionGraphicsDeviceInterop_SetRenderingDevice(native, (IUnknown *)replacement) == S_OK);
                check(handler.calls == 2);
                check(ICompositionGraphicsDevice_remove_RenderingDeviceReplaced(graphics, handler.token) == S_OK);
                {
                    ICompositionObject *object = NULL;
                    IClosable *closable = NULL;
                    ICompositor *owner = NULL;
                    ICompositionPropertySet *properties = NULL, *again = NULL;
                    ICompositionGraphicsDevice *device = NULL;
                    IUnknown *first = NULL, *second = NULL;
                    IID *iids = NULL;
                    ULONG count = 0;
                    check(IRenderingDeviceReplacedEventArgs_QueryInterface(handler.retained,
                          &IID_ICompositionObject, (void **)&object) == S_OK);
                    check(IRenderingDeviceReplacedEventArgs_QueryInterface(handler.retained,
                          &IID_IClosable, (void **)&closable) == S_OK);
                    if (object && closable)
                    {
                        check(ICompositionObject_QueryInterface(object, &IID_IUnknown, (void **)&first) == S_OK);
                        check(IClosable_QueryInterface(closable, &IID_IUnknown, (void **)&second) == S_OK);
                        check(first == second && first == (IUnknown *)handler.retained);
                        if (first) IUnknown_Release(first);
                        if (second) IUnknown_Release(second);
                        check(ICompositionObject_GetIids(object, &count, &iids) == S_OK);
                        check(count == 3);
                        CoTaskMemFree(iids);
                        check(ICompositionObject_get_Compositor(object, &owner) == S_OK);
                        check(owner == compositor);
                        if (owner) ICompositor_Release(owner);
                        check(ICompositionObject_get_Properties(object, &properties) == S_OK);
                        check(properties != NULL);
                        check(ICompositionObject_get_Properties(object, &again) == S_OK);
                        check(again == properties);
                        if (properties) ICompositionPropertySet_Release(properties);
                        if (again) ICompositionPropertySet_Release(again);
                        check(IClosable_Close(closable) == S_OK);
                        check(IClosable_Close(closable) == S_OK);
                        check(IRenderingDeviceReplacedEventArgs_get_GraphicsDevice(handler.retained, &device)
                              == RO_E_CLOSED);
                        check(device == NULL);
                        owner = NULL;
                        check(ICompositionObject_get_Compositor(object, &owner) == RO_E_CLOSED);
                        check(owner == NULL);
                    }
                    if (object) ICompositionObject_Release(object);
                    if (closable) IClosable_Release(closable);
                }
                IRenderingDeviceReplacedEventArgs_Release(handler.retained);
                handler.retained = NULL;
                handler.remove = FALSE;
                handler.interop = native;
                handler.next = (IUnknown *)replacement;
                check(ICompositionGraphicsDevice_add_RenderingDeviceReplaced(graphics, &handler.iface,
                      &handler.token) == S_OK);
                check(ICompositionGraphicsDeviceInterop_SetRenderingDevice(native, (IUnknown *)d2d) == S_OK);
                check(handler.calls == 4);
                got = NULL;
                check(ICompositionGraphicsDeviceInterop_GetRenderingDevice(native, &got) == S_OK);
                check(got == (IUnknown *)replacement);
                if (got) IUnknown_Release(got);
                check(ICompositionGraphicsDevice_remove_RenderingDeviceReplaced(graphics, handler.token) == S_OK);
                check(handler.ref == 1);
                if (handler.retained) IRenderingDeviceReplacedEventArgs_Release(handler.retained);
                handler.retained = NULL;
                ID2D1Device_Release(replacement);
            }
            IUnknown_Release(result);
        }
        printf("GRAPHICS_DEVICE_RESULT checks=%ld failures=%ld\n", checks, failures);
        ICompositionGraphicsDevice_Release(graphics);
        ICompositorInterop_Release(interop);
        ICompositor_Release(compositor);
        ICompositorController_Release(controller);
        ID2D1Device_Release(d2d);
        IDXGIDevice_Release(dxgi);
        ID3D11Device_Release(d3d);
        RoUninitialize();
        return FAILED(hr) || failures;
    }
}
