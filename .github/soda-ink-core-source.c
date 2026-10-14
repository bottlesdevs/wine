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

#define CONST_VTABLE
#define COBJMACROS
#include <stdarg.h>
#include <stdio.h>
#include <windows.h>
#include <winstring.h>
#include <initguid.h>
#include <roapi.h>
#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Numerics
#define WIDL_using_Windows_UI
#define WIDL_using_Windows_UI_Core
#define WIDL_using_Windows_UI_Composition
#define WIDL_using_Windows_UI_Input_Inking
#define WIDL_using_Windows_UI_Input_Inking_Core
#include "windows.ui.input.inking.core.h"

static LONG checks, failures;
#define check(expr) do { InterlockedIncrement(&checks); if (!(expr)) { printf("FAIL line %u: %s\n", __LINE__, #expr); InterlockedIncrement(&failures); } } while (0)

struct handler
{
    ITypedEventHandler_CoreWetStrokeUpdateSource_CoreWetStrokeUpdateEventArgs wet;
    ITypedEventHandler_CoreInkIndependentInputSource_PointerEventArgs pointer;
    LONG ref, calls;
};

static HRESULT handler_query(struct handler *handler, REFIID iid, void **out)
{
    *out = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IAgileObject)
            || IsEqualIID(iid, &IID_ITypedEventHandler_CoreWetStrokeUpdateSource_CoreWetStrokeUpdateEventArgs)) *out = &handler->wet;
    else if (IsEqualIID(iid, &IID_ITypedEventHandler_CoreInkIndependentInputSource_PointerEventArgs)) *out = &handler->pointer;
    else return E_NOINTERFACE;
    InterlockedIncrement(&handler->ref);
    return S_OK;
}

#define HANDLER(prefix, type, sender_type, args_type, member) \
static struct handler *prefix##_impl(type *iface) { return CONTAINING_RECORD(iface, struct handler, member); } \
static HRESULT WINAPI prefix##_query(type *iface, REFIID iid, void **out) { return handler_query(prefix##_impl(iface), iid, out); } \
static ULONG WINAPI prefix##_addref(type *iface) { return InterlockedIncrement(&prefix##_impl(iface)->ref); } \
static ULONG WINAPI prefix##_release(type *iface) { return InterlockedDecrement(&prefix##_impl(iface)->ref); } \
static HRESULT WINAPI prefix##_invoke(type *iface, sender_type *sender, args_type *args) \
{ InterlockedIncrement(&prefix##_impl(iface)->calls); return S_OK; } \
static const type##Vtbl prefix##_vtbl = {prefix##_query, prefix##_addref, prefix##_release, prefix##_invoke};

HANDLER(wet_handler, ITypedEventHandler_CoreWetStrokeUpdateSource_CoreWetStrokeUpdateEventArgs, ICoreWetStrokeUpdateSource, ICoreWetStrokeUpdateEventArgs, wet)
HANDLER(pointer_handler, ITypedEventHandler_CoreInkIndependentInputSource_PointerEventArgs, ICoreInkIndependentInputSource, IPointerEventArgs, pointer)

struct marshal_context
{
    IStream *wet, *pointer;
    DWORD apartment;
};

static DWORD WINAPI consume_sources(void *arg)
{
    struct marshal_context *context = arg;
    ICoreWetStrokeUpdateSource *wet;
    ICoreInkIndependentInputSource *pointer;
    IInkPresenter *a, *b;
    HSTRING name;
    boolean enabled;

    check(CoInitializeEx(NULL, context->apartment) == S_OK);
    check(CoGetInterfaceAndReleaseStream(context->wet, &IID_ICoreWetStrokeUpdateSource, (void **)&wet) == S_OK);
    check(CoGetInterfaceAndReleaseStream(context->pointer, &IID_ICoreInkIndependentInputSource, (void **)&pointer) == S_OK);
    check(ICoreWetStrokeUpdateSource_get_InkPresenter(wet, &a) == S_OK);
    check(ICoreInkIndependentInputSource_get_InkPresenter(pointer, &b) == S_OK && a == b);
    check(IInkPresenter_get_IsInputEnabled(a, &enabled) == S_OK && !enabled);
    check(ICoreWetStrokeUpdateSource_GetRuntimeClassName(wet, &name) == S_OK);
    check(!wcscmp(WindowsGetStringRawBuffer(name, NULL), RuntimeClass_Windows_UI_Input_Inking_Core_CoreWetStrokeUpdateSource));
    WindowsDeleteString(name);
    check(ICoreInkIndependentInputSource_GetRuntimeClassName(pointer, &name) == S_OK);
    check(!wcscmp(WindowsGetStringRawBuffer(name, NULL), RuntimeClass_Windows_UI_Input_Inking_Core_CoreInkIndependentInputSource));
    WindowsDeleteString(name);
    IInkPresenter_Release(a);
    IInkPresenter_Release(b);
    ICoreWetStrokeUpdateSource_Release(wet);
    ICoreInkIndependentInputSource_Release(pointer);
    CoUninitialize();
    return 0;
}

int main(int argc, char **argv)
{
    HRESULT (WINAPI *can_unload)(void);
    ICoreWetStrokeUpdateSourceStatics *wet_factory = NULL;
    ICoreInkIndependentInputSourceStatics *pointer_factory = NULL;
    IActivationFactory *activation;
    ICoreWetStrokeUpdateSource *wet;
    ICoreInkIndependentInputSource *pointer;
    ICoreInkPresenterHost *host;
    IInspectable *instance;
    IInkPresenter *presenter, *owner;
    IUnknown *unknown;
    HSTRING name;
    HMODULE module;
    HANDLE thread;
    HRESULT hr;
    IID *iids;
    ULONG count;
    EventRegistrationToken wet_tokens[5], pointer_tokens[7], duplicate;
    struct handler handler = {{&wet_handler_vtbl}, {&pointer_handler_vtbl}, 1, 0};
    struct marshal_context context;
    BOOL sta = argc > 1 && argv[1][0] == 's';

    check(RoInitialize(sta ? RO_INIT_SINGLETHREADED : RO_INIT_MULTITHREADED) == S_OK);
    check(WindowsCreateString(RuntimeClass_Windows_UI_Input_Inking_Core_CoreWetStrokeUpdateSource,
            wcslen(RuntimeClass_Windows_UI_Input_Inking_Core_CoreWetStrokeUpdateSource), &name) == S_OK);
    hr = RoGetActivationFactory(name, &IID_ICoreWetStrokeUpdateSourceStatics, (void **)&wet_factory);
    WindowsDeleteString(name);
    printf("WET_FACTORY=%#lx bits=%u apartment=%s\n", hr, (unsigned int)(8 * sizeof(void *)), sta ? "sta" : "mta");
    if (FAILED(hr)) return 2;
    check(WindowsCreateString(RuntimeClass_Windows_UI_Input_Inking_Core_CoreInkIndependentInputSource,
            wcslen(RuntimeClass_Windows_UI_Input_Inking_Core_CoreInkIndependentInputSource), &name) == S_OK);
    check(RoGetActivationFactory(name, &IID_ICoreInkIndependentInputSourceStatics, (void **)&pointer_factory) == S_OK);
    WindowsDeleteString(name);
    check(ICoreWetStrokeUpdateSourceStatics_QueryInterface(wet_factory, &IID_IActivationFactory, (void **)&activation) == S_OK);
    instance = (void *)1;
    check(IActivationFactory_ActivateInstance(activation, &instance) == E_NOTIMPL && !instance);
    IActivationFactory_Release(activation);
    unknown = (void *)1;
    check(ICoreWetStrokeUpdateSourceStatics_QueryInterface(wet_factory, &IID_ICoreInkIndependentInputSourceStatics, (void **)&unknown) == E_NOINTERFACE && !unknown);
    check(WindowsCreateString(RuntimeClass_Windows_UI_Input_Inking_Core_CoreInkPresenterHost,
            wcslen(RuntimeClass_Windows_UI_Input_Inking_Core_CoreInkPresenterHost), &name) == S_OK);
    check(RoActivateInstance(name, &instance) == S_OK);
    WindowsDeleteString(name);
    check(IInspectable_QueryInterface(instance, &IID_ICoreInkPresenterHost, (void **)&host) == S_OK);
    IInspectable_Release(instance);
    check(ICoreInkPresenterHost_get_InkPresenter(host, &presenter) == S_OK);
    wet = (void *)1;
    check(ICoreWetStrokeUpdateSourceStatics_Create(wet_factory, NULL, &wet) == E_POINTER && !wet);
    pointer = (void *)1;
    check(ICoreInkIndependentInputSourceStatics_Create(pointer_factory, NULL, &pointer) == E_POINTER && !pointer);
    check(ICoreWetStrokeUpdateSourceStatics_Create(wet_factory, presenter, NULL) == E_POINTER);
    check(ICoreInkIndependentInputSourceStatics_Create(pointer_factory, presenter, NULL) == E_POINTER);
    check(ICoreWetStrokeUpdateSourceStatics_Create(wet_factory, presenter, &wet) == S_OK);
    check(ICoreInkIndependentInputSourceStatics_Create(pointer_factory, presenter, &pointer) == S_OK);
    ICoreWetStrokeUpdateSourceStatics_Release(wet_factory);
    ICoreInkIndependentInputSourceStatics_Release(pointer_factory);
    module = LoadLibraryW(L"inkobjcore.dll");
    check(module != NULL);
    can_unload = (void *)GetProcAddress(module, "DllCanUnloadNow");
    check(can_unload != NULL && can_unload() == S_FALSE);
    check(ICoreWetStrokeUpdateSource_GetIids(wet, &count, &iids) == S_OK && count == 1 && IsEqualIID(iids, &IID_ICoreWetStrokeUpdateSource));
    CoTaskMemFree(iids);
    check(ICoreInkIndependentInputSource_GetIids(pointer, &count, &iids) == S_OK && count == 1 && IsEqualIID(iids, &IID_ICoreInkIndependentInputSource));
    CoTaskMemFree(iids);
    unknown = (void *)1;
    check(ICoreWetStrokeUpdateSource_QueryInterface(wet, &IID_ICoreInkIndependentInputSource, (void **)&unknown) == E_NOINTERFACE && !unknown);
    check(ICoreWetStrokeUpdateSource_get_InkPresenter(wet, &owner) == S_OK && owner == presenter);
    IInkPresenter_Release(owner);
    check(ICoreWetStrokeUpdateSource_add_WetStrokeStarting(wet, &handler.wet, &wet_tokens[0]) == S_OK);
    check(ICoreWetStrokeUpdateSource_add_WetStrokeContinuing(wet, &handler.wet, &wet_tokens[1]) == S_OK);
    check(ICoreWetStrokeUpdateSource_add_WetStrokeStopping(wet, &handler.wet, &wet_tokens[2]) == S_OK);
    check(ICoreWetStrokeUpdateSource_add_WetStrokeCompleted(wet, &handler.wet, &wet_tokens[3]) == S_OK);
    check(ICoreWetStrokeUpdateSource_add_WetStrokeCanceled(wet, &handler.wet, &wet_tokens[4]) == S_OK);
    check(ICoreInkIndependentInputSource_add_PointerEntering(pointer, &handler.pointer, &pointer_tokens[0]) == S_OK);
    check(ICoreInkIndependentInputSource_add_PointerHovering(pointer, &handler.pointer, &pointer_tokens[1]) == S_OK);
    check(ICoreInkIndependentInputSource_add_PointerExiting(pointer, &handler.pointer, &pointer_tokens[2]) == S_OK);
    check(ICoreInkIndependentInputSource_add_PointerPressing(pointer, &handler.pointer, &pointer_tokens[3]) == S_OK);
    check(ICoreInkIndependentInputSource_add_PointerMoving(pointer, &handler.pointer, &pointer_tokens[4]) == S_OK);
    check(ICoreInkIndependentInputSource_add_PointerReleasing(pointer, &handler.pointer, &pointer_tokens[5]) == S_OK);
    check(ICoreInkIndependentInputSource_add_PointerLost(pointer, &handler.pointer, &pointer_tokens[6]) == S_OK);
    check(handler.ref == 13);
    check(ICoreWetStrokeUpdateSource_add_WetStrokeStarting(wet, &handler.wet, &duplicate) == S_OK && duplicate.value != wet_tokens[0].value && handler.ref == 14);
    check(ICoreWetStrokeUpdateSource_remove_WetStrokeCompleted(wet, duplicate) == S_OK && handler.ref == 14);
    check(ICoreWetStrokeUpdateSource_remove_WetStrokeStarting(wet, duplicate) == S_OK && handler.ref == 13);
    check(ICoreWetStrokeUpdateSource_remove_WetStrokeStarting(wet, wet_tokens[0]) == S_OK && handler.ref == 12);
    check(ICoreWetStrokeUpdateSource_remove_WetStrokeStarting(wet, wet_tokens[0]) == S_OK && handler.ref == 12);
    check(IInkPresenter_put_IsInputEnabled(presenter, FALSE) == S_OK);
    context.apartment = sta ? COINIT_MULTITHREADED : COINIT_APARTMENTTHREADED;
    check(CoMarshalInterThreadInterfaceInStream(&IID_ICoreWetStrokeUpdateSource, (IUnknown *)wet, &context.wet) == S_OK);
    check(CoMarshalInterThreadInterfaceInStream(&IID_ICoreInkIndependentInputSource, (IUnknown *)pointer, &context.pointer) == S_OK);
    ICoreInkPresenterHost_Release(host);
    IInkPresenter_Release(presenter);
    ICoreWetStrokeUpdateSource_Release(wet);
    ICoreInkIndependentInputSource_Release(pointer);
    check(handler.ref == 12);
    thread = CreateThread(NULL, 0, consume_sources, &context, 0, NULL);
    check(thread != NULL);
    check(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    check(handler.ref == 1 && !handler.calls);
    RoUninitialize();
    check(can_unload() == S_OK);
    FreeLibrary(module);
    printf("INK_SOURCE_RESULT checks=%ld failures=%ld\n", checks, failures);
    return failures ? 1 : 0;
}
