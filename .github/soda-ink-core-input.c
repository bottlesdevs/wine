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
    ITypedEventHandler_InkStrokeInput_PointerEventArgs stroke;
    ITypedEventHandler_InkUnprocessedInput_PointerEventArgs unprocessed;
    ITypedEventHandler_InkPresenter_InkStrokesCollectedEventArgs collected;
    ITypedEventHandler_InkPresenter_InkStrokesErasedEventArgs erased;
    LONG ref, calls;
};

static HRESULT handler_query(struct handler *handler, REFIID iid, void **out)
{
    *out = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IAgileObject)
            || IsEqualIID(iid, &IID_ITypedEventHandler_InkStrokeInput_PointerEventArgs)) *out = &handler->stroke;
    if (IsEqualIID(iid, &IID_ITypedEventHandler_InkUnprocessedInput_PointerEventArgs)) *out = &handler->unprocessed;
    if (IsEqualIID(iid, &IID_ITypedEventHandler_InkPresenter_InkStrokesCollectedEventArgs)) *out = &handler->collected;
    if (IsEqualIID(iid, &IID_ITypedEventHandler_InkPresenter_InkStrokesErasedEventArgs)) *out = &handler->erased;
    if (!*out) return E_NOINTERFACE;
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

HANDLER(stroke_handler, ITypedEventHandler_InkStrokeInput_PointerEventArgs, IInkStrokeInput, IPointerEventArgs, stroke)
HANDLER(unprocessed_handler, ITypedEventHandler_InkUnprocessedInput_PointerEventArgs, IInkUnprocessedInput, IPointerEventArgs, unprocessed)
HANDLER(collected_handler, ITypedEventHandler_InkPresenter_InkStrokesCollectedEventArgs, IInkPresenter, IInkStrokesCollectedEventArgs, collected)
HANDLER(erased_handler, ITypedEventHandler_InkPresenter_InkStrokesErasedEventArgs, IInkPresenter, IInkStrokesErasedEventArgs, erased)

struct marshal_context
{
    IStream *stroke, *unprocessed;
    DWORD apartment;
};

static DWORD WINAPI consume_inputs(void *arg)
{
    struct marshal_context *context = arg;
    IInkStrokeInput *stroke;
    IInkUnprocessedInput *unprocessed;
    IInkPresenter *a, *b;
    HSTRING name;

    check(CoInitializeEx(NULL, context->apartment) == S_OK);
    check(CoGetInterfaceAndReleaseStream(context->stroke, &IID_IInkStrokeInput, (void **)&stroke) == S_OK);
    check(CoGetInterfaceAndReleaseStream(context->unprocessed, &IID_IInkUnprocessedInput, (void **)&unprocessed) == S_OK);
    check(IInkStrokeInput_get_InkPresenter(stroke, &a) == S_OK);
    check(IInkUnprocessedInput_get_InkPresenter(unprocessed, &b) == S_OK && a == b);
    check(IInkStrokeInput_GetRuntimeClassName(stroke, &name) == S_OK);
    check(!wcscmp(WindowsGetStringRawBuffer(name, NULL), RuntimeClass_Windows_UI_Input_Inking_InkStrokeInput));
    WindowsDeleteString(name);
    check(IInkUnprocessedInput_GetRuntimeClassName(unprocessed, &name) == S_OK);
    check(!wcscmp(WindowsGetStringRawBuffer(name, NULL), RuntimeClass_Windows_UI_Input_Inking_InkUnprocessedInput));
    WindowsDeleteString(name);
    IInkPresenter_Release(a);
    IInkPresenter_Release(b);
    IInkStrokeInput_Release(stroke);
    IInkUnprocessedInput_Release(unprocessed);
    CoUninitialize();
    return 0;
}

int main(int argc, char **argv)
{
    HRESULT (WINAPI *can_unload)(void);
    ICoreInkPresenterHost *host;
    IInspectable *instance;
    IInkPresenter *presenter, *owner;
    IInkStrokeInput *stroke, *same;
    IInkUnprocessedInput *unprocessed;
    IUnknown *identity, *other;
    HSTRING name;
    HMODULE module;
    HANDLE thread;
    HRESULT hr;
    IID *iids;
    ULONG count;
    EventRegistrationToken stroke_tokens[4], pointer_tokens[7], collected, erased, duplicate, invalid;
    struct handler handler = {{&stroke_handler_vtbl}, {&unprocessed_handler_vtbl}, {&collected_handler_vtbl}, {&erased_handler_vtbl}, 1, 0};
    struct marshal_context context;
    BOOL sta = argc > 1 && argv[1][0] == 's';

    check(RoInitialize(sta ? RO_INIT_SINGLETHREADED : RO_INIT_MULTITHREADED) == S_OK);
    check(WindowsCreateString(RuntimeClass_Windows_UI_Input_Inking_Core_CoreInkPresenterHost,
            wcslen(RuntimeClass_Windows_UI_Input_Inking_Core_CoreInkPresenterHost), &name) == S_OK);
    check(RoActivateInstance(name, &instance) == S_OK);
    WindowsDeleteString(name);
    check(IInspectable_QueryInterface(instance, &IID_ICoreInkPresenterHost, (void **)&host) == S_OK);
    IInspectable_Release(instance);
    check(ICoreInkPresenterHost_get_InkPresenter(host, &presenter) == S_OK);
    hr = IInkPresenter_get_StrokeInput(presenter, &stroke);
    printf("STROKE_INPUT=%#lx bits=%u apartment=%s\n", hr, (unsigned int)(8 * sizeof(void *)), sta ? "sta" : "mta");
    if (FAILED(hr))
    {
        IInkPresenter_Release(presenter);
        ICoreInkPresenterHost_Release(host);
        RoUninitialize();
        return 2;
    }
    check(IInkPresenter_get_UnprocessedInput(presenter, &unprocessed) == S_OK);
    module = LoadLibraryW(L"inkobjcore.dll");
    check(module != NULL);
    can_unload = (void *)GetProcAddress(module, "DllCanUnloadNow");
    check(can_unload != NULL && can_unload() == S_FALSE);
    check(IInkPresenter_get_StrokeInput(presenter, &same) == S_OK && stroke == same);
    IInkStrokeInput_Release(same);
    check(IInkStrokeInput_QueryInterface(stroke, &IID_IUnknown, (void **)&identity) == S_OK);
    check(identity == (IUnknown *)stroke && identity != (IUnknown *)presenter);
    check(IInkUnprocessedInput_QueryInterface(unprocessed, &IID_IUnknown, (void **)&other) == S_OK);
    check(other == (IUnknown *)unprocessed && other != identity && other != (IUnknown *)presenter);
    IUnknown_Release(identity);
    IUnknown_Release(other);
    check(IInkStrokeInput_GetIids(stroke, &count, &iids) == S_OK && count == 1 && IsEqualIID(iids, &IID_IInkStrokeInput));
    CoTaskMemFree(iids);
    check(IInkUnprocessedInput_GetIids(unprocessed, &count, &iids) == S_OK && count == 1 && IsEqualIID(iids, &IID_IInkUnprocessedInput));
    CoTaskMemFree(iids);
    check(IInkStrokeInput_get_InkPresenter(stroke, &owner) == S_OK && owner == presenter);
    IInkPresenter_Release(owner);
    invalid.value = 99;
    check(IInkStrokeInput_add_StrokeStarted(stroke, NULL, &invalid) == E_POINTER && !invalid.value && handler.ref == 1);
    check(IInkStrokeInput_add_StrokeStarted(stroke, &handler.stroke, NULL) == E_POINTER && handler.ref == 1);
    check(IInkStrokeInput_add_StrokeStarted(stroke, &handler.stroke, &stroke_tokens[0]) == S_OK);
    check(IInkStrokeInput_add_StrokeContinued(stroke, &handler.stroke, &stroke_tokens[1]) == S_OK);
    check(IInkStrokeInput_add_StrokeEnded(stroke, &handler.stroke, &stroke_tokens[2]) == S_OK);
    check(IInkStrokeInput_add_StrokeCanceled(stroke, &handler.stroke, &stroke_tokens[3]) == S_OK);
    check(IInkUnprocessedInput_add_PointerEntered(unprocessed, &handler.unprocessed, &pointer_tokens[0]) == S_OK);
    check(IInkUnprocessedInput_add_PointerHovered(unprocessed, &handler.unprocessed, &pointer_tokens[1]) == S_OK);
    check(IInkUnprocessedInput_add_PointerExited(unprocessed, &handler.unprocessed, &pointer_tokens[2]) == S_OK);
    check(IInkUnprocessedInput_add_PointerPressed(unprocessed, &handler.unprocessed, &pointer_tokens[3]) == S_OK);
    check(IInkUnprocessedInput_add_PointerMoved(unprocessed, &handler.unprocessed, &pointer_tokens[4]) == S_OK);
    check(IInkUnprocessedInput_add_PointerReleased(unprocessed, &handler.unprocessed, &pointer_tokens[5]) == S_OK);
    check(IInkUnprocessedInput_add_PointerLost(unprocessed, &handler.unprocessed, &pointer_tokens[6]) == S_OK);
    check(IInkPresenter_add_StrokesCollected(presenter, &handler.collected, &collected) == S_OK);
    check(IInkPresenter_add_StrokesErased(presenter, &handler.erased, &erased) == S_OK);
    check(handler.ref == 14);
    check(stroke_tokens[0].value && stroke_tokens[3].value > stroke_tokens[0].value && pointer_tokens[6].value > pointer_tokens[0].value);
    check(IInkStrokeInput_add_StrokeStarted(stroke, &handler.stroke, &duplicate) == S_OK && duplicate.value != stroke_tokens[0].value && handler.ref == 15);
    check(IInkStrokeInput_remove_StrokeEnded(stroke, duplicate) == S_OK && handler.ref == 15);
    check(IInkStrokeInput_remove_StrokeStarted(stroke, duplicate) == S_OK && handler.ref == 14);
    check(IInkUnprocessedInput_remove_PointerMoved(unprocessed, pointer_tokens[4]) == S_OK && handler.ref == 13);
    check(IInkUnprocessedInput_remove_PointerMoved(unprocessed, pointer_tokens[4]) == S_OK && handler.ref == 13);
    check(IInkPresenter_remove_StrokesErased(presenter, erased) == S_OK && handler.ref == 12);
    context.apartment = sta ? COINIT_MULTITHREADED : COINIT_APARTMENTTHREADED;
    check(CoMarshalInterThreadInterfaceInStream(&IID_IInkStrokeInput, (IUnknown *)stroke, &context.stroke) == S_OK);
    check(CoMarshalInterThreadInterfaceInStream(&IID_IInkUnprocessedInput, (IUnknown *)unprocessed, &context.unprocessed) == S_OK);
    ICoreInkPresenterHost_Release(host);
    IInkPresenter_Release(presenter);
    IInkStrokeInput_Release(stroke);
    IInkUnprocessedInput_Release(unprocessed);
    check(handler.ref == 12);
    thread = CreateThread(NULL, 0, consume_inputs, &context, 0, NULL);
    check(thread != NULL);
    check(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    check(handler.ref == 1 && !handler.calls);
    RoUninitialize();
    check(can_unload() == S_OK);
    FreeLibrary(module);
    printf("INK_INPUT_RESULT checks=%ld failures=%ld\n", checks, failures);
    return failures ? 1 : 0;
}
