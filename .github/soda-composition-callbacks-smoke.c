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
    LONG ref, calls, destroyed, self_remove, reenter_add, reenter_release;
    BOOL fail;
    ICompositorController *controller;
    EventRegistrationToken token;
    struct handler *next;
    HANDLE entered, proceed;
};
struct reentry
{
    ICompositorController *controller;
    HANDLE thread;
};

static struct reentry reentries[16];
static LONG reentry_count;

static DWORD WINAPI remove_unknown(void *arg)
{
    struct reentry *entry = arg;
    check(RoInitialize(RO_INIT_MULTITHREADED) == S_OK);
    check(ICompositorController_remove_CommitNeeded(entry->controller, (EventRegistrationToken){0}) == S_OK);
    ICompositorController_Release(entry->controller);
    RoUninitialize();
    return 0;
}

static void reenter(struct handler *handler)
{
    struct reentry *entry = &reentries[InterlockedIncrement(&reentry_count) - 1];
    entry->controller = handler->controller;
    ICompositorController_AddRef(entry->controller);
    entry->thread = CreateThread(NULL, 0, remove_unknown, entry, 0, NULL);
    check(entry->thread != NULL);
    if (entry->thread) check(WaitForSingleObject(entry->thread, 5000) == WAIT_OBJECT_0);
}

static HRESULT WINAPI handler_QueryInterface(ITypedEventHandler_CompositorController_IInspectable *iface, REFIID iid,
                                             void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) &&
        !IsEqualGUID(iid, &IID_ITypedEventHandler_CompositorController_IInspectable))
        return E_NOINTERFACE;
    *out = iface;
    ITypedEventHandler_CompositorController_IInspectable_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI handler_AddRef(ITypedEventHandler_CompositorController_IInspectable *iface)
{
    struct handler *handler = CONTAINING_RECORD(iface, struct handler, iface);
    LONG ref = InterlockedIncrement(&handler->ref);
    if (InterlockedExchange(&handler->reenter_add, 0)) reenter(handler);
    return ref;
}

static ULONG WINAPI handler_Release(ITypedEventHandler_CompositorController_IInspectable *iface)
{
    struct handler *handler = CONTAINING_RECORD(iface, struct handler, iface);
    LONG ref = InterlockedDecrement(&handler->ref);
    if (InterlockedExchange(&handler->reenter_release, 0)) reenter(handler);
    if (!ref) InterlockedIncrement(&handler->destroyed);
    return ref;
}

static HRESULT WINAPI handler_Invoke(ITypedEventHandler_CompositorController_IInspectable *iface,
                                     ICompositorController *sender, IInspectable *args)
{
    struct handler *handler = CONTAINING_RECORD(iface, struct handler, iface);
    InterlockedIncrement(&handler->calls);
    check(sender == handler->controller);
    if (InterlockedExchange(&handler->self_remove, 0))
    {
        check(ICompositorController_remove_CommitNeeded(sender, handler->token) == S_OK);
        check(ICompositorController_add_CommitNeeded(sender, &handler->next->iface, &handler->next->token) == S_OK);
    }
    if (handler->entered)
    {
        SetEvent(handler->entered);
        check(WaitForSingleObject(handler->proceed, 10000) == WAIT_OBJECT_0);
    }
    return handler->fail ? E_FAIL : S_OK;
}

static const ITypedEventHandler_CompositorController_IInspectableVtbl handler_vtbl = {
    handler_QueryInterface, handler_AddRef, handler_Release, handler_Invoke};

static void initialize_handler(struct handler *handler, ICompositorController *controller)
{
    memset(handler, 0, sizeof(*handler));
    handler->iface.lpVtbl = &handler_vtbl;
    handler->ref = 1;
    handler->controller = controller;
}

static void create_controller(ICompositorController **controller, ICompositor **compositor)
{
    HSTRING name = NULL;
    IInspectable *instance = NULL;
    check(WindowsCreateString(RuntimeClass_Windows_UI_Composition_Core_CompositorController,
                              ARRAYSIZE(RuntimeClass_Windows_UI_Composition_Core_CompositorController) - 1,
                              &name) == S_OK);
    check(RoActivateInstance(name, &instance) == S_OK);
    WindowsDeleteString(name);
    check(instance != NULL);
    if (!instance) ExitProcess(2);
    check(IInspectable_QueryInterface(instance, &IID_ICompositorController, (void **)controller) == S_OK);
    IInspectable_Release(instance);
    check(ICompositorController_get_Compositor(*controller, compositor) == S_OK);
}

static void trigger(ICompositor *compositor)
{
    ISpriteVisual *sprite = NULL;
    check(ICompositor_CreateSpriteVisual(compositor, &sprite) == S_OK);
    check(sprite != NULL);
    if (sprite) ISpriteVisual_Release(sprite);
}
struct trigger_context
{
    ICompositor *compositor;
    HANDLE start;
};

static DWORD WINAPI trigger_thread(void *arg)
{
    struct trigger_context *context = arg;
    check(RoInitialize(RO_INIT_MULTITHREADED) == S_OK);
    if (context->start) check(WaitForSingleObject(context->start, 10000) == WAIT_OBJECT_0);
    trigger(context->compositor);
    RoUninitialize();
    return 0;
}
int main(void)
{
    ICompositorController *controller = NULL;
    ICompositor *compositor = NULL;
    struct handler a, b;
    struct trigger_context context;
    HANDLE thread;
    setvbuf(stdout, NULL, _IONBF, 0);
    check(RoInitialize(RO_INIT_MULTITHREADED) == S_OK);
    create_controller(&controller, &compositor);
    initialize_handler(&a, controller);
    initialize_handler(&b, controller);
    a.self_remove = 1;
    a.next = &b;
    check(ICompositorController_add_CommitNeeded(controller, &a.iface, &a.token) == S_OK);
    trigger(compositor);
    check(a.calls == 1 && b.calls == 0 && a.ref == 1 && b.ref == 2);
    trigger(compositor);
    check(a.calls == 1 && b.calls == 1);
    check(ICompositorController_remove_CommitNeeded(controller, b.token) == S_OK);
    ITypedEventHandler_CompositorController_IInspectable_Release(&a.iface);
    ITypedEventHandler_CompositorController_IInspectable_Release(&b.iface);
    check(a.destroyed == 1 && b.destroyed == 1);

    initialize_handler(&a, controller);
    initialize_handler(&b, controller);
    a.fail = TRUE;
    check(ICompositorController_add_CommitNeeded(controller, &a.iface, &a.token) == S_OK);
    check(ICompositorController_add_CommitNeeded(controller, &b.iface, &b.token) == S_OK);
    trigger(compositor);
    check(a.calls == 1 && b.calls == 1);
    check(ICompositorController_remove_CommitNeeded(controller, a.token) == S_OK);
    check(ICompositorController_remove_CommitNeeded(controller, b.token) == S_OK);
    ITypedEventHandler_CompositorController_IInspectable_Release(&a.iface);
    ITypedEventHandler_CompositorController_IInspectable_Release(&b.iface);
    check(a.destroyed == 1 && b.destroyed == 1);

    initialize_handler(&a, controller);
    a.reenter_add = 1;
    check(ICompositorController_add_CommitNeeded(controller, &a.iface, &a.token) == S_OK);
    check(reentry_count == 1);
    a.reenter_release = 1;
    check(ICompositorController_remove_CommitNeeded(controller, a.token) == S_OK);
    check(reentry_count == 2);
    ITypedEventHandler_CompositorController_IInspectable_Release(&a.iface);
    check(a.destroyed == 1);
    for (LONG i = 0; i < reentry_count; ++i)
    {
        check(WaitForSingleObject(reentries[i].thread, 10000) == WAIT_OBJECT_0);
        CloseHandle(reentries[i].thread);
    }

    initialize_handler(&a, controller);
    a.entered = CreateEventW(NULL, TRUE, FALSE, NULL);
    a.proceed = CreateEventW(NULL, TRUE, FALSE, NULL);
    check(a.entered && a.proceed);
    check(ICompositorController_add_CommitNeeded(controller, &a.iface, &a.token) == S_OK);
    context = (struct trigger_context){compositor, NULL};
    thread = CreateThread(NULL, 0, trigger_thread, &context, 0, NULL);
    check(thread != NULL);
    check(WaitForSingleObject(a.entered, 10000) == WAIT_OBJECT_0);
    check(ICompositorController_remove_CommitNeeded(controller, a.token) == S_OK);
    ITypedEventHandler_CompositorController_IInspectable_Release(&a.iface);
    check(a.destroyed == 0 && a.calls == 1);
    ICompositorController_Release(controller);
    controller = NULL;
    SetEvent(a.proceed);
    check(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    check(a.destroyed == 1 && a.ref == 0);
    CloseHandle(a.entered);
    CloseHandle(a.proceed);
    trigger(compositor);
    ICompositor_Release(compositor);

    for (UINT i = 0; i < 128; ++i)
    {
        create_controller(&controller, &compositor);
        context = (struct trigger_context){compositor, CreateEventW(NULL, TRUE, FALSE, NULL)};
        check(context.start != NULL);
        thread = CreateThread(NULL, 0, trigger_thread, &context, 0, NULL);
        check(thread != NULL);
        SetEvent(context.start);
        ICompositorController_Release(controller);
        check(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
        CloseHandle(thread);
        CloseHandle(context.start);
        trigger(compositor);
        ICompositor_Release(compositor);
    }
    RoUninitialize();
    printf("CONTROLLER_CALLBACK_RESULT checks=%ld failures=%ld\n", checks, failures);
    return failures ? 1 : 0;
}
