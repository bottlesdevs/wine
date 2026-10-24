#define COBJMACROS
#define INITGUID
#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#define WIDL_using_Windows_Foundation
#include "windows.foundation.h"
#define WIDL_using_Windows_UI_Composition
#include "windows.ui.composition.h"
#define WIDL_using_Windows_UI_Composition_Interactions
#include "windows.ui.composition.interactions.h"
#include <stdio.h>
#include <string.h>

static LONG checks, failures;

static void check(const char *label, BOOL value)
{
    InterlockedIncrement(&checks);
    if (value) return;
    InterlockedIncrement(&failures);
    printf("%s:failed\n", label);
}

static HRESULT factory(const WCHAR *name, REFIID iid, void **value)
{
    HSTRING class_id;
    HRESULT hr = WindowsCreateString(name, lstrlenW(name), &class_id);
    if (FAILED(hr)) return hr;
    hr = RoGetActivationFactory(class_id, iid, value);
    WindowsDeleteString(class_id);
    return hr;
}

static void metadata(IInspectable *value)
{
    HSTRING name = NULL;
    IID *iids = NULL;
    IUnknown *view = NULL, *identity = NULL, *other = NULL;
    ULONG count = 0, i;

    check("runtime_name", IInspectable_GetRuntimeClassName(value, &name) == S_OK);
    check("runtime_class", name && !wcscmp(WindowsGetStringRawBuffer(name, NULL),
            RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaRestingValue));
    WindowsDeleteString(name);
    check("interface_list", IInspectable_GetIids(value, &count, &iids) == S_OK);
    check("interface_count", count == 4 && iids);
    check("identity", IInspectable_QueryInterface(value, &IID_IUnknown, (void **)&identity) == S_OK);
    if (iids) for (i = 0; i < count; ++i)
    {
        check("listed_interface", IInspectable_QueryInterface(value, &iids[i], (void **)&view) == S_OK && view);
        if (!view) continue;
        check("interface_identity", IUnknown_QueryInterface(view, &IID_IUnknown, (void **)&other) == S_OK && other == identity);
        if (other) IUnknown_Release(other);
        IUnknown_Release(view);
        view = other = NULL;
    }
    if (identity) IUnknown_Release(identity);
    CoTaskMemFree(iids);
}

static void legacy_conditional_value(ICompositor *compositor, IExpressionAnimation *animation)
{
    ICompositionConditionalValueStatics *statics = NULL;
    ICompositionConditionalValue *value = NULL;
    IExpressionAnimation *observed = NULL;
    IInteractionTrackerInertiaRestingValue *resting = NULL;
    ICompositionObject *object = NULL;
    IClosable *closable = NULL;
    HSTRING name = NULL;
    HRESULT hr;

    hr = factory(RuntimeClass_Windows_UI_Composition_Interactions_CompositionConditionalValue,
            &IID_ICompositionConditionalValueStatics, (void **)&statics);
    check("legacy_factory", hr == S_OK && statics);
    if (!statics) return;
    hr = ICompositionConditionalValueStatics_Create(statics, compositor, &value);
    check("legacy_create", hr == S_OK && value);
    if (!value) goto done;
    check("legacy_name", ICompositionConditionalValue_GetRuntimeClassName(value, &name) == S_OK && name &&
            !wcscmp(WindowsGetStringRawBuffer(name, NULL),
            RuntimeClass_Windows_UI_Composition_Interactions_CompositionConditionalValue));
    WindowsDeleteString(name);
    check("legacy_interface", ICompositionConditionalValue_QueryInterface(value,
            &IID_IInteractionTrackerInertiaRestingValue, (void **)&resting) == E_NOINTERFACE && !resting);
    if (resting) IInteractionTrackerInertiaRestingValue_Release(resting);
    check("legacy_default", ICompositionConditionalValue_get_Condition(value, &observed) == S_OK && !observed);
    if (observed) IExpressionAnimation_Release(observed);
    check("legacy_set", ICompositionConditionalValue_put_Value(value, animation) == S_OK);
    check("legacy_get", ICompositionConditionalValue_get_Value(value, &observed) == S_OK && observed == animation);
    if (observed) IExpressionAnimation_Release(observed);
    check("legacy_self_set", ICompositionConditionalValue_put_Value(value, animation) == S_OK);
    check("legacy_composition", ICompositionConditionalValue_QueryInterface(value,
            &IID_ICompositionObject, (void **)&object) == S_OK && object);
    check("legacy_closable", ICompositionConditionalValue_QueryInterface(value,
            &IID_IClosable, (void **)&closable) == S_OK && closable);
    if (closable) check("legacy_close", IClosable_Close(closable) == S_OK);
    check("legacy_clear", ICompositionConditionalValue_put_Value(value, NULL) == S_OK);
    check("legacy_cleared", ICompositionConditionalValue_get_Value(value, &observed) == S_OK && !observed);
    if (observed) IExpressionAnimation_Release(observed);
    if (object) ICompositionObject_Release(object);
    if (closable) IClosable_Release(closable);
    ICompositionConditionalValue_Release(value);
done:
    ICompositionConditionalValueStatics_Release(statics);
}

struct writer_context
{
    IInteractionTrackerInertiaRestingValue *value;
    IExpressionAnimation *animation;
    HANDLE ready;
};

static DWORD WINAPI writer(void *argument)
{
    struct writer_context *context = argument;
    IExpressionAnimation *animation;
    HRESULT hr;
    unsigned int i;

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    check("worker_initialize", SUCCEEDED(hr));
    if (FAILED(hr)) return 1;
    for (i = 0; i < 1000; ++i)
    {
        hr = IInteractionTrackerInertiaRestingValue_put_Condition(context->value, context->animation);
        check("worker_set", hr == S_OK || hr == RO_E_CLOSED);
        animation = (void *)0xdeadbeef;
        hr = IInteractionTrackerInertiaRestingValue_get_Condition(context->value, &animation);
        check("worker_get", (hr == S_OK && animation == context->animation) || (hr == RO_E_CLOSED && !animation));
        if (SUCCEEDED(hr) && animation) IExpressionAnimation_Release(animation);
        if (i == 16) SetEvent(context->ready);
    }
    RoUninitialize();
    return 0;
}

int main(int argc, char **argv)
{
    IInteractionTrackerInertiaRestingValueStatics *statics = NULL;
    IInteractionTrackerInertiaRestingValue *value = NULL;
    IActivationFactory *activation = NULL;
    IInspectable *compositor_object = NULL;
    ICompositionObject *object = NULL;
    ICompositor *compositor = NULL, *parent = NULL;
    ICompositionPropertySet *properties = NULL;
    IExpressionAnimation *animation = NULL, *observed = NULL;
    IClosable *closable = NULL;
    IUnknown *agile = NULL;
    HSTRING text = NULL;
    HANDLE threads[2];
    struct writer_context context;
    HRESULT hr;
    unsigned int i;

    setvbuf(stdout, NULL, _IONBF, 0);
    hr = RoInitialize(argc > 1 && !strcmp(argv[1], "sta") ? RO_INIT_SINGLETHREADED : RO_INIT_MULTITHREADED);
    if (FAILED(hr)) return 2;
    hr = factory(RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaRestingValue,
            &IID_IInteractionTrackerInertiaRestingValueStatics, (void **)&statics);
    printf("resting_value_factory:%08lx\n", (unsigned long)hr);
    if (FAILED(hr) || !statics) return 1;
    check("null_compositor", IInteractionTrackerInertiaRestingValueStatics_Create(statics, NULL, &value) == E_INVALIDARG && !value);
    check("null_result", IInteractionTrackerInertiaRestingValueStatics_Create(statics, NULL, NULL) == E_POINTER);
    hr = factory(RuntimeClass_Windows_UI_Composition_Compositor, &IID_IActivationFactory, (void **)&activation);
    if (FAILED(hr) || !activation) return 3;
    hr = IActivationFactory_ActivateInstance(activation, &compositor_object);
    if (FAILED(hr) || !compositor_object) return 4;
    hr = IInspectable_QueryInterface(compositor_object, &IID_ICompositor, (void **)&compositor);
    if (FAILED(hr) || !compositor) return 5;
    check("create", IInteractionTrackerInertiaRestingValueStatics_Create(statics, compositor, &value) == S_OK && value);
    if (!value) return 6;
    metadata((IInspectable *)value);
    check("agile", IInteractionTrackerInertiaRestingValue_QueryInterface(value, &IID_IAgileObject, (void **)&agile) == S_OK && agile);
    if (agile) IUnknown_Release(agile);
    check("composition_object", IInteractionTrackerInertiaRestingValue_QueryInterface(value, &IID_ICompositionObject, (void **)&object) == S_OK && object);
    check("closable", IInteractionTrackerInertiaRestingValue_QueryInterface(value, &IID_IClosable, (void **)&closable) == S_OK && closable);
    if (!object || !closable) return 7;
    check("compositor", ICompositionObject_get_Compositor(object, &parent) == S_OK && parent == compositor);
    if (parent) ICompositor_Release(parent);
    check("properties", ICompositionObject_get_Properties(object, &properties) == S_OK && properties);
    if (properties) ICompositionPropertySet_Release(properties);
    check("condition_default", IInteractionTrackerInertiaRestingValue_get_Condition(value, &observed) == S_OK && !observed);
    check("resting_default", IInteractionTrackerInertiaRestingValue_get_RestingValue(value, &observed) == S_OK && !observed);
    check("null_get", IInteractionTrackerInertiaRestingValue_get_Condition(value, NULL) == E_POINTER);
    check("expression_create", ICompositor_CreateExpressionAnimation(compositor, &animation) == S_OK && animation);
    if (!animation) return 8;
    WindowsCreateString(L"42", 2, &text);
    check("expression_set", IExpressionAnimation_put_Expression(animation, text) == S_OK);
    WindowsDeleteString(text);
    check("condition_set", IInteractionTrackerInertiaRestingValue_put_Condition(value, animation) == S_OK);
    check("resting_set", IInteractionTrackerInertiaRestingValue_put_RestingValue(value, animation) == S_OK);
    check("condition_identity", IInteractionTrackerInertiaRestingValue_get_Condition(value, &observed) == S_OK && observed == animation);
    if (observed) IExpressionAnimation_Release(observed);
    check("self_assignment", IInteractionTrackerInertiaRestingValue_put_Condition(value, animation) == S_OK);
    IExpressionAnimation_Release(animation);
    animation = NULL;
    check("retained_expression", IInteractionTrackerInertiaRestingValue_get_RestingValue(value, &animation) == S_OK && animation);
    if (!animation) return 9;
    text = NULL;
    check("retained_text", IExpressionAnimation_get_Expression(animation, &text) == S_OK && text && !wcscmp(WindowsGetStringRawBuffer(text, NULL), L"42"));
    WindowsDeleteString(text);
    check("clear_condition", IInteractionTrackerInertiaRestingValue_put_Condition(value, NULL) == S_OK);
    check("cleared_condition", IInteractionTrackerInertiaRestingValue_get_Condition(value, &observed) == S_OK && !observed);
    legacy_conditional_value(compositor, animation);
    context = (struct writer_context){value, animation, CreateEventW(NULL, TRUE, FALSE, NULL)};
    if (!context.ready) return 10;
    for (i = 0; i < 2; ++i)
    {
        threads[i] = CreateThread(NULL, 0, writer, &context, 0, NULL);
        if (!threads[i]) return 11;
    }
    check("worker_ready", WaitForSingleObject(context.ready, 10000) == WAIT_OBJECT_0);
    check("close", IClosable_Close(closable) == S_OK);
    if (WaitForMultipleObjects(2, threads, TRUE, 10000) != WAIT_OBJECT_0) return 12;
    for (i = 0; i < 2; ++i)
    {
        DWORD exit_code;
        check("worker_exit", GetExitCodeThread(threads[i], &exit_code) && !exit_code);
    }
    for (i = 0; i < 2; ++i) CloseHandle(threads[i]);
    CloseHandle(context.ready);
    check("close_again", IClosable_Close(closable) == S_OK);
    observed = (void *)0xdeadbeef;
    check("closed_get", IInteractionTrackerInertiaRestingValue_get_RestingValue(value, &observed) == RO_E_CLOSED && !observed);
    check("closed_set", IInteractionTrackerInertiaRestingValue_put_Condition(value, animation) == RO_E_CLOSED);
    parent = (void *)0xdeadbeef;
    check("closed_compositor", ICompositionObject_get_Compositor(object, &parent) == RO_E_CLOSED && !parent);
    properties = (void *)0xdeadbeef;
    check("closed_properties", ICompositionObject_get_Properties(object, &properties) == RO_E_CLOSED && !properties);
    metadata((IInspectable *)value);
    IExpressionAnimation_Release(animation);
    IClosable_Release(closable);
    ICompositionObject_Release(object);
    IInteractionTrackerInertiaRestingValue_Release(value);
    ICompositor_Release(compositor);
    IInspectable_Release(compositor_object);
    IActivationFactory_Release(activation);
    IInteractionTrackerInertiaRestingValueStatics_Release(statics);
    RoUninitialize();
    printf("INERTIA_OBJECT_CHECKS:%ld failures:%ld\n", checks, failures);
    return failures != 0;
}
