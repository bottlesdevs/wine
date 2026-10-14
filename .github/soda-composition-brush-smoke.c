#define COBJMACROS
#define INITGUID
#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#define WIDL_using_Windows_Foundation
#include "windows.foundation.h"
#define WIDL_using_Windows_UI
#include "windows.ui.h"
#define WIDL_using_Windows_UI_Composition
#include "windows.ui.composition.h"

#include <stdio.h>

static unsigned int checks, failures;

static void check_hr(const char *label, HRESULT result, HRESULT expected)
{
    ++checks;
    if (result == expected) return;
    ++failures;
    printf("%s:%08lx expected:%08lx\n", label, (unsigned long)result, (unsigned long)expected);
}

static void check_value(const char *label, BOOL value)
{
    ++checks;
    if (value) return;
    ++failures;
    printf("%s:failed\n", label);
}

static void check_metadata(IInspectable *object, const WCHAR *expected)
{
    IUnknown *view = NULL;
    HSTRING name = NULL;
    IID *iids = NULL;
    ULONG count = 0, i;
    BOOL closable = FALSE;

    check_hr("closed_name", IInspectable_GetRuntimeClassName(object, &name), S_OK);
    check_value("closed_class", name && !wcscmp(WindowsGetStringRawBuffer(name, NULL), expected));
    WindowsDeleteString(name);
    check_hr("closed_iids", IInspectable_GetIids(object, &count, &iids), S_OK);
    check_value("closed_interfaces", count && iids);
    if (iids) for (i = 0; i < count; ++i)
    {
        if (IsEqualGUID(&iids[i], &IID_IClosable)) closable = TRUE;
        view = NULL;
        check_hr("closed_query", IInspectable_QueryInterface(object, &iids[i], (void **)&view), S_OK);
        check_value("closed_query_output", view != NULL);
        if (view) IUnknown_Release(view);
    }
    check_value("closed_closable", closable);
    CoTaskMemFree(iids);
}

static void check_surface_brush(ICompositor *compositor, BOOL with_surface)
{
    ICompositionSurfaceBrush *brush = NULL;
    ICompositionSurface *surface = NULL;
    ICompositionObject *object = NULL;
    ICompositor *parent = NULL;
    IClosable *closable = NULL;
    FLOAT alignment = 0;
    HRESULT hr;

    hr = with_surface ? ICompositor_CreateSurfaceBrushWithSurface(compositor, NULL, &brush)
            : ICompositor_CreateSurfaceBrush(compositor, &brush);
    check_hr("surface_factory", hr, S_OK);
    check_value("surface_factory_output", brush != NULL);
    if (!brush) return;
    check_hr("surface_object", ICompositionSurfaceBrush_QueryInterface(brush,
            &IID_ICompositionObject, (void **)&object), S_OK);
    check_value("surface_object_output", object != NULL);
    check_hr("surface_closable", ICompositionSurfaceBrush_QueryInterface(brush,
            &IID_IClosable, (void **)&closable), S_OK);
    check_value("surface_closable_output", closable != NULL);
    check_hr("surface_alignment_set", ICompositionSurfaceBrush_put_HorizontalAlignmentRatio(brush, 0.25f), S_OK);
    check_hr("surface_alignment_get", ICompositionSurfaceBrush_get_HorizontalAlignmentRatio(brush, &alignment), S_OK);
    check_value("surface_alignment", alignment == 0.25f);
    if (object)
    {
        check_hr("surface_parent", ICompositionObject_get_Compositor(object, &parent), S_OK);
        check_value("surface_parent_identity", parent == compositor);
        if (parent) ICompositor_Release(parent);
    }
    if (closable)
    {
        check_hr("surface_close", IClosable_Close(closable), S_OK);
        check_hr("surface_close_again", IClosable_Close(closable), S_OK);
        check_hr("surface_closed_get", ICompositionSurfaceBrush_get_Surface(brush, &surface), RO_E_CLOSED);
        check_value("surface_closed_output", surface == NULL);
        if (surface) ICompositionSurface_Release(surface);
        check_hr("surface_closed_put", ICompositionSurfaceBrush_put_Surface(brush, NULL), RO_E_CLOSED);
        check_hr("surface_closed_alignment", ICompositionSurfaceBrush_get_HorizontalAlignmentRatio(brush, &alignment), RO_E_CLOSED);
        if (object)
        {
            parent = NULL;
            check_hr("surface_closed_parent", ICompositionObject_get_Compositor(object, &parent), RO_E_CLOSED);
            check_value("surface_closed_parent_output", parent == NULL);
            if (parent) ICompositor_Release(parent);
        }
        check_metadata((IInspectable *)brush, L"Windows.UI.Composition.CompositionSurfaceBrush");
        IClosable_Release(closable);
    }
    if (object) ICompositionObject_Release(object);
    ICompositionSurfaceBrush_Release(brush);
}

static void check_color_brush(ICompositor *compositor)
{
    ICompositionColorBrush *brush = NULL;
    IClosable *closable = NULL;
    struct Color color = {0};

    check_hr("color_factory", ICompositor_CreateColorBrush(compositor, &brush), S_OK);
    check_value("color_factory_output", brush != NULL);
    if (!brush) return;
    check_hr("color_closable", ICompositionColorBrush_QueryInterface(brush,
            &IID_IClosable, (void **)&closable), S_OK);
    check_value("color_closable_output", closable != NULL);
    if (closable)
    {
        check_hr("color_close", IClosable_Close(closable), S_OK);
        check_hr("color_close_again", IClosable_Close(closable), S_OK);
        check_hr("color_closed_get", ICompositionColorBrush_get_Color(brush, &color), RO_E_CLOSED);
        check_hr("color_closed_put", ICompositionColorBrush_put_Color(brush, color), RO_E_CLOSED);
        check_metadata((IInspectable *)brush, L"Windows.UI.Composition.CompositionColorBrush");
        IClosable_Release(closable);
    }
    ICompositionColorBrush_Release(brush);
}

int main(void)
{
    const WCHAR class_name[] = L"Windows.UI.Composition.Compositor";
    IInspectable *instance = NULL;
    ICompositor *compositor = NULL;
    HSTRING name = NULL;
    HRESULT hr;

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr)) return 1;
    check_hr("compositor_name", WindowsCreateString(class_name, ARRAYSIZE(class_name) - 1, &name), S_OK);
    check_hr("compositor_activate", RoActivateInstance(name, &instance), S_OK);
    check_value("compositor_activate_output", instance != NULL);
    WindowsDeleteString(name);
    if (instance)
    {
        check_hr("compositor_interface", IInspectable_QueryInterface(instance,
                &IID_ICompositor, (void **)&compositor), S_OK);
        check_value("compositor_interface_output", compositor != NULL);
        IInspectable_Release(instance);
    }
    if (compositor)
    {
        check_surface_brush(compositor, FALSE);
        check_surface_brush(compositor, TRUE);
        check_color_brush(compositor);
        ICompositor_Release(compositor);
    }
    RoUninitialize();
    printf("composition_brush_checks:%u failures:%u\n", checks, failures);
    return failures != 0;
}
