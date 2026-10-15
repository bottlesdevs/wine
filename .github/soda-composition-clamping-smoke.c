#define COBJMACROS
#define INITGUID
#include <stdio.h>
#include "windows.h"
#include "winstring.h"
#include "roapi.h"
#include "objbase.h"
#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include "windows.foundation.h"
#define WIDL_using_Windows_Foundation_Numerics
#include "windows.foundation.numerics.h"
#define WIDL_using_Windows_UI
#include "windows.ui.h"
#define WIDL_using_Windows_UI_Composition
#include "windows.ui.composition.h"
#define WIDL_using_Windows_UI_Composition_Core
#include "windows.ui.composition.core.h"
#define WIDL_using_Windows_UI_Composition_Desktop
#include "windows.ui.composition.interop.h"
#define WIDL_using_Windows_UI_Composition_Interactions
#include "windows.ui.composition.interactions.h"

static void check(const char *name,HRESULT hr)
{
    if(FAILED(hr)){printf("FAIL %s %08lx\n",name,(unsigned long)hr);fflush(stdout);ExitProcess(2);}
}
static HSTRING string(const WCHAR *text)
{
    HSTRING value;check("string",WindowsCreateString(text,lstrlenW(text),&value));return value;
}

static int failures;
static void position(IInteractionTracker *tracker,const char *label,FLOAT x,FLOAT y,FLOAT z)
{
    struct Vector3 got;
    check("get position",IInteractionTracker_get_Position(tracker,&got));
    printf("%s GOT=%g,%g,%g EXPECT=%g,%g,%g\n",label,got.X,got.Y,got.Z,x,y,z);
    failures += got.X!=x || got.Y!=y || got.Z!=z;
}
int main(void)
{
    IInspectable *instance;
    ICompositorController *controller;
    ICompositor *compositor;
    IInteractionTrackerStatics *factory;
    IInteractionTracker *tracker;
    IInteractionTracker5 *tracker5;
    HSTRING name;
    INT32 request;
    FLOAT scale;
    check("initialize",RoInitialize(RO_INIT_MULTITHREADED));
    name=string(RuntimeClass_Windows_UI_Composition_Core_CompositorController);
    check("activate",RoActivateInstance(name,&instance));WindowsDeleteString(name);
    check("controller",IInspectable_QueryInterface(instance,&IID_ICompositorController,(void **)&controller));IInspectable_Release(instance);
    check("compositor",ICompositorController_get_Compositor(controller,&compositor));
    name=string(RuntimeClass_Windows_UI_Composition_Interactions_InteractionTracker);
    check("factory",RoGetActivationFactory(name,&IID_IInteractionTrackerStatics,(void **)&factory));WindowsDeleteString(name);
    check("tracker",IInteractionTrackerStatics_Create(factory,compositor,&tracker));
    check("tracker5",IInteractionTracker_QueryInterface(tracker,&IID_IInteractionTracker5,(void **)&tracker5));
    check("min",IInteractionTracker_put_MinPosition(tracker,((struct Vector3){-10,-20,-30})));
    check("max",IInteractionTracker_put_MaxPosition(tracker,((struct Vector3){10,20,30})));
    check("auto",IInteractionTracker5_TryUpdatePositionWithOption(tracker5,((struct Vector3){-20,200,25}),InteractionTrackerClampingOption_Auto,InteractionTrackerPositionUpdateOption_Default,&request));
    position(tracker,"AUTO",-10,20,25);
    check("disabled",IInteractionTracker5_TryUpdatePositionWithOption(tracker5,((struct Vector3){-20,200,25}),InteractionTrackerClampingOption_Disabled,InteractionTrackerPositionUpdateOption_Default,&request));
    position(tracker,"DISABLED",-20,200,25);
    check("default",IInteractionTracker_TryUpdatePosition(tracker,((struct Vector3){-20,200,25}),&request));
    position(tracker,"DEFAULT",-10,20,25);
    check("relative",IInteractionTracker_TryUpdatePositionBy(tracker,((struct Vector3){100,-100,100}),&request));
    position(tracker,"RELATIVE",10,-20,30);
    check("min scale",IInteractionTracker_put_MinScale(tracker,0.5f));
    check("max scale",IInteractionTracker_put_MaxScale(tracker,2.0f));
    check("scale",IInteractionTracker_TryUpdateScale(tracker,4.0f,((struct Vector3){0}),&request));
    check("scale read",IInteractionTracker_get_Scale(tracker,&scale));
    printf("SCALE GOT=%g EXPECT=2\n",scale);failures+=scale!=2.0f;
    {
        ICompositionObject *object;
        IExpressionAnimation *expression;
        ICompositionAnimation *animation;
        HRESULT hr;
        INT32 unchanged=12345;
        check("tracker object",IInteractionTracker_QueryInterface(tracker,&IID_ICompositionObject,(void **)&object));
        check("expression",ICompositor_CreateExpressionAnimation(compositor,&expression));
        name=string(L"5");check("expression text",IExpressionAnimation_put_Expression(expression,name));WindowsDeleteString(name);
        check("animation",IExpressionAnimation_QueryInterface(expression,&IID_ICompositionAnimation,(void **)&animation));
        name=string(L"MaxPosition.X");check("start bounds",ICompositionObject_StartAnimation(object,name,animation));WindowsDeleteString(name);
        check("expression disabled",IInteractionTracker5_TryUpdatePositionWithOption(tracker5,((struct Vector3){50,0,0}),InteractionTrackerClampingOption_Disabled,InteractionTrackerPositionUpdateOption_Default,&request));
        position(tracker,"EXPRESSION_DISABLED",50,0,0);
        check("expression auto",IInteractionTracker5_TryUpdatePositionWithOption(tracker5,((struct Vector3){50,0,0}),InteractionTrackerClampingOption_Auto,InteractionTrackerPositionUpdateOption_Default,&request));
        position(tracker,"EXPRESSION_AUTO",5,0,0);
        hr=IInteractionTracker5_TryUpdatePositionWithOption(tracker5,((struct Vector3){0}),99,InteractionTrackerPositionUpdateOption_Default,&unchanged);
        printf("INVALID_CLAMP HR=%08lx REQUEST=%d\n",(unsigned long)hr,unchanged);
        failures+=hr!=E_INVALIDARG || unchanged!=12345;
        hr=IInteractionTracker5_TryUpdatePositionWithOption(tracker5,((struct Vector3){0}),InteractionTrackerClampingOption_Auto,99,&unchanged);
        printf("INVALID_UPDATE HR=%08lx REQUEST=%d\n",(unsigned long)hr,unchanged);
        failures+=hr!=E_INVALIDARG || unchanged!=12345;
        position(tracker,"INVALID_UNCHANGED",5,0,0);
        name=string(L"MaxPosition.X");check("stop bounds",ICompositionObject_StopAnimation(object,name));WindowsDeleteString(name);
        ICompositionAnimation_Release(animation);IExpressionAnimation_Release(expression);ICompositionObject_Release(object);
    }
    IInteractionTracker5_Release(tracker5);IInteractionTracker_Release(tracker);
    IInteractionTrackerStatics_Release(factory);ICompositor_Release(compositor);ICompositorController_Release(controller);RoUninitialize();
    printf("CLAMP_FAILURES=%d\n",failures);return failures?10:0;
}
