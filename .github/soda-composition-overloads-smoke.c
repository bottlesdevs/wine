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
    IInteractionTracker4 *tracker4;
    IInteractionTracker5 *tracker5;
    IUnknown *identity,*other;
    HSTRING name;
    IID *iids;
    ULONG count,i;
    HRESULT hr;
    INT32 request,previous,unchanged=12345;
    boolean impulse=TRUE;
    BOOL found=FALSE;
    check("initialize",RoInitialize(RO_INIT_MULTITHREADED));
    name=string(RuntimeClass_Windows_UI_Composition_Core_CompositorController);
    check("activate",RoActivateInstance(name,&instance));WindowsDeleteString(name);
    check("controller",IInspectable_QueryInterface(instance,&IID_ICompositorController,(void **)&controller));IInspectable_Release(instance);
    check("compositor",ICompositorController_get_Compositor(controller,&compositor));
    name=string(RuntimeClass_Windows_UI_Composition_Interactions_InteractionTracker);
    check("factory",RoGetActivationFactory(name,&IID_IInteractionTrackerStatics,(void **)&factory));WindowsDeleteString(name);
    check("tracker",IInteractionTrackerStatics_Create(factory,compositor,&tracker));
    check("tracker4",IInteractionTracker_QueryInterface(tracker,&IID_IInteractionTracker4,(void **)&tracker4));
    check("tracker5",IInteractionTracker4_QueryInterface(tracker4,&IID_IInteractionTracker5,(void **)&tracker5));
    check("identity",IInteractionTracker_QueryInterface(tracker,&IID_IUnknown,(void **)&identity));
    check("identity4",IInteractionTracker4_QueryInterface(tracker4,&IID_IUnknown,(void **)&other));
    failures+=identity!=other;IUnknown_Release(other);
    check("identity5",IInteractionTracker5_QueryInterface(tracker5,&IID_IUnknown,(void **)&other));
    failures+=identity!=other;IUnknown_Release(other);IUnknown_Release(identity);
    check("iids",IInteractionTracker4_GetIids(tracker4,&count,&iids));
    for(i=0;i<count;++i)if(IsEqualGUID(&iids[i],&IID_IInteractionTracker4))found=TRUE;
    failures+=!found;CoTaskMemFree(iids);
    check("name4",IInteractionTracker4_GetRuntimeClassName(tracker4,&name));
    failures+=wcscmp(WindowsGetStringRawBuffer(name,NULL),RuntimeClass_Windows_UI_Composition_Interactions_InteractionTracker)!=0;WindowsDeleteString(name);
    check("min",IInteractionTracker_put_MinPosition(tracker,((struct Vector3){-10,-20,-30})));
    check("max",IInteractionTracker_put_MaxPosition(tracker,((struct Vector3){10,20,30})));
    check("absolute auto",IInteractionTracker4_TryUpdatePositionWithOption(tracker4,((struct Vector3){100,-100,50}),InteractionTrackerClampingOption_Auto,&request));
    position(tracker,"ABSOLUTE_AUTO",10,-20,30);failures+=request!=1;previous=request;
    check("relative disabled",IInteractionTracker4_TryUpdatePositionByWithOption(tracker4,((struct Vector3){100,200,300}),InteractionTrackerClampingOption_Disabled,&request));
    position(tracker,"RELATIVE_DISABLED",110,180,330);failures+=request!=previous+1;previous=request;
    check("relative auto",IInteractionTracker4_TryUpdatePositionByWithOption(tracker4,((struct Vector3){0}),InteractionTrackerClampingOption_Auto,&request));
    position(tracker,"RELATIVE_AUTO",10,20,30);failures+=request!=previous+1;previous=request;
    check("shared5",IInteractionTracker5_TryUpdatePositionWithOption(tracker5,((struct Vector3){1,2,3}),InteractionTrackerClampingOption_Auto,InteractionTrackerPositionUpdateOption_Default,&request));
    position(tracker,"SHARED5",1,2,3);failures+=request!=previous+1;previous=request;
    check("absolute disabled",IInteractionTracker4_TryUpdatePositionWithOption(tracker4,((struct Vector3){50,60,70}),InteractionTrackerClampingOption_Disabled,&request));
    position(tracker,"ABSOLUTE_DISABLED",50,60,70);failures+=request!=previous+1;
    hr=IInteractionTracker4_TryUpdatePositionWithOption(tracker4,((struct Vector3){0}),99,&unchanged);failures+=hr!=E_INVALIDARG||unchanged!=12345;
    hr=IInteractionTracker4_TryUpdatePositionByWithOption(tracker4,((struct Vector3){0}),99,&unchanged);failures+=hr!=E_INVALIDARG||unchanged!=12345;
    hr=IInteractionTracker4_TryUpdatePositionByWithOption(tracker4,((struct Vector3){0}),InteractionTrackerClampingOption_Auto,NULL);failures+=hr!=E_POINTER;
    hr=IInteractionTracker4_TryUpdatePositionWithOption(tracker4,((struct Vector3){0}),InteractionTrackerClampingOption_Auto,NULL);failures+=hr!=E_POINTER;
    position(tracker,"INVALID_UNCHANGED",50,60,70);
    check("idle impulse",IInteractionTracker4_get_IsInertiaFromImpulse(tracker4,&impulse));failures+=impulse!=FALSE;
    hr=IInteractionTracker4_get_IsInertiaFromImpulse(tracker4,NULL);failures+=hr!=E_POINTER;
    IInteractionTracker4_Release(tracker4);IInteractionTracker5_Release(tracker5);IInteractionTracker_Release(tracker);
    IInteractionTrackerStatics_Release(factory);ICompositor_Release(compositor);ICompositorController_Release(controller);RoUninitialize();
    printf("OVERLOAD_FAILURES=%d\n",failures);return failures?10:0;
}
