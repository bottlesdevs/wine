#define WIN32_LEAN_AND_MEAN
#define XR_NO_PROTOTYPES

#include <windows.h>

#include <openxr/openxr.h>

#include <stdio.h>

static int check_result(const char *name, XrResult result)
{
    if (XR_SUCCEEDED(result)) return 1;

    fprintf(stderr, "%s failed: %d\n", name, result);
    return 0;
}

int main(void)
{
    PFN_xrCreateInstance create_instance;
    PFN_xrDestroyInstance destroy_instance;
    PFN_xrGetInstanceProcAddr get_instance_proc_addr;
    PFN_xrGetInstanceProperties get_instance_properties;
    PFN_xrGetSystem get_system;
    PFN_xrGetSystemProperties get_system_properties;
    XrInstanceCreateInfo create_info = {XR_TYPE_INSTANCE_CREATE_INFO};
    XrInstanceProperties instance_properties = {XR_TYPE_INSTANCE_PROPERTIES};
    XrSystemGetInfo system_info = {XR_TYPE_SYSTEM_GET_INFO};
    XrSystemProperties system_properties = {XR_TYPE_SYSTEM_PROPERTIES};
    XrInstance instance = XR_NULL_HANDLE;
    XrSystemId system = XR_NULL_SYSTEM_ID;
    HMODULE loader;

    loader = LoadLibraryA("openxr_loader.dll");
    if (!loader)
    {
        fprintf(stderr, "LoadLibraryA failed: %lu\n", GetLastError());
        return 1;
    }

    create_instance = (PFN_xrCreateInstance)GetProcAddress(loader, "xrCreateInstance");
    destroy_instance = (PFN_xrDestroyInstance)GetProcAddress(loader, "xrDestroyInstance");
    get_instance_proc_addr = (PFN_xrGetInstanceProcAddr)GetProcAddress(loader, "xrGetInstanceProcAddr");
    if (!create_instance || !destroy_instance || !get_instance_proc_addr)
    {
        fprintf(stderr, "OpenXR loader exports are missing\n");
        FreeLibrary(loader);
        return 1;
    }

    snprintf(create_info.applicationInfo.applicationName,
             XR_MAX_APPLICATION_NAME_SIZE, "Soda OpenXR CI");
    snprintf(create_info.applicationInfo.engineName,
             XR_MAX_ENGINE_NAME_SIZE, "Soda");
    create_info.applicationInfo.applicationVersion = 1;
    create_info.applicationInfo.engineVersion = 1;
    create_info.applicationInfo.apiVersion = XR_MAKE_VERSION(1, 0, 0);

    if (!check_result("xrCreateInstance", create_instance(&create_info, &instance))) goto failed;
    if (!check_result("xrGetInstanceProperties",
                      get_instance_proc_addr(instance, "xrGetInstanceProperties",
                                             (PFN_xrVoidFunction *)&get_instance_properties))) goto failed;
    if (!check_result("xrGetSystem",
                      get_instance_proc_addr(instance, "xrGetSystem",
                                             (PFN_xrVoidFunction *)&get_system))) goto failed;
    if (!check_result("xrGetSystemProperties",
                      get_instance_proc_addr(instance, "xrGetSystemProperties",
                                             (PFN_xrVoidFunction *)&get_system_properties))) goto failed;
    if (!check_result("xrGetInstanceProperties", get_instance_properties(instance, &instance_properties))) goto failed;

    system_info.formFactor = XR_FORM_FACTOR_HEAD_MOUNTED_DISPLAY;
    if (!check_result("xrGetSystem", get_system(instance, &system_info, &system))) goto failed;
    if (!check_result("xrGetSystemProperties",
                      get_system_properties(instance, system, &system_properties))) goto failed;

    printf("runtime=%s\nsystem=%s\nsystem_id=%llu\n",
           instance_properties.runtimeName, system_properties.systemName,
           (unsigned long long)system);
    destroy_instance(instance);
    FreeLibrary(loader);
    return 0;

failed:
    if (instance != XR_NULL_HANDLE) destroy_instance(instance);
    FreeLibrary(loader);
    return 1;
}
