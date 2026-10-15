#define COBJMACROS
#define INITGUID
#include <windows.h>
#include <winternl.h>
#include <d3d11.h>
#include <dxgi.h>
#include <d2d1_1.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    ID3D11Device *d3d;
    IDXGIDevice *dxgi;
    ID2D1Factory1 *factory;
    ID2D1Device *device;
    ID2D1DeviceContext *context;
    ID2D1CommandList *commands;
    D2D1_TAG tag1, tag2;
    unsigned i;
    HRESULT hr;

    if (FAILED(D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            NULL, 0, D3D11_SDK_VERSION, &d3d, NULL, NULL))) return 1;
    if (FAILED(ID3D11Device_QueryInterface(d3d, &IID_IDXGIDevice, (void **)&dxgi))) return 2;
    if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &IID_ID2D1Factory1, NULL, (void **)&factory))) return 3;
    if (FAILED(ID2D1Factory1_CreateDevice(factory, dxgi, &device))) return 4;
    if (FAILED(ID2D1Device_CreateDeviceContext(device, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &context))) return 5;
    ID2D1DeviceContext_BeginDraw(context);
    ID2D1DeviceContext_SetTags(context, 0x123456789abcdef0ULL, 0xfedcba9876543210ULL);
    ID2D1DeviceContext_Clear(context, NULL);
    hr = ID2D1DeviceContext_Flush(context, &tag1, &tag2);
    if (hr != D2DERR_WRONG_STATE || tag1 != 0x123456789abcdef0ULL || tag2 != 0xfedcba9876543210ULL) return 6;
    if (ID2D1DeviceContext_EndDraw(context, NULL, NULL) != S_OK) return 7;
    ID2D1DeviceContext_BeginDraw(context);
    ID2D1DeviceContext_SetTags(context, 0xfedcba9876543210ULL, 0x123456789abcdef0ULL);
    ID2D1DeviceContext_Clear(context, NULL);
    if (ID2D1DeviceContext_EndDraw(context, NULL, NULL) != D2DERR_WRONG_STATE) return 8;
    if (FAILED(ID2D1DeviceContext_CreateCommandList(context, &commands))) return 9;
    ID2D1DeviceContext_SetTarget(context, (ID2D1Image *)commands);
    ID2D1DeviceContext_BeginDraw(context);
    NtCurrentTeb()->LastStatusValue = 0xc0000022;
    SetLastError(0x12345678);
    if (ID2D1DeviceContext_EndDraw(context, NULL, NULL) != S_OK) return 10;
    if (GetLastError() != 0x12345678) return 12;
    if (NtCurrentTeb()->LastStatusValue != 0xc0000022) return 13;
    if (argc > 1 && !strcmp(argv[1], "budget"))
    {
        for (i = 0; i < 4100; i++)
        {
            ID2D1DeviceContext_BeginDraw(context);
            if (ID2D1DeviceContext_EndDraw(context, NULL, NULL) != S_OK) return 11;
        }
    }
    ID2D1DeviceContext_SetTarget(context, NULL);
    ID2D1CommandList_Release(commands);
    ID2D1DeviceContext_Release(context);
    ID2D1Device_Release(device);
    ID2D1Factory1_Release(factory);
    IDXGIDevice_Release(dxgi);
    ID3D11Device_Release(d3d);
    puts("D2D_PROVIDER_OK");
    fflush(stdout);
    if (argc > 1 && !strcmp(argv[1], "hold")) Sleep(300000);
    return 0;
}
