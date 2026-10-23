#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <stdio.h>

static int read_pixels(ID3D11Device *device, ID3D11DeviceContext *context,
        ID3D11Texture2D *texture)
{
    D3D11_TEXTURE2D_DESC desc;
    D3D11_MAPPED_SUBRESOURCE map;
    ID3D11Texture2D *staging;
    unsigned int x, y, differences = 0;
    const unsigned char *pixel;
    HRESULT hr;

    ID3D11Texture2D_GetDesc(texture, &desc);
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.MiscFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    hr = ID3D11Device_CreateTexture2D(device, &desc, NULL, &staging);
    if (FAILED(hr)) return 1;
    ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)staging, (ID3D11Resource *)texture);
    hr = ID3D11DeviceContext_Map(context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &map);
    printf("MAP=%08lx\n", (unsigned long)hr);
    if (SUCCEEDED(hr))
    {
        for (y = 0; y < desc.Height; ++y)
            for (x = 0; x < desc.Width; ++x)
            {
                pixel = (const unsigned char *)map.pData + y * map.RowPitch + x * 4;
                if (pixel[0] != 0 || pixel[1] != 255 || pixel[2] != 0 || pixel[3] != 255)
                    ++differences;
            }
        ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)staging, 0);
        printf("PIXEL_DIFFERENCES=%u\n", differences);
    }
    ID3D11Texture2D_Release(staging);
    return FAILED(hr) || differences;
}

int main(void)
{
    ID3D11Device *device = NULL, *other = NULL;
    ID3D11DeviceContext *context = NULL, *other_context = NULL;
    ID3D11Texture2D *texture = NULL, *opened = NULL;
    ID3D11RenderTargetView *view = NULL;
    IDXGIResource *resource = NULL;
    D3D11_TEXTURE2D_DESC desc = {0};
    const float green[4] = {0, 1, 0, 1};
    D3D_FEATURE_LEVEL level;
    HANDLE handle = NULL;
    HRESULT hr;
    int result = 1;

    setvbuf(stdout, NULL, _IONBF, 0);
    hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
            NULL, 0, D3D11_SDK_VERSION, &device, &level, &context);
    printf("DEVICE=%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) goto done;
    desc.Width = desc.Height = 8;
    desc.MipLevels = desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
    desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED;
    hr = ID3D11Device_CreateTexture2D(device, &desc, NULL, &texture);
    printf("TEXTURE=%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) goto done;
    hr = ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)texture, NULL, &view);
    if (FAILED(hr)) goto done;
    ID3D11DeviceContext_ClearRenderTargetView(context, view, green);
    ID3D11DeviceContext_Flush(context);
    if (read_pixels(device, context, texture)) goto done;
    hr = ID3D11Texture2D_QueryInterface(texture, &IID_IDXGIResource, (void **)&resource);
    if (FAILED(hr)) goto done;
    hr = IDXGIResource_GetSharedHandle(resource, &handle);
    printf("SHARED_HANDLE=%08lx present=%d\n", (unsigned long)hr, !!handle);
    if (FAILED(hr) || !handle) goto done;
    hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
            NULL, 0, D3D11_SDK_VERSION, &other, &level, &other_context);
    if (FAILED(hr)) goto done;
    hr = ID3D11Device_OpenSharedResource(other, handle, &IID_ID3D11Texture2D, (void **)&opened);
    printf("OPEN_SHARED=%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) goto done;
    result = read_pixels(other, other_context, opened);
done:
    if (opened) ID3D11Texture2D_Release(opened);
    if (other_context) ID3D11DeviceContext_Release(other_context);
    if (other) ID3D11Device_Release(other);
    if (resource) IDXGIResource_Release(resource);
    if (view) ID3D11RenderTargetView_Release(view);
    if (texture) ID3D11Texture2D_Release(texture);
    if (context) ID3D11DeviceContext_Release(context);
    if (device) ID3D11Device_Release(device);
    printf("RESULT=%s\n", result ? "FAIL" : "PASS");
    return result ? 1 : 0;
}
