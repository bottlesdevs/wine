#include <windows.h>
#include <d2d1_1.h>
#include <d2d1effects.h>
#include <wincodec.h>
#include <stdio.h>
#include <math.h>

int main(void)
{
    IWICImagingFactory *imaging = NULL;
    IWICBitmap *output = NULL;
    ID2D1Factory *factory = NULL;
    ID2D1RenderTarget *target = NULL;
    ID2D1DeviceContext *context = NULL;
    ID2D1Bitmap *bitmap = NULL;
    ID2D1CommandList *commands = NULL;
    ID2D1Image *saved = NULL;
    D2D1_RENDER_TARGET_PROPERTIES props = {};
    D2D1_BITMAP_PROPERTIES bitmap_props = {{DXGI_FORMAT_B8G8R8A8_UNORM,
            D2D1_ALPHA_MODE_PREMULTIPLIED}, 96, 96};
    D2D1_SIZE_U size = {12, 12};
    D2D1_COLOR_F white = {1, 1, 1, 1};
    const float dpis[] = {72, 96, 300};
    const DWORD colors[] = {0xffff0000, 0xff00ff00, 0xff0000ff, 0xff000000};
    WICRect row = {0, 0, 32, 32};
    DWORD source[144], pixels[1024];
    unsigned int i, x, failures = 0;
    HRESULT hr, end_hr;
    int result = 1;

#define CHECK(call) do { hr = (call); if (FAILED(hr)) { \
    printf("FAILED line=%d hr=%08lx\n", __LINE__, (unsigned long)hr); goto done; } } while (0)
    CHECK(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));
    CHECK(CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
            IID_IWICImagingFactory, (void **)&imaging));
    CHECK(imaging->CreateBitmap(32, 32, GUID_WICPixelFormat32bppPBGRA, WICBitmapCacheOnLoad, &output));
    CHECK(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, IID_ID2D1Factory, NULL, (void **)&factory));
    CHECK(factory->CreateWicBitmapRenderTarget(output, &props, &target));
    CHECK(target->QueryInterface(IID_ID2D1DeviceContext, (void **)&context));
    for (x = 0; x < 144; ++x) source[x] = colors[(x % 12 >= 6) + 2 * (x / 12 >= 6)];
    for (i = 0; i < 24; ++i)
    {
        bool pixel_units = i % 2, legacy = (i / 2) % 2, recorded = (i / 4) % 2;
        float dpi = dpis[i / 8], extent = pixel_units ? 12 : 12 * 96 / dpi;
        D2D1_RECT_F src = {0, 0, extent, extent}, dst = {0, 0, 24, 24};
        unsigned int differences = 0;
        bitmap_props.dpiX = bitmap_props.dpiY = dpi;
        CHECK(target->CreateBitmap(size, source, 48, &bitmap_props, &bitmap));
        context->SetUnitMode(pixel_units ? D2D1_UNIT_MODE_PIXELS : D2D1_UNIT_MODE_DIPS);
        if (recorded)
        {
            context->GetTarget(&saved);
            CHECK(context->CreateCommandList(&commands));
            context->SetTarget(commands);
        }
        context->BeginDraw();
        if (!recorded) context->Clear(&white);
        if (legacy)
            target->DrawBitmap(bitmap, &dst, 1.0f, D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR, &src);
        else
            context->DrawBitmap(bitmap, &dst, 1.0f, D2D1_INTERPOLATION_MODE_NEAREST_NEIGHBOR, &src, NULL);
        end_hr = context->EndDraw();
        if (FAILED(end_hr)) ++failures;
        if (recorded)
        {
            CHECK(commands->Close());
            context->SetTarget(saved);
            saved->Release(); saved = NULL;
            context->BeginDraw();
            context->Clear(&white);
            context->DrawImage(commands);
            end_hr = context->EndDraw();
            if (FAILED(end_hr)) ++failures;
        }
        CHECK(output->CopyPixels(&row, 128, sizeof(pixels), (BYTE *)pixels));
        for (x = 0; x < 1024; ++x)
        {
            unsigned int px = x % 32, py = x / 32;
            DWORD expected = px < 24 && py < 24 ? colors[(px >= 12) + 2 * (py >= 12)] : 0xffffffff;
            if (pixels[x] != expected) ++differences;
        }
        printf("BITMAP case=%u dpi=%g pixels=%u legacy=%u recorded=%u end=%08lx differences=%u\n",
                i, dpi, pixel_units, legacy, recorded, (unsigned long)end_hr, differences);
        failures += differences;
        if (commands) {commands->Release(); commands = NULL;}
        bitmap->Release(); bitmap = NULL;
    }
    for (i = 0; i < 12; ++i)
    {
        bool pixel_units = i % 2, legacy = (i / 2) % 2;
        float dpi = dpis[i / 4], extent = pixel_units ? 12 : 12 * 96 / dpi;
        D2D1_RECT_F bounds;

        bitmap_props.dpiX = bitmap_props.dpiY = dpi;
        CHECK(target->CreateBitmap(size, source, 48, &bitmap_props, &bitmap));
        context->SetUnitMode(pixel_units ? D2D1_UNIT_MODE_PIXELS : D2D1_UNIT_MODE_DIPS);
        context->GetTarget(&saved);
        CHECK(context->CreateCommandList(&commands));
        context->SetTarget(commands);
        context->BeginDraw();
        if (legacy)
            target->DrawBitmap(bitmap, NULL, 1.0f, D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR, NULL);
        else
            context->DrawBitmap(bitmap, NULL, 1.0f, D2D1_INTERPOLATION_MODE_NEAREST_NEIGHBOR, NULL, NULL);
        CHECK(context->EndDraw());
        CHECK(commands->Close());
        context->SetTarget(saved);
        saved->Release(); saved = NULL;
        CHECK(context->GetImageLocalBounds(commands, &bounds));
        if (fabsf(bounds.left) > 0.001f || fabsf(bounds.top) > 0.001f
                || fabsf(bounds.right - extent) > 0.001f || fabsf(bounds.bottom - extent) > 0.001f)
            ++failures;
        printf("DEFAULT case=%u dpi=%g pixels=%u legacy=%u bounds=%g,%g,%g,%g expected=%g\n",
                i, dpi, pixel_units, legacy, bounds.left, bounds.top, bounds.right, bounds.bottom, extent);
        commands->Release(); commands = NULL;
        bitmap->Release(); bitmap = NULL;
    }
    result = failures ? 1 : 0;
done:
    if (saved) {context->SetTarget(saved); saved->Release();}
    if (commands) commands->Release();
    if (bitmap) bitmap->Release();
    if (context) context->Release();
    if (target) target->Release();
    if (factory) factory->Release();
    if (output) output->Release();
    if (imaging) imaging->Release();
    CoUninitialize();
    printf("RESULT=%s failures=%u\n", result ? "FAIL" : "PASS", failures);
    return result;
}
