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
    ID2D1Brush *brush = NULL;
    ID2D1RectangleGeometry *geometry = NULL;
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
    for (i = 0; i < 48; ++i)
    {
        bool pixel_units = i % 2, geometry_fill = (i / 2) % 2, recorded = (i / 4) % 2;
        bool image_brush = i >= 24;
        float dpi = dpis[(i % 24) / 8];
        D2D1_RECT_F rect = {0, 0, 12, 12};
        D2D1_MATRIX_3X2_F transform = {2, 0, 0, 2, 0, 0};
        D2D1_BITMAP_BRUSH_PROPERTIES brush_props = {D2D1_EXTEND_MODE_CLAMP,
                D2D1_EXTEND_MODE_CLAMP, D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR};
        unsigned int pixel_differences = 0, dip_differences = 0;
        bitmap_props.dpiX = bitmap_props.dpiY = dpi;
        CHECK(target->CreateBitmap(size, source, 48, &bitmap_props, &bitmap));
        if (image_brush)
        {
            ID2D1ImageBrush *image;
            float extent = pixel_units ? 12 : 12 * 96 / dpi;
            D2D1_IMAGE_BRUSH_PROPERTIES image_props = {{0, 0, extent, extent},
                    D2D1_EXTEND_MODE_CLAMP, D2D1_EXTEND_MODE_CLAMP, D2D1_INTERPOLATION_MODE_NEAREST_NEIGHBOR};

            CHECK(context->CreateImageBrush(bitmap, &image_props, NULL, &image));
            brush = image;
        }
        else
        {
            ID2D1BitmapBrush *bitmap_brush;

            CHECK(target->CreateBitmapBrush(bitmap, &brush_props, NULL, &bitmap_brush));
            brush = bitmap_brush;
        }
        CHECK(factory->CreateRectangleGeometry(&rect, &geometry));
        context->SetUnitMode(pixel_units ? D2D1_UNIT_MODE_PIXELS : D2D1_UNIT_MODE_DIPS);
        if (recorded)
        {
            context->GetTarget(&saved);
            CHECK(context->CreateCommandList(&commands));
            context->SetTarget(commands);
        }
        context->BeginDraw();
        if (!recorded) context->Clear(&white);
        context->SetTransform(&transform);
        if (geometry_fill)
            context->FillGeometry(geometry, brush);
        else
            context->FillRectangle(&rect, brush);
        end_hr = context->EndDraw();
        if (FAILED(end_hr)) ++failures;
        if (recorded)
        {
            CHECK(commands->Close());
            context->SetTarget(saved);
            saved->Release(); saved = NULL;
            context->BeginDraw();
            context->Clear(&white);
            D2D1_MATRIX_3X2_F identity = {1, 0, 0, 1, 0, 0};
            context->SetTransform(&identity);
            context->DrawImage(commands);
            end_hr = context->EndDraw();
            if (FAILED(end_hr)) ++failures;
        }
        CHECK(output->CopyPixels(&row, 128, sizeof(pixels), (BYTE *)pixels));
        for (x = 0; x < 1024; ++x)
        {
            unsigned int px = x % 32, py = x / 32;
            DWORD pixel_expected = px < 24 && py < 24 ? colors[(px >= 12) + 2 * (py >= 12)] : 0xffffffff;
            DWORD dip_expected = px < 24 && py < 24
                    ? colors[((px + 0.5f) * dpi / 192 >= 6) + 2 * ((py + 0.5f) * dpi / 192 >= 6)]
                    : 0xffffffff;
            if (pixels[x] != pixel_expected) ++pixel_differences;
            if (pixels[x] != dip_expected) ++dip_differences;
        }
        printf("BRUSH case=%u dpi=%g pixels=%u geometry=%u recorded=%u image=%u end=%08lx pixel_diff=%u dip_diff=%u\n",
                i, dpi, pixel_units, geometry_fill, recorded, image_brush, (unsigned long)end_hr,
                pixel_differences, dip_differences);
        failures += pixel_units ? pixel_differences : dip_differences;
        geometry->Release(); geometry = NULL;
        brush->Release(); brush = NULL;
        if (commands) {commands->Release(); commands = NULL;}
        bitmap->Release(); bitmap = NULL;
    }
    result = failures ? 1 : 0;
done:
    if (saved) {context->SetTarget(saved); saved->Release();}
    if (commands) commands->Release();
    if (geometry) geometry->Release();
    if (brush) brush->Release();
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
