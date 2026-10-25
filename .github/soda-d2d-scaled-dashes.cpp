#include <windows.h>
#include <d2d1_1.h>
#include <wincodec.h>
#include <stdio.h>

int main(void)
{
    static const struct
    {
        float scale, dpi_x, dpi_y;
        D2D1_UNIT_MODE unit;
        bool mirror;
    }
    cases[] =
    {
        {1, 96, 96, D2D1_UNIT_MODE_DIPS, false},
        {9525, 96, 96, D2D1_UNIT_MODE_DIPS, false},
        {0.001f, 96, 96, D2D1_UNIT_MODE_DIPS, false},
        {9525, 144, 192, D2D1_UNIT_MODE_DIPS, false},
        {9525, 192, 144, D2D1_UNIT_MODE_DIPS, true},
        {9525, 144, 192, D2D1_UNIT_MODE_PIXELS, false},
        {9525, 192, 144, D2D1_UNIT_MODE_PIXELS, true},
        {1, 192, 144, D2D1_UNIT_MODE_DIPS, true},
        {0.001f, 144, 192, D2D1_UNIT_MODE_DIPS, true},
    };
    IWICImagingFactory *imaging = NULL;
    IWICBitmap *bitmap = NULL;
    ID2D1Factory *factory = NULL;
    ID2D1RenderTarget *target = NULL;
    ID2D1DeviceContext *context = NULL;
    ID2D1SolidColorBrush *brush = NULL;
    ID2D1StrokeStyle *style = NULL;
    ID2D1RoundedRectangleGeometry *geometry = NULL;
    D2D1_RENDER_TARGET_PROPERTIES properties = {};
    D2D1_STROKE_STYLE_PROPERTIES stroke = {};
    D2D1_COLOR_F white = {1, 1, 1, 1}, black = {0, 0, 0, 1};
    float dashes[] = {1, 2};
    DWORD pixels[320 * 240];
    WICRect area = {0, 0, 320, 240};
    unsigned int checks = 0, failures = 0;
    HRESULT hr;
    int result = 1;

#define CHECK(call) do { hr = (call); if (FAILED(hr)) { \
    printf("FAILED line=%d hr=%08lx\n", __LINE__, (unsigned long)hr); goto done; } } while (0)
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));
    CHECK(CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
            IID_IWICImagingFactory, (void **)&imaging));
    CHECK(imaging->CreateBitmap(320, 240, GUID_WICPixelFormat32bppPBGRA,
            WICBitmapCacheOnLoad, &bitmap));
    CHECK(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, IID_ID2D1Factory,
            NULL, (void **)&factory));
    CHECK(factory->CreateWicBitmapRenderTarget(bitmap, &properties, &target));
    CHECK(target->QueryInterface(IID_ID2D1DeviceContext, (void **)&context));
    CHECK(target->CreateSolidColorBrush(&black, NULL, &brush));
    target->SetAntialiasMode(D2D1_ANTIALIAS_MODE_ALIASED);
    stroke.lineJoin = D2D1_LINE_JOIN_ROUND;
    stroke.miterLimit = 10;
    stroke.dashStyle = D2D1_DASH_STYLE_CUSTOM;
    for (unsigned int i = 0; i < sizeof(cases) / sizeof(*cases); ++i)
    {
        float scale = cases[i].scale;
        float x = cases[i].unit == D2D1_UNIT_MODE_PIXELS ? 1 : cases[i].dpi_x / 96;
        float y = cases[i].unit == D2D1_UNIT_MODE_PIXELS ? 1 : cases[i].dpi_y / 96;
        D2D1_MATRIX_3X2_F transform = {1 / (scale * x), 0, 0, 1 / (scale * y), 0, 0};
        D2D1_ROUNDED_RECT rounded = {{16 * scale, 16 * scale, 304 * scale, 224 * scale},
                20 * scale, 20 * scale};
        if (cases[i].mirror)
        {
            transform._11 = -transform._11;
            transform._31 = 320 / x;
        }
        target->SetDpi(cases[i].dpi_x, cases[i].dpi_y);
        target->SetTransform(&transform);
        context->SetUnitMode(cases[i].unit);
        CHECK(factory->CreateRoundedRectangleGeometry(&rounded, &geometry));
        for (unsigned int cap = D2D1_CAP_STYLE_FLAT; cap <= D2D1_CAP_STYLE_TRIANGLE; ++cap)
        {
            unsigned int ink = 0, gaps = 0;
            ULONGLONG started;
            stroke.startCap = stroke.endCap = stroke.dashCap = (D2D1_CAP_STYLE)cap;
            CHECK(factory->CreateStrokeStyle(&stroke, dashes, 2, &style));
            target->BeginDraw();
            target->Clear(&white);
            started = GetTickCount64();
            target->DrawGeometry(geometry, brush, 4 * scale, style);
            hr = target->EndDraw(NULL, NULL);
            ++checks;
            if (FAILED(hr))
            {
                ++failures;
            }
            else
            {
                CHECK(bitmap->CopyPixels(&area, 320 * 4, sizeof(pixels), (BYTE *)pixels));
                for (unsigned int column = 60; column < 280; ++column)
                {
                    DWORD pixel = pixels[16 * 320 + column] & 0xffffff;
                    if (!pixel) ++ink;
                    if (pixel == 0xffffff) ++gaps;
                }
                ++checks;
                if (ink < 20 || gaps < 20) ++failures;
            }
            printf("SCALED_DASH case=%u cap=%u scale=%.9g dpi=%.9g,%.9g unit=%u mirror=%u "
                    "hr=%08lx ink=%u gaps=%u elapsed=%llu\n", i, cap, scale,
                    cases[i].dpi_x, cases[i].dpi_y, (unsigned int)cases[i].unit,
                    (unsigned int)cases[i].mirror, (unsigned long)hr, ink, gaps,
                    (unsigned long long)(GetTickCount64() - started));
            style->Release(); style = NULL;
        }
        geometry->Release(); geometry = NULL;
    }
    result = failures ? 1 : 0;
done:
    if (geometry) geometry->Release();
    if (style) style->Release();
    if (brush) brush->Release();
    if (context) context->Release();
    if (target) target->Release();
    if (factory) factory->Release();
    if (bitmap) bitmap->Release();
    if (imaging) imaging->Release();
    CoUninitialize();
    printf("SCALED_DASH_RESULT checks=%u failures=%u\n", checks, failures);
    return result;
}
