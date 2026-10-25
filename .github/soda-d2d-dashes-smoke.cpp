#include <windows.h>
#include <d2d1_1.h>
#include <wincodec.h>
#include <stdio.h>
#include <math.h>

static float cap_clearance(float x, float y, float radius, D2D1_CAP_STYLE cap)
{
    if (cap == D2D1_CAP_STYLE_ROUND) return radius - hypotf(x, y);
    if (cap == D2D1_CAP_STYLE_SQUARE) return fminf(fminf(x, radius - x), radius - fabsf(y));
    if (cap == D2D1_CAP_STYLE_TRIANGLE) return fminf(x, radius - x - fabsf(y));
    return -1000.0f;
}

static float line_clearance(float x, float y, float length, float width,
        const float *dashes, unsigned int count, const D2D1_STROKE_STYLE_PROPERTIES &style)
{
    unsigned int n = count * (count % 2 ? 2 : 1);
    float period = 0, clearance = -1000.0f, radius = width * 0.5f;

    if (fabsf(y) > radius + 0.15f) return -1000.0f;
    for (unsigned int i = 0; i < n; ++i) period += dashes[i % count] * width;
    for (int cycle = -2; cycle <= (int)ceilf(length / period) + 2; ++cycle)
    {
        float start = cycle * period - style.dashOffset * width;
        for (unsigned int i = 0; i < n; ++i)
        {
            float end = start + dashes[i % count] * width;
            if (!(i & 1) && start <= length && end >= 0)
            {
                float a = fmaxf(0, start), b = fminf(length, end);
                if (a < b) clearance = fmaxf(clearance, fminf(fminf(x - a, b - x), radius - fabsf(y)));
                clearance = fmaxf(clearance, cap_clearance(a - x, y, radius,
                        a == 0 ? style.startCap : style.dashCap));
                clearance = fmaxf(clearance, cap_clearance(x - b, y, radius,
                        b == length ? style.endCap : style.dashCap));
            }
            start = end;
        }
    }
    return clearance;
}

static HRESULT save_image(IWICImagingFactory *imaging, IWICBitmap *bitmap, const char *filename)
{
    IWICStream *stream = NULL;
    IWICBitmapEncoder *encoder = NULL;
    IWICBitmapFrameEncode *frame = NULL;
    IPropertyBag2 *options = NULL;
    WICPixelFormatGUID format = GUID_WICPixelFormat32bppBGRA;
    WCHAR path[MAX_PATH];
    UINT width, height;
    HRESULT hr;

    if (!MultiByteToWideChar(CP_UTF8, 0, filename, -1, path, MAX_PATH)) return E_INVALIDARG;
    hr = bitmap->GetSize(&width, &height);
    if (SUCCEEDED(hr)) hr = imaging->CreateStream(&stream);
    if (SUCCEEDED(hr)) hr = stream->InitializeFromFilename(path, GENERIC_WRITE);
    if (SUCCEEDED(hr)) hr = imaging->CreateEncoder(GUID_ContainerFormatPng, NULL, &encoder);
    if (SUCCEEDED(hr)) hr = encoder->Initialize(stream, WICBitmapEncoderNoCache);
    if (SUCCEEDED(hr)) hr = encoder->CreateNewFrame(&frame, &options);
    if (SUCCEEDED(hr)) hr = frame->Initialize(options);
    if (SUCCEEDED(hr)) hr = frame->SetSize(width, height);
    if (SUCCEEDED(hr)) hr = frame->SetPixelFormat(&format);
    if (SUCCEEDED(hr)) hr = frame->WriteSource(bitmap, NULL);
    if (SUCCEEDED(hr)) hr = frame->Commit();
    if (SUCCEEDED(hr)) hr = encoder->Commit();
    if (options) options->Release();
    if (frame) frame->Release();
    if (encoder) encoder->Release();
    if (stream) stream->Release();
    return hr;
}

int main(int argc, char **argv)
{
    IWICImagingFactory *imaging = NULL;
    IWICBitmap *output = NULL;
    ID2D1Factory *factory = NULL;
    ID2D1RenderTarget *target = NULL;
    ID2D1SolidColorBrush *brush = NULL;
    ID2D1StrokeStyle *style = NULL;
    ID2D1DeviceContext *context = NULL;
    ID2D1CommandList *commands = NULL;
    ID2D1Image *saved = NULL;
    D2D1_RENDER_TARGET_PROPERTIES props = {};
    D2D1_COLOR_F white = {1, 1, 1, 1}, black = {0, 0, 0, 1};
    D2D1_STROKE_STYLE_PROPERTIES stroke = {};
    const float patterns[][6] = {{}, {2, 2}, {0, 2}, {2, 2, 0, 2},
            {2, 2, 0, 2, 0, 2}, {3, 1}};
    const unsigned int counts[] = {0, 2, 2, 4, 6, 2};
    WICRect area = {0, 0, 192, 256};
    DWORD pixels[192 * 256];
    unsigned int checks = 0, failures = 0;
    HRESULT hr;
    int result = 1;

#define CHECK(call) do { hr = (call); if (FAILED(hr)) { \
    printf("FAILED line=%d hr=%08lx\n", __LINE__, (unsigned long)hr); goto done; } } while (0)
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED));
    CHECK(CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
            IID_IWICImagingFactory, (void **)&imaging));
    CHECK(imaging->CreateBitmap(192, 256, GUID_WICPixelFormat32bppPBGRA,
            WICBitmapCacheOnLoad, &output));
    CHECK(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, IID_ID2D1Factory,
            NULL, (void **)&factory));
    CHECK(factory->CreateWicBitmapRenderTarget(output, &props, &target));
    CHECK(target->CreateSolidColorBrush(&black, NULL, &brush));
    CHECK(target->QueryInterface(IID_ID2D1DeviceContext, (void **)&context));
    target->SetAntialiasMode(D2D1_ANTIALIAS_MODE_ALIASED);
    target->BeginDraw();
    target->Clear(&white);
    for (unsigned int i = 0; i < 8; ++i)
    {
        unsigned int pattern = i < 6 ? i : 1;
        stroke.startCap = stroke.endCap = stroke.dashCap = D2D1_CAP_STYLE_FLAT;
        if (pattern == 2 || pattern == 3 || pattern == 4)
            stroke.startCap = stroke.endCap = stroke.dashCap = D2D1_CAP_STYLE_ROUND;
        stroke.lineJoin = D2D1_LINE_JOIN_MITER;
        stroke.miterLimit = 10;
        stroke.dashStyle = (D2D1_DASH_STYLE)pattern;
        stroke.dashOffset = i == 6 ? 1 : i == 7 ? -1 : 0;
        CHECK(factory->CreateStrokeStyle(&stroke, pattern == 5 ? patterns[5] : NULL,
                pattern == 5 ? counts[5] : 0, &style));
        ULONGLONG started = GetTickCount64();
        printf("DRAW_BEGIN case=%u\n", i);
        target->DrawLine(D2D1_POINT_2F{8, (float)(12 + i * 32)},
                D2D1_POINT_2F{184, (float)(12 + i * 32)}, brush, 4, style);
        printf("DRAW_END case=%u elapsed=%llu\n", i, GetTickCount64() - started);
        style->Release(); style = NULL;
    }
    CHECK(target->EndDraw(NULL, NULL));
    CHECK(output->CopyPixels(&area, 192 * 4, sizeof(pixels), (BYTE *)pixels));
    if (argc > 1) CHECK(save_image(imaging, output, argv[1]));
    for (unsigned int i = 0; i < 8; ++i)
    {
        unsigned int pattern = i < 6 ? i : 1, differences = 0;
        float offset = i == 6 ? 1 : i == 7 ? -1 : 0, period = 0;
        bool round = pattern == 2 || pattern == 3 || pattern == 4;
        for (unsigned int k = 0; k < counts[pattern]; ++k) period += patterns[pattern][k];
        for (unsigned int x = 12; x < 180; ++x)
        {
            bool inside = !pattern;
            float position = (x + 0.5f - 8) / 4 + offset;
            if (pattern)
            {
                position = fmodf(position, period);
                if (position < 0) position += period;
                float start = 0;
                for (unsigned int k = 0; k < counts[pattern]; ++k)
                {
                    float end = start + patterns[pattern][k];
                    if (!(k & 1))
                    {
                        if (position >= start && position < end) inside = true;
                        if (round)
                        {
                            for (int repeat = -1; repeat <= 1; ++repeat)
                            {
                                float p = position + repeat * period;
                                float distance = p < start ? start - p : p > end ? p - end : 0;
                                if (distance * distance + 0.125f * 0.125f < 0.25f) inside = true;
                            }
                        }
                    }
                    start = end;
                }
            }
            DWORD actual = pixels[(12 + i * 32) * 192 + x];
            ++checks;
            if (actual != (inside ? 0xff000000 : 0xffffffff)) ++differences;
        }
        failures += differences;
        printf("DASH_LINE case=%u differences=%u\n", i, differences);
    }
    for (unsigned int i = 0; i < 28; ++i)
    {
        const D2D1_MATRIX_3X2_F matrices[] = {{1, 0, 0, 1, 0, 0}, {0.75f, 0, 0, 1.25f, 7, 10},
                {0, 1, -1, 0, 84, 0}, {0.75f, 0.125f, 0.25f, 0.75f, 4, 30}};
        const float odd[] = {1, 2, 3}, zero_gaps[] = {3, 0, 0, 0};
        unsigned int pattern = i % 6, count = i >= 24 ? 4 : i >= 20 ? 3 : counts[pattern ? pattern : 1];
        const float *dashes = i >= 24 ? zero_gaps : i >= 20 ? odd : patterns[pattern ? pattern : 1];
        D2D1_MATRIX_3X2_F m = matrices[i % 4];
        float dpi = (i / 4) % 2 ? 144 : 96, width = i % 2 ? 4 : 2;
        bool pixel_units = (i / 8) % 2, recorded = i % 3 == 0;
        float scale = pixel_units ? 1 : dpi / 96;
        float determinant = m._11 * m._22 - m._12 * m._21;
        unsigned int differences = 0;

        stroke.startCap = (D2D1_CAP_STYLE)(i % 4);
        stroke.endCap = (D2D1_CAP_STYLE)((i + 1) % 4);
        stroke.dashCap = (D2D1_CAP_STYLE)((i / 4) % 4);
        stroke.dashStyle = D2D1_DASH_STYLE_CUSTOM;
        stroke.dashOffset = i % 3 == 0 ? -0.5f : i % 3 == 1 ? 0 : 1;
        CHECK(factory->CreateStrokeStyle(&stroke, dashes, count, &style));
        context->SetDpi(dpi, dpi);
        context->SetUnitMode(pixel_units ? D2D1_UNIT_MODE_PIXELS : D2D1_UNIT_MODE_DIPS);
        context->SetTransform(&m);
        brush->SetOpacity(i % 2 ? 0.5f : 1);
        if (recorded)
        {
            context->GetTarget(&saved);
            CHECK(context->CreateCommandList(&commands));
            context->SetTarget(commands);
        }
        context->BeginDraw();
        if (!recorded) context->Clear(&white);
        target->DrawLine(D2D1_POINT_2F{8, 12}, D2D1_POINT_2F{184, 12}, brush, width, style);
        CHECK(context->EndDraw());
        if (recorded)
        {
            CHECK(commands->Close());
            context->SetTarget(saved);
            saved->Release(); saved = NULL;
            D2D1_MATRIX_3X2_F identity = {1, 0, 0, 1, 0, 0};
            context->SetTransform(&identity);
            context->BeginDraw();
            context->Clear(&white);
            context->DrawImage(commands);
            CHECK(context->EndDraw());
        }
        CHECK(output->CopyPixels(&area, 192 * 4, sizeof(pixels), (BYTE *)pixels));
        for (unsigned int y = 0; y < 256; ++y)
        {
            for (unsigned int x = 0; x < 192; ++x)
            {
                float px = (x + 0.5f) / scale - m._31, py = (y + 0.5f) / scale - m._32;
                float lx = (px * m._22 - py * m._21) / determinant;
                float ly = (py * m._11 - px * m._12) / determinant;
                float clearance = line_clearance(lx - 8, ly - 12, 176, width, dashes, count, stroke);
                if (fabsf(clearance) < 0.15f) continue;
                unsigned int expected = clearance < 0 ? 255 : i % 2 ? 127 : 0;
                DWORD actual = pixels[y * 192 + x];
                ++checks;
                if (abs((int)(actual & 255) - (int)expected) > 1)
                {
                    if (differences++ < 3)
                        printf("MATRIX_PIXEL case=%u x=%u y=%u value=%08lx expected=%u clearance=%g\n",
                                i, x, y, actual, expected, clearance);
                }
            }
        }
        failures += differences;
        printf("DASH_MATRIX case=%u recorded=%u differences=%u\n", i, recorded, differences);
        style->Release(); style = NULL;
        if (commands) {commands->Release(); commands = NULL;}
    }
    for (unsigned int i = 0; i < 6; ++i)
    {
        const float dashes[] = {5, 2};
        D2D1_MATRIX_3X2_F identity = {1, 0, 0, 1, 0, 0};
        D2D1_RECT_F rect = {16, 40, 88, 88};
        D2D1_ROUNDED_RECT rounded = {rect, 12, 12};
        unsigned int differences = 0, ink = 0, gaps = 0;

        stroke.startCap = stroke.endCap = D2D1_CAP_STYLE_FLAT;
        stroke.dashCap = i < 3 ? D2D1_CAP_STYLE_FLAT : D2D1_CAP_STYLE_ROUND;
        stroke.lineJoin = D2D1_LINE_JOIN_MITER;
        stroke.dashStyle = D2D1_DASH_STYLE_CUSTOM;
        stroke.dashOffset = i % 3 == 0 ? 0 : i % 3 == 1 ? 1 : -0.5f;
        CHECK(factory->CreateStrokeStyle(&stroke, dashes, 2, &style));
        context->SetDpi(96, 96);
        context->SetUnitMode(D2D1_UNIT_MODE_DIPS);
        context->SetTransform(&identity);
        brush->SetOpacity(0.5f);
        target->BeginDraw();
        target->Clear(&white);
        if (i < 3) target->DrawRectangle(&rect, brush, 4, style);
        else target->DrawRoundedRectangle(&rounded, brush, 4, style);
        CHECK(target->EndDraw(NULL, NULL));
        CHECK(output->CopyPixels(&area, 192 * 4, sizeof(pixels), (BYTE *)pixels));
        for (unsigned int y = 0; y < 256; ++y)
        {
            for (unsigned int x = 0; x < 192; ++x)
            {
                DWORD value = pixels[y * 192 + x];
                if (x < 14 || x >= 90 || y < 38 || y >= 90)
                {
                    ++checks;
                    if (value != 0xffffffff) ++differences;
                }
                if (value != 0xffffffff && (value & 255) < 126) ++differences;
            }
        }
        if (i < 3)
        {
            for (unsigned int side = 0; side < 4; ++side)
            {
                unsigned int count = side % 2 ? 32 : 56;
                for (unsigned int k = 0; k < count; ++k)
                {
                    unsigned int x = side % 2 ? side == 1 ? 88 : 16 : 24 + k;
                    unsigned int y = side % 2 ? 48 + k : side == 0 ? 40 : 88;
                    float distance = side == 0 ? x + 0.5f - 16 : side == 1 ? 72 + y + 0.5f - 40
                            : side == 2 ? 120 + 88 - x - 0.5f : 192 + 88 - y - 0.5f;
                    float phase = fmodf(distance / 4 + stroke.dashOffset + 70, 7);
                    if (phase < 0.05f || fabsf(phase - 5) < 0.05f) continue;
                    DWORD value = pixels[y * 192 + x];
                    bool expected = phase < 5;
                    ++checks;
                    if (expected ? (value & 255) < 126 || (value & 255) > 129 : value != 0xffffffff)
                    {
                        if (differences++ < 3)
                            printf("CONTOUR_PIXEL case=%u side=%u x=%u y=%u phase=%g value=%08lx\n",
                                    i, side, x, y, phase, value);
                    }
                }
            }
        }
        else
        {
            ID2D1RoundedRectangleGeometry *geometry = NULL;
            ID2D1PathGeometry *flat = NULL;
            ID2D1GeometrySink *sink = NULL;
            D2D1_RECT_F bounds = {};
            HRESULT geometry_hr = factory->CreateRoundedRectangleGeometry(&rounded, &geometry);
            if (SUCCEEDED(geometry_hr)) geometry_hr = factory->CreatePathGeometry(&flat);
            if (SUCCEEDED(geometry_hr)) geometry_hr = flat->Open(&sink);
            if (SUCCEEDED(geometry_hr)) geometry_hr = geometry->Simplify(D2D1_GEOMETRY_SIMPLIFICATION_OPTION_LINES,
                    NULL, 0.25f, sink);
            if (SUCCEEDED(geometry_hr)) geometry_hr = sink->Close();
            if (SUCCEEDED(geometry_hr)) geometry_hr = flat->GetBounds(NULL, &bounds);
            ++checks;
            if (FAILED(geometry_hr) || fabsf(bounds.left - rect.left) > 0.01f
                    || fabsf(bounds.top - rect.top) > 0.01f || fabsf(bounds.right - rect.right) > 0.01f
                    || fabsf(bounds.bottom - rect.bottom) > 0.01f) ++differences;
            if (sink) sink->Release();
            if (flat) flat->Release();
            if (geometry) geometry->Release();
            for (unsigned int x = 32; x < 72; ++x)
            {
                if (pixels[40 * 192 + x] == 0xffffffff) ++gaps;
                else ++ink;
            }
            ++checks;
            if (!ink || !gaps) ++differences;
        }
        failures += differences;
        printf("DASH_CONTOUR case=%u ink=%u gaps=%u differences=%u\n", i, ink, gaps, differences);
        style->Release(); style = NULL;
    }
    for (unsigned int i = 0; i < 4; ++i)
    {
        float dashes[] = {i == 0 ? 1e-40f : i == 1 ? -1.0f : i == 2 ? NAN : 0.0f,
                i == 0 ? 1e-40f : i == 3 ? 0.0f : 2.0f};
        stroke.dashStyle = D2D1_DASH_STYLE_CUSTOM;
        stroke.dashCap = D2D1_CAP_STYLE_FLAT;
        HRESULT create = factory->CreateStrokeStyle(&stroke, dashes, 2, &style);
        HRESULT end = create;
        if (SUCCEEDED(create))
        {
            target->BeginDraw();
            target->DrawLine(D2D1_POINT_2F{8, 12}, D2D1_POINT_2F{184, 12}, brush, 4, style);
            end = target->EndDraw(NULL, NULL);
            style->Release(); style = NULL;
        }
        ++checks;
        if (i == 3 ? FAILED(end) : SUCCEEDED(end)) ++failures;
        printf("DASH_LIMIT case=%u create=%08lx end=%08lx\n", i, create, end);
    }
    result = failures ? 1 : 0;
done:
    if (saved) {context->SetTarget(saved); saved->Release();}
    if (commands) commands->Release();
    if (context) context->Release();
    if (style) style->Release();
    if (brush) brush->Release();
    if (target) target->Release();
    if (factory) factory->Release();
    if (output) output->Release();
    if (imaging) imaging->Release();
    CoUninitialize();
    printf("DASH_RESULT checks=%u failures=%u\n", checks, failures);
    return result;
}
