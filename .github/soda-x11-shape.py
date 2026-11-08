import argparse
import ctypes as C
import json
import time


class Rectangle(C.Structure):
    _fields_ = [('x', C.c_short), ('y', C.c_short),
                ('width', C.c_ushort), ('height', C.c_ushort)]


x11 = C.CDLL('libX11.so.6')
xext = C.CDLL('libXext.so.6')
x11.XOpenDisplay.argtypes = [C.c_char_p]
x11.XOpenDisplay.restype = C.c_void_p
x11.XDefaultRootWindow.argtypes = [C.c_void_p]
x11.XDefaultRootWindow.restype = C.c_ulong
x11.XQueryTree.argtypes = [C.c_void_p, C.c_ulong, C.POINTER(C.c_ulong),
                          C.POINTER(C.c_ulong), C.POINTER(C.POINTER(C.c_ulong)), C.POINTER(C.c_uint)]
x11.XFetchName.argtypes = [C.c_void_p, C.c_ulong, C.POINTER(C.c_void_p)]
x11.XFree.argtypes = [C.c_void_p]
x11.XCloseDisplay.argtypes = [C.c_void_p]
x11.XMoveWindow.argtypes = [C.c_void_p, C.c_ulong, C.c_int, C.c_int]
x11.XReparentWindow.argtypes = [C.c_void_p, C.c_ulong, C.c_ulong, C.c_int, C.c_int]
x11.XSync.argtypes = [C.c_void_p, C.c_int]
x11.XTranslateCoordinates.argtypes = [C.c_void_p, C.c_ulong, C.c_ulong, C.c_int, C.c_int,
                                      C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(C.c_ulong)]
x11.XGetImage.argtypes = [C.c_void_p, C.c_ulong, C.c_int, C.c_int, C.c_uint, C.c_uint, C.c_ulong, C.c_int]
x11.XGetImage.restype = C.c_void_p
x11.XGetPixel.argtypes = [C.c_void_p, C.c_int, C.c_int]
x11.XGetPixel.restype = C.c_ulong
x11.XDestroyImage.argtypes = [C.c_void_p]
x11.XGetGeometry.argtypes = [C.c_void_p, C.c_ulong, C.POINTER(C.c_ulong),
                            C.POINTER(C.c_int), C.POINTER(C.c_int), C.POINTER(C.c_uint),
                            C.POINTER(C.c_uint), C.POINTER(C.c_uint), C.POINTER(C.c_uint)]
xext.XShapeQueryExtension.argtypes = [C.c_void_p, C.POINTER(C.c_int), C.POINTER(C.c_int)]
xext.XShapeGetRectangles.argtypes = [C.c_void_p, C.c_ulong, C.c_int,
                                   C.POINTER(C.c_int), C.POINTER(C.c_int)]
xext.XShapeGetRectangles.restype = C.POINTER(Rectangle)


def children(display, window):
    root, parent, count = C.c_ulong(), C.c_ulong(), C.c_uint()
    items = C.POINTER(C.c_ulong)()
    if not x11.XQueryTree(display, window, C.byref(root), C.byref(parent), C.byref(items), C.byref(count)):
        raise RuntimeError('XQueryTree failed')
    result = list(items[:count.value]) if count.value else []
    if items:
        x11.XFree(items)
    return result


def title(display, window):
    value = C.c_void_p()
    if not x11.XFetchName(display, window, C.byref(value)) or not value:
        return ''
    result = C.string_at(value).decode('utf-8', errors='replace')
    x11.XFree(value)
    return result


def find(display, window, name, depth=0):
    if title(display, window) == name:
        return window
    if depth >= 8:
        return None
    for child in children(display, window):
        if result := find(display, child, name, depth + 1):
            return result
    return None


def describe(display, window, depth=0):
    root, x, y = C.c_ulong(), C.c_int(), C.c_int()
    width, height, border, planes = C.c_uint(), C.c_uint(), C.c_uint(), C.c_uint()
    if not x11.XGetGeometry(display, window, C.byref(root), C.byref(x), C.byref(y),
                           C.byref(width), C.byref(height), C.byref(border), C.byref(planes)):
        raise RuntimeError('XGetGeometry failed')
    count, order = C.c_int(), C.c_int()
    rectangles = xext.XShapeGetRectangles(display, window, 0, C.byref(count), C.byref(order))
    shape = [[r.x, r.y, r.width, r.height] for r in rectangles[:count.value]] if count.value else []
    if rectangles:
        x11.XFree(rectangles)
    return {'window': hex(window), 'title': title(display, window),
            'geometry': [x.value, y.value, width.value, height.value], 'depth': planes.value,
            'bounding_rectangles': shape,
            'children': [describe(display, child, depth + 1) for child in children(display, window)] if depth < 4 else []}


def translate(display, window, root, x, y):
    dst_x, dst_y, child = C.c_int(), C.c_int(), C.c_ulong()
    if not x11.XTranslateCoordinates(display, window, root, x, y,
                                     C.byref(dst_x), C.byref(dst_y), C.byref(child)):
        raise RuntimeError('XTranslateCoordinates failed')
    return dst_x.value, dst_y.value


def pixel(display, root, point):
    image = x11.XGetImage(display, root, *point, 1, 1, C.c_ulong(-1).value, 2)
    if not image:
        raise RuntimeError('XGetImage failed')
    value = x11.XGetPixel(image, 0, 0)
    x11.XDestroyImage(image)
    return hex(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('title')
    parser.add_argument('--placement', choices=['move', 'reparent'])
    parser.add_argument('--sample', nargs=2, type=int, default=[16, 16])
    args = parser.parse_args()
    display = x11.XOpenDisplay(None)
    if not display:
        raise RuntimeError('XOpenDisplay failed')
    try:
        event, error = C.c_int(), C.c_int()
        if not xext.XShapeQueryExtension(display, C.byref(event), C.byref(error)):
            raise RuntimeError('XShape extension unavailable')
        root = x11.XDefaultRootWindow(display)
        window = find(display, root, args.title)
        if window is None:
            raise RuntimeError('fixture window not found')
        result = {'fixture': describe(display, window),
                  'root_windows': [describe(display, child, 4) for child in children(display, root)]}
        if args.placement:
            layers = [w for w in result['root_windows'] if w['depth'] == 32 and
                      w['geometry'][2:] == result['fixture']['geometry'][2:]]
            if len(layers) != 1:
                raise RuntimeError('alpha host is missing or ambiguous')
            layer = int(layers[0]['window'], 16)
            point = translate(display, window, root, *args.sample)
            result['placement'] = {'mode': args.placement, 'window': hex(layer),
                                   'sample': point, 'before_pixel': pixel(display, root, point)}
            if args.placement == 'move':
                origin = translate(display, window, root, 0, 0)
                x11.XMoveWindow(display, layer, *origin)
            else:
                x11.XReparentWindow(display, layer, window, 0, 0)
            x11.XSync(display, 0)
            time.sleep(0.15)
            result['placement']['after_pixel'] = pixel(display, root, point)
            result['placement']['after_window'] = describe(display, layer, 4)
        print(json.dumps(result, indent=2))
    finally:
        x11.XCloseDisplay(display)


if __name__ == '__main__':
    main()
