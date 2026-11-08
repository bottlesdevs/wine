import argparse
import ctypes as C
import json


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('title')
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
        print(json.dumps({'fixture': describe(display, window),
                          'root_windows': [describe(display, child, 4) for child in children(display, root)]}, indent=2))
    finally:
        x11.XCloseDisplay(display)


if __name__ == '__main__':
    main()
