import os
from pathlib import Path
import shlex
import subprocess
import sys


source = Path(sys.argv[1]).read_text()
start = source.index('void WAYLAND_WindowPosChanged(')
end = source.index('\nstatic void wayland_configure_window', start)
work = Path(sys.argv[2])
work.mkdir(parents=True, exist_ok=True)
(work / 'window-pos.h').write_text(source[start:end])
(work / 'parent.c').write_text(r'''
#include <assert.h>
#include <stddef.h>
#include <stdio.h>

typedef void *HWND;
typedef unsigned int UINT;
typedef int BOOL;
#define GA_ROOT 2
#define WINE_SWP_FULLSCREEN 1
#define TRUE 1
#define TRACE(...) ((void)0)
struct window_rects { int unused; };
struct window_surface { int unused; };
struct wayland_surface { int unused; };
struct wayland_client_surface { int unused; };
struct wayland_win_data
{
    HWND hwnd;
    struct wayland_surface *wayland_surface;
    struct wayland_client_surface *client_surface;
    struct window_rects rects;
    BOOL is_fullscreen, managed, restack_pending;
};
static int child_handle, root_handle, other_handle;
static struct wayland_surface root_surface, other_surface;
static struct wayland_win_data child, root, other;
static struct wayland_surface *selected;
static HWND ancestor;
static BOOL managed;
static HWND NtUserGetAncestor(HWND hwnd, int flag) { return ancestor; }
static BOOL NtUserIsWindowVisible(HWND hwnd) { return TRUE; }
static BOOL is_mso_border_effect_window(HWND hwnd) { return 0; }
static BOOL is_window_managed(HWND hwnd, UINT flags, BOOL fullscreen) { return managed; }
static struct wayland_win_data *wayland_win_data_get(HWND hwnd) { return &child; }
static struct wayland_win_data *wayland_win_data_get_nolock(HWND hwnd)
{
    if (hwnd == root.hwnd) return &root;
    if (hwnd == other.hwnd) return &other;
    return NULL;
}
static void wayland_win_data_release(struct wayland_win_data *data) {}
static void wayland_client_surface_attach(struct wayland_client_surface *client, HWND hwnd) {}
static void wayland_destroy_overlays(struct wayland_win_data *data) {}
static void wayland_surface_destroy(struct wayland_surface *surface) {}
static BOOL wayland_win_data_create_wayland_surface(struct wayland_win_data *data,
                                                   struct wayland_surface *parent)
{
    selected = parent;
    return TRUE;
}
static void wayland_win_data_update_wayland_state(struct wayland_win_data *data) {}
static void wayland_restack_client_surfaces(HWND hwnd) {}
#include "window-pos.h"

int main(void)
{
    struct window_rects rects = {0};
    struct window_surface surface = {0};
    HWND hints[] = {NULL, &other_handle, &root_handle};
    root.hwnd = &root_handle;
    root.wayland_surface = &root_surface;
    other.hwnd = &other_handle;
    other.wayland_surface = &other_surface;
    child.hwnd = &child_handle;
    ancestor = root.hwnd;
    for (unsigned int i = 0; i < sizeof(hints) / sizeof(*hints); ++i)
    {
        WAYLAND_WindowPosChanged(child.hwnd, NULL, hints[i], 0, &rects, &surface);
        if (selected != &root_surface)
        {
            fprintf(stderr, "child lost its root with owner hint %u\n", i);
            return 1;
        }
    }
    ancestor = child.hwnd;
    WAYLAND_WindowPosChanged(child.hwnd, NULL, other.hwnd, 0, &rects, &surface);
    assert(selected == &other_surface);
    WAYLAND_WindowPosChanged(child.hwnd, NULL, NULL, 0, &rects, &surface);
    assert(selected == NULL);
    managed = TRUE;
    WAYLAND_WindowPosChanged(child.hwnd, NULL, other.hwnd, 0, &rects, &surface);
    assert(selected == NULL);
    puts("Wayland parent selection: 6 cases passed");
    return 0;
}
''')
subprocess.run([*shlex.split(os.environ.get('CC', 'cc')), '-std=c99',
                str(work / 'parent.c'), '-o', str(work / 'parent')], check=True)
subprocess.run([str(work / 'parent')], check=True)
