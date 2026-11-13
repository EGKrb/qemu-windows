/*
 * D-Bus display listener — scanout, update and cursor handling.
 *
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "qemu/sockets.h"
#include "qemu/error-report.h"
#include "ui/console-priv.h"
#include "ui/dbus-display1.h"
#include "ui/surface.h"
#include "trace.h"
#include "qemu-vnc.h"

typedef struct ConsoleData {
    QemuDBusDisplay1Console *console_proxy;
    QemuDBusDisplay1Keyboard *keyboard_proxy;
    QemuDBusDisplay1Mouse *mouse_proxy;
    QemuGraphicConsole *gfx_con;
    GDBusConnection *listener_conn;
    /*
     * When true the surface is backed by a read-only mmap (ScanoutMap path)
     * and Update messages must be rejected because compositing into the
     * surface is not possible.  The plain Scanout path provides a writable
     * copy and clears this flag.
     */
    bool read_only;
} ConsoleData;

static void display_ui_info(void *opaque, uint32_t head, QemuUIInfo *info)
{
    ConsoleData *cd = opaque;
    g_autoptr(GError) err = NULL;

    if (!cd || !cd->console_proxy) {
        return;
    }

    qemu_dbus_display1_console_call_set_uiinfo_sync(
        cd->console_proxy,
        info->width_mm, info->height_mm,
        info->xoff, info->yoff,
        info->width, info->height,
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    if (err) {
        error_report("SetUIInfo failed: %s", err->message);
    }
}

static void
scanout_image_destroy(pixman_image_t *image, void *data)
{
    g_variant_unref(data);
}

typedef struct {
    void *addr;
    size_t len;
} ScanoutMapData;

static void
scanout_map_destroy(pixman_image_t *image, void *data)
{
    ScanoutMapData *map = data;
#ifdef G_OS_WIN32
    UnmapViewOfFile(map->addr);
#else
    munmap(map->addr, map->len);
#endif
    g_free(map);
}

static gboolean
on_scanout(QemuDBusDisplay1Listener *listener,
           GDBusMethodInvocation *invocation,
           guint width, guint height, guint stride,
           guint pixman_format, GVariant *data,
           gpointer user_data)
{
    ConsoleData *cd = user_data;
    QemuConsole *con = QEMU_CONSOLE(cd->gfx_con);
    gsize size;
    const uint8_t *pixels;
    pixman_image_t *image;
    DisplaySurface *surface;

    trace_qemu_vnc_scanout(width, height, stride, pixman_format);

    pixels = g_variant_get_fixed_array(data, &size, 1);

    image = pixman_image_create_bits((pixman_format_code_t)pixman_format,
        width, height, (uint32_t *)pixels, stride);
    assert(image);

    g_variant_ref(data);
    pixman_image_set_destroy_function(image, scanout_image_destroy, data);

    cd->read_only = false;
    surface = qemu_create_displaysurface_pixman(image);
    qemu_console_set_surface(con, surface);

    qemu_dbus_display1_listener_complete_scanout(listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_update(QemuDBusDisplay1Listener *listener,
          GDBusMethodInvocation *invocation,
          gint x, gint y, gint w, gint h,
          guint stride, guint pixman_format, GVariant *data,
          gpointer user_data)
{
    ConsoleData *cd = user_data;
    QemuConsole *con = QEMU_CONSOLE(cd->gfx_con);
    DisplaySurface *surface = qemu_console_surface(con);
    gsize size;
    const uint8_t *pixels;
    pixman_image_t *src;

    trace_qemu_vnc_update(x, y, w, h, stride, pixman_format);
    if (!surface || cd->read_only) {
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR,
            G_DBUS_ERROR_FAILED, "No active or writable console");
        return DBUS_METHOD_INVOCATION_HANDLED;
    }

    pixels = g_variant_get_fixed_array(data, &size, 1);
    src = pixman_image_create_bits((pixman_format_code_t)pixman_format,
        w, h, (uint32_t *)pixels, stride);
    assert(src);
    pixman_image_composite(PIXMAN_OP_SRC, src, NULL,
            surface->image,
            0, 0, 0, 0, x, y, w, h);
    pixman_image_unref(src);

    qemu_console_update(con, x, y, w, h);

    qemu_dbus_display1_listener_complete_update(listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

#ifdef G_OS_UNIX
static gboolean
on_scanout_map(QemuDBusDisplay1ListenerUnixMap *listener,
               GDBusMethodInvocation *invocation,
               GUnixFDList *fd_list,
               GVariant *arg_handle,
               guint offset, guint width, guint height,
               guint stride, guint pixman_format,
               gpointer user_data)
{
    ConsoleData *cd = user_data;
    gint32 handle = g_variant_get_handle(arg_handle);
    g_autoptr(GError) err = NULL;
    DisplaySurface *surface;
    int fd;
    void *addr;
    size_t len = (size_t)height * stride;
    pixman_image_t *image;

    trace_qemu_vnc_scanout_map(width, height, stride, pixman_format, offset);

    fd = g_unix_fd_list_get(fd_list, handle, &err);
    if (fd < 0) {
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR,
            G_DBUS_ERROR_FAILED, "Failed to get fd: %s", err->message);
        return DBUS_METHOD_INVOCATION_HANDLED;
    }

    /* MAP_PRIVATE: we only read; avoid propagating writes back to QEMU */
    addr = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, offset);
    close(fd);
    if (addr == MAP_FAILED) {
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR,
            G_DBUS_ERROR_FAILED, "mmap failed: %s", g_strerror(errno));
        return DBUS_METHOD_INVOCATION_HANDLED;
    }

    image = pixman_image_create_bits((pixman_format_code_t)pixman_format,
                                     width, height, addr, stride);
    assert(image);
    {
        ScanoutMapData *map = g_new0(ScanoutMapData, 1);
        map->addr = addr;
        map->len = len;
        pixman_image_set_destroy_function(image, scanout_map_destroy, map);
    }

    cd->read_only = true;
    surface = qemu_create_displaysurface_pixman(image);
    qemu_console_set_surface(QEMU_CONSOLE(cd->gfx_con), surface);

    qemu_dbus_display1_listener_unix_map_complete_scanout_map(
        listener, invocation, NULL);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_update_map(QemuDBusDisplay1ListenerUnixMap *listener,
              GDBusMethodInvocation *invocation,
              guint x, guint y, guint w, guint h,
              gpointer user_data)
{
    ConsoleData *cd = user_data;

    trace_qemu_vnc_update_map(x, y, w, h);

    qemu_console_update(QEMU_CONSOLE(cd->gfx_con), x, y, w, h);

    qemu_dbus_display1_listener_unix_map_complete_update_map(
        listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

#else
/*
 * Windows: QEMU duplicates a handle of its file mapping into this process
 * (org.qemu.Display1.Listener.Win32.Map)
 */
static gboolean
on_scanout_map(QemuDBusDisplay1ListenerWin32Map *listener,
               GDBusMethodInvocation *invocation,
               guint64 arg_handle,
               guint offset, guint width, guint height,
               guint stride, guint pixman_format,
               gpointer user_data)
{
    ConsoleData *cd = user_data;
    HANDLE handle = (HANDLE)(uintptr_t)arg_handle;
    DisplaySurface *surface;
    size_t len = (size_t)height * stride;
    pixman_image_t *image;
    ScanoutMapData *map;
    uint8_t *base;

    trace_qemu_vnc_scanout_map(width, height, stride, pixman_format, offset);

    base = MapViewOfFile(handle, FILE_MAP_COPY, 0, 0, offset + len);
    CloseHandle(handle);
    if (!base) {
        g_autofree char *msg = g_win32_error_message(GetLastError());
        g_dbus_method_invocation_return_error(invocation, G_DBUS_ERROR,
            G_DBUS_ERROR_FAILED, "MapViewOfFile failed: %s", msg);
        return DBUS_METHOD_INVOCATION_HANDLED;
    }

    image = pixman_image_create_bits((pixman_format_code_t)pixman_format,
                                     width, height,
                                     (uint32_t *)(base + offset), stride);
    assert(image);
    map = g_new0(ScanoutMapData, 1);
    map->addr = base;
    map->len = offset + len;
    pixman_image_set_destroy_function(image, scanout_map_destroy, map);

    cd->read_only = true;
    surface = qemu_create_displaysurface_pixman(image);
    qemu_console_set_surface(QEMU_CONSOLE(cd->gfx_con), surface);

    qemu_dbus_display1_listener_win32_map_complete_scanout_map(
        listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

static gboolean
on_update_map(QemuDBusDisplay1ListenerWin32Map *listener,
              GDBusMethodInvocation *invocation,
              guint x, guint y, guint w, guint h,
              gpointer user_data)
{
    ConsoleData *cd = user_data;

    trace_qemu_vnc_update_map(x, y, w, h);

    qemu_console_update(QEMU_CONSOLE(cd->gfx_con), x, y, w, h);

    qemu_dbus_display1_listener_win32_map_complete_update_map(
        listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}
#endif

static gboolean
on_cursor_define(QemuDBusDisplay1Listener *listener,
                 GDBusMethodInvocation *invocation,
                 gint width, gint height,
                 gint hot_x, gint hot_y,
                 GVariant *data,
                 gpointer user_data)
{
    ConsoleData *cd = user_data;
    gsize size;
    const uint8_t *pixels;
    QEMUCursor *c;

    trace_qemu_vnc_cursor_define(width, height, hot_x, hot_y);

    c = cursor_alloc(width, height);
    if (!c) {
        qemu_dbus_display1_listener_complete_cursor_define(
            listener, invocation);
        return DBUS_METHOD_INVOCATION_HANDLED;
    }

    c->hot_x = hot_x;
    c->hot_y = hot_y;

    pixels = g_variant_get_fixed_array(data, &size, 1);
    memcpy(c->data, pixels, MIN(size, (gsize)width * height * 4));

    qemu_console_set_cursor(QEMU_CONSOLE(cd->gfx_con), c);
    cursor_unref(c);

    qemu_dbus_display1_listener_complete_cursor_define(
        listener, invocation);
    return DBUS_METHOD_INVOCATION_HANDLED;
}

typedef struct {
    GMainLoop *loop;
    GThread *thread;
    GDBusConnection *listener_conn;
} ListenerSetupData;

static void
on_register_listener_finished(GObject *source_object,
                              GAsyncResult *res,
                              gpointer user_data)
{
    ListenerSetupData *data = user_data;
    g_autoptr(GError) err = NULL;

    qemu_dbus_display1_console_call_register_listener_finish(
        QEMU_DBUS_DISPLAY1_CONSOLE(source_object),
#ifdef G_OS_UNIX
        NULL,
#endif
        res, &err);

    if (err) {
        error_report("RegisterListener failed: %s", err->message);
        g_main_loop_quit(data->loop);
        return;
    }

    data->listener_conn = g_thread_join(data->thread);
    g_main_loop_quit(data->loop);
}

static GDBusConnection *
console_register_display_listener(QemuDBusDisplay1Console *console)
{
    g_autoptr(GMainLoop) loop = NULL;
    ListenerSetupData data = { 0 };
    PeerSocket ps;
    int pair[2];

    if (qemu_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        error_report("socketpair failed: %s", strerror(errno));
        return NULL;
    }

    if (!peer_socket_prepare(G_DBUS_PROXY(console), pair[1], &ps)) {
        close(pair[0]);
        return NULL;
    }

    loop = g_main_loop_new(NULL, FALSE);
    data.loop = loop;
    data.thread = p2p_dbus_thread_new(pair[0]);

    qemu_dbus_display1_console_call_register_listener(
        console,
        ps.arg,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        PEER_FD_LIST(ps)
        NULL,
        on_register_listener_finished,
        &data);
    peer_socket_clear(&ps);

    g_main_loop_run(loop);

    return data.listener_conn;
}

static void
setup_display_listener(ConsoleData *cd)
{
    g_autoptr(GDBusObjectSkeleton) obj = NULL;
    GDBusObjectManagerServer *server;
    QemuDBusDisplay1Listener *iface;
#ifdef G_OS_UNIX
    QemuDBusDisplay1ListenerUnixMap *iface_map;
#else
    QemuDBusDisplay1ListenerWin32Map *iface_map;
#endif

    server = g_dbus_object_manager_server_new(DBUS_DISPLAY1_ROOT);
    obj = g_dbus_object_skeleton_new(DBUS_DISPLAY1_ROOT "/Listener");

    /* Main listener interface */
    iface = qemu_dbus_display1_listener_skeleton_new();
    g_object_connect(iface,
                     "signal::handle-scanout", on_scanout, cd,
                     "signal::handle-update", on_update, cd,
                     "signal::handle-cursor-define", on_cursor_define, cd,
                     NULL);
    g_dbus_object_skeleton_add_interface(obj,
                                         G_DBUS_INTERFACE_SKELETON(iface));

    /* the shared memory map interface of the platform */
#ifdef G_OS_UNIX
    iface_map = qemu_dbus_display1_listener_unix_map_skeleton_new();
#else
    iface_map = qemu_dbus_display1_listener_win32_map_skeleton_new();
#endif
    g_object_connect(iface_map,
                     "signal::handle-scanout-map", on_scanout_map, cd,
                     "signal::handle-update-map", on_update_map, cd,
                     NULL);
    g_dbus_object_skeleton_add_interface(obj,
                                         G_DBUS_INTERFACE_SKELETON(iface_map));

    {
        const gchar *ifaces[] = {
#ifdef G_OS_UNIX
            "org.qemu.Display1.Listener.Unix.Map", NULL
#else
            "org.qemu.Display1.Listener.Win32.Map", NULL
#endif
        };
        g_object_set(iface, "interfaces", ifaces, NULL);
    }

    g_dbus_object_manager_server_export(server, obj);
    g_dbus_object_manager_server_set_connection(server,
                                                 cd->listener_conn);

    g_dbus_connection_start_message_processing(cd->listener_conn);
}

static const GraphicHwOps vnc_hw_ops = {
    .ui_info = display_ui_info,
};

bool console_setup(GDBusConnection *bus, const char *bus_name,
                   const char *console_path)
{
    g_autoptr(GError) err = NULL;
    ConsoleData *cd;
    QemuConsole *con;

    cd = g_new0(ConsoleData, 1);

    cd->console_proxy = qemu_dbus_display1_console_proxy_new_sync(
        bus, G_DBUS_PROXY_FLAGS_NONE, bus_name,
        console_path, NULL, &err);
    if (!cd->console_proxy) {
        error_report("Failed to create console proxy for %s: %s",
                     console_path, err->message);
        g_free(cd);
        return false;
    }

    cd->keyboard_proxy = QEMU_DBUS_DISPLAY1_KEYBOARD(
        qemu_dbus_display1_keyboard_proxy_new_sync(
            bus, G_DBUS_PROXY_FLAGS_NONE, bus_name,
            console_path, NULL, &err));
    if (!cd->keyboard_proxy) {
        error_report("Failed to create keyboard proxy for %s: %s",
                     console_path, err->message);
        g_object_unref(cd->console_proxy);
        g_free(cd);
        return false;
    }

    g_clear_error(&err);
    cd->mouse_proxy = QEMU_DBUS_DISPLAY1_MOUSE(
        qemu_dbus_display1_mouse_proxy_new_sync(
            bus, G_DBUS_PROXY_FLAGS_NONE, bus_name,
            console_path, NULL, &err));
    if (!cd->mouse_proxy) {
        error_report("Failed to create mouse proxy for %s: %s",
                     console_path, err->message);
        g_object_unref(cd->keyboard_proxy);
        g_object_unref(cd->console_proxy);
        g_free(cd);
        return false;
    }

    con = qemu_graphic_console_create(NULL, 0, &vnc_hw_ops, cd);
    cd->gfx_con = QEMU_GRAPHIC_CONSOLE(con);

    cd->listener_conn = console_register_display_listener(
        cd->console_proxy);
    if (!cd->listener_conn) {
        error_report("Failed to setup D-Bus listener for %s",
                     console_path);
        g_object_unref(cd->mouse_proxy);
        g_object_unref(cd->keyboard_proxy);
        g_object_unref(cd->console_proxy);
        g_free(cd);
        return false;
    }

    setup_display_listener(cd);
    input_setup(cd->keyboard_proxy, cd->mouse_proxy);

    return true;
}

QemuDBusDisplay1Keyboard *console_get_keyboard(const QemuConsole *con)
{
    ConsoleData *cd;

    if (!QEMU_IS_GRAPHIC_CONSOLE(con)) {
        return NULL;
    }
    cd = con->hw;
    return cd ? cd->keyboard_proxy : NULL;
}

QemuDBusDisplay1Mouse *console_get_mouse(const QemuConsole *con)
{
    ConsoleData *cd;

    if (!QEMU_IS_GRAPHIC_CONSOLE(con)) {
        return NULL;
    }
    cd = con->hw;
    return cd ? cd->mouse_proxy : NULL;
}
