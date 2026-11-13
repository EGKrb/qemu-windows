/*
 * Standalone VNC server connecting to QEMU via D-Bus display interface.
 *
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "qemu/error-report.h"
#include "qemu-vnc.h"

static GDBusConnection *
dbus_p2p_from_fd(int fd)
{
    g_autoptr(GError) err = NULL;
    g_autoptr(GSocket) socket = NULL;
    g_autoptr(GSocketConnection) socketc = NULL;
    GDBusConnection *conn;

#ifdef G_OS_WIN32
    /* QEMU's sockets are descriptors of the C runtime: GLib takes SOCKETs */
    socket = g_socket_new_from_fd((int)_get_osfhandle(fd), &err);
#else
    socket = g_socket_new_from_fd(fd, &err);
#endif
    if (!socket) {
        error_report("Failed to create socket: %s", err->message);
        return NULL;
    }

    socketc = g_socket_connection_factory_create_connection(socket);
    if (!socketc) {
        error_report("Failed to create socket connection");
        return NULL;
    }

    conn = g_dbus_connection_new_sync(
        G_IO_STREAM(socketc), NULL,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
        G_DBUS_CONNECTION_FLAGS_DELAY_MESSAGE_PROCESSING,
        NULL, NULL, &err);
    if (!conn) {
        error_report("Failed to create D-Bus connection: %s", err->message);
        return NULL;
    }

    return conn;
}

static gpointer
p2p_server_setup_thread(gpointer data)
{
    return dbus_p2p_from_fd(GPOINTER_TO_INT(data));
}

GThread *
p2p_dbus_thread_new(int fd)
{
    return g_thread_new("p2p-server-setup",
                         p2p_server_setup_thread,
                         GINT_TO_POINTER(fd));
}

#ifdef G_OS_WIN32
/* The process of QEMU, at the other end of @proxy */
static DWORD peer_pid(GDBusProxy *proxy)
{
    GDBusConnection *conn = g_dbus_proxy_get_connection(proxy);
    GCredentials *creds = g_dbus_connection_get_peer_credentials(conn);
    g_autoptr(GVariant) ret = NULL;
    g_autofree char *owner = NULL;
    guint32 pid = 0;

    if (creds) {
        gpointer p = g_credentials_get_native(creds,
                                              G_CREDENTIALS_TYPE_WIN32_PID);

        if (p) {
            return *(DWORD *)p;
        }
    }
    /* on a bus: ask it */
    owner = g_dbus_proxy_get_name_owner(proxy);
    if (!owner) {
        return 0;
    }
    ret = g_dbus_connection_call_sync(conn, "org.freedesktop.DBus",
                                      "/org/freedesktop/DBus",
                                      "org.freedesktop.DBus",
                                      "GetConnectionUnixProcessID",
                                      g_variant_new("(s)", owner),
                                      G_VARIANT_TYPE("(u)"),
                                      G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);
    if (ret) {
        g_variant_get(ret, "(u)", &pid);
    }
    return pid;
}
#endif

bool peer_socket_prepare(GDBusProxy *proxy, int fd, PeerSocket *ps)
{
#ifdef G_OS_WIN32
    WSAPROTOCOL_INFOW info;
    DWORD pid = peer_pid(proxy);

    memset(ps, 0, sizeof(*ps));
    if (!pid || WSADuplicateSocketW((SOCKET)_get_osfhandle(fd), pid,
                                    &info) != 0) {
        error_report("Cannot give a socket to QEMU (pid %lu, error %d)",
                     (unsigned long)pid, WSAGetLastError());
        close(fd);
        return false;
    }
    close(fd);
    ps->arg = g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, &info,
                                        sizeof(info), 1);
    return true;
#else
    g_autoptr(GError) err = NULL;
    int idx;

    memset(ps, 0, sizeof(*ps));
    ps->fd_list = g_unix_fd_list_new();
    idx = g_unix_fd_list_append(ps->fd_list, fd, &err);
    close(fd);
    if (idx < 0) {
        error_report("Failed to append fd: %s", err->message);
        g_clear_object(&ps->fd_list);
        return false;
    }
    ps->arg = g_variant_new_handle(idx);
    return true;
#endif
}

void peer_socket_clear(PeerSocket *ps)
{
#ifdef G_OS_UNIX
    g_clear_object(&ps->fd_list);
#endif
}
