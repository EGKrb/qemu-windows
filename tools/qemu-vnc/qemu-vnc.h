/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TOOLS_QEMU_VNC_H
#define TOOLS_QEMU_VNC_H

#include "qemu/osdep.h"

#ifdef G_OS_UNIX
#include <gio/gunixfdlist.h>
#endif
#include "qemu/dbus.h"
#include "qapi-types-char.h"
#include "ui/console.h"
#include "ui/dbus-display1.h"

#define TEXT_COLS 80
#define TEXT_ROWS 24
#define TEXT_FONT_WIDTH  8
#define TEXT_FONT_HEIGHT 16


QemuTextConsole *qemu_vnc_text_console_new(const char *name,
                                           int fd, bool echo,
                                           ChardevVCEncoding encoding);

void input_setup(QemuDBusDisplay1Keyboard *kbd,
                 QemuDBusDisplay1Mouse *mouse);
bool console_setup(GDBusConnection *bus, const char *bus_name,
                   const char *console_path);
QemuDBusDisplay1Keyboard *console_get_keyboard(const QemuConsole *con);
QemuDBusDisplay1Mouse *console_get_mouse(const QemuConsole *con);

void audio_setup(GDBusObjectManager *manager);
void clipboard_setup(GDBusObjectManager *manager, GDBusConnection *bus);
void chardev_setup(const char * const *chardev_names,
                   GDBusObjectManager *manager);

GThread *p2p_dbus_thread_new(int fd);

/*
 * One end of a socket pair, given to QEMU in a D-Bus call: a descriptor in
 * a GUnixFDList on POSIX; on Windows the WSAPROTOCOL_INFOW of the socket
 * duplicated for QEMU's process (the "ay" arguments of the Win32 D-Bus
 * display interface)
 */
typedef struct PeerSocket {
    GVariant *arg;
#ifdef G_OS_UNIX
    GUnixFDList *fd_list;
#endif
} PeerSocket;

#ifdef G_OS_UNIX
#define PEER_FD_LIST(ps) (ps).fd_list,
/* the out_fd_list argument of the _finish() functions */
#define PEER_NO_FD_LIST NULL,
#else
#define PEER_FD_LIST(ps)
#define PEER_NO_FD_LIST
#endif

/* Closes @fd in any case */
bool peer_socket_prepare(GDBusProxy *proxy, int fd, PeerSocket *ps);
void peer_socket_clear(PeerSocket *ps);

void vnc_dbus_setup(GDBusConnection *bus);
void vnc_dbus_emit_leaving(const char *reason);
void vnc_dbus_cleanup(void);
void vnc_dbus_client_connected(const char *host, const char *service,
                               const char *family, bool websocket);
void vnc_dbus_client_initialized(const char *host, const char *service,
                                 const char *x509_dname,
                                 const char *sasl_username);
void vnc_dbus_client_disconnected(const char *host, const char *service);

#endif /* TOOLS_QEMU_VNC_H */
