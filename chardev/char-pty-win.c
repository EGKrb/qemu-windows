/*
 * "pty" character device on Windows
 *
 * Windows has no pseudo-terminals with a path for other programs: the
 * device is a named pipe, \\.\pipe\qemu-pty-PID-N, which terminal and
 * serial programs open as Hyper-V's COM ports.  As with a pty, QEMU
 * starts without waiting for a client, drops the output while none is
 * connected, and takes the next client when one leaves.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "chardev/char.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "qemu/qemu-print.h"

#define PTY_BUF_LEN 4096

struct PtyChardev {
    Chardev parent;

    HANDLE pipe;
    char *pty_name;
    char *path;         /* the symbolic link asked for */

    bool connected;
    bool pending;       /* a connection or a read is in progress */
    bool reading;       /* ... a read, not a connection */
    guint retry;        /* timer to read when the guest can take data */
    OVERLAPPED ov;
    HANDLE hwrite;
    uint8_t buf[PTY_BUF_LEN];
};
typedef struct PtyChardev PtyChardev;

DECLARE_INSTANCE_CHECKER(PtyChardev, PTY_CHARDEV, TYPE_CHARDEV_PTY)

static void pty_chr_listen(PtyChardev *s);
static void pty_chr_start_read(PtyChardev *s);

static gboolean pty_chr_retry(gpointer opaque)
{
    PtyChardev *s = opaque;

    s->retry = 0;
    pty_chr_start_read(s);
    return G_SOURCE_REMOVE;
}

static void pty_chr_disconnected(PtyChardev *s)
{
    Chardev *chr = CHARDEV(s);

    if (s->connected) {
        s->connected = false;
        qemu_chr_be_event(chr, CHR_EVENT_CLOSED);
    }
    DisconnectNamedPipe(s->pipe);
    pty_chr_listen(s);
}

static void pty_chr_completed(void *opaque)
{
    PtyChardev *s = opaque;
    Chardev *chr = CHARDEV(s);
    DWORD size = 0;
    BOOL ok;

    if (!s->pending) {
        return;
    }
    ok = GetOverlappedResult(s->pipe, &s->ov, &size, FALSE);
    if (!ok && GetLastError() == ERROR_IO_INCOMPLETE) {
        return;
    }
    s->pending = false;
    ResetEvent(s->ov.hEvent);

    if (!s->reading) {
        /* a client connected (or was already there) */
        if (!ok && GetLastError() != ERROR_PIPE_CONNECTED) {
            pty_chr_disconnected(s);
            return;
        }
        s->connected = true;
        qemu_chr_be_event(chr, CHR_EVENT_OPENED);
    } else {
        if (!ok || size == 0) {
            if (!ok && GetLastError() == ERROR_MORE_DATA) {
                qemu_chr_be_write(chr, s->buf, size);
            } else {
                pty_chr_disconnected(s);
                return;
            }
        } else {
            qemu_chr_be_write(chr, s->buf, size);
        }
    }
    pty_chr_start_read(s);
}

static void pty_chr_listen(PtyChardev *s)
{
    HANDLE event = s->ov.hEvent;

    ZeroMemory(&s->ov, sizeof(s->ov));
    s->ov.hEvent = event;
    ResetEvent(event);
    s->reading = false;
    s->pending = true;
    if (ConnectNamedPipe(s->pipe, &s->ov)) {
        SetEvent(s->ov.hEvent);
    } else {
        switch (GetLastError()) {
        case ERROR_IO_PENDING:
            break;
        case ERROR_PIPE_CONNECTED:
            /* connected between CreateNamedPipe and ConnectNamedPipe */
            SetEvent(s->ov.hEvent);
            break;
        default:
            s->pending = false;
            break;
        }
    }
}

/* Read what the guest can take now; called again when it can take more */
static void pty_chr_start_read(PtyChardev *s)
{
    Chardev *chr = CHARDEV(s);
    HANDLE event = s->ov.hEvent;
    DWORD len;

    if (!s->connected || s->pending) {
        return;
    }
    len = MIN(qemu_chr_be_can_write(chr), PTY_BUF_LEN);
    if (len == 0) {
        /*
         * The guest cannot take data now: chr_accept_input tells when it
         * can, and a timer looks again in case the front end does not
         */
        if (!s->retry) {
            s->retry = g_timeout_add(20, pty_chr_retry, s);
        }
        return;
    }
    ZeroMemory(&s->ov, sizeof(s->ov));
    s->ov.hEvent = event;
    s->reading = true;
    s->pending = true;
    if (!ReadFile(s->pipe, s->buf, len, NULL, &s->ov) &&
        GetLastError() != ERROR_IO_PENDING) {
        /* the completion handler sees the error */
        SetEvent(event);
    }
}

static void pty_chr_update_read_handler(Chardev *chr)
{
    pty_chr_start_read(PTY_CHARDEV(chr));
}

static void pty_chr_accept_input(Chardev *chr)
{
    pty_chr_start_read(PTY_CHARDEV(chr));
}

static int pty_chr_write(Chardev *chr, const uint8_t *buf, int len)
{
    PtyChardev *s = PTY_CHARDEV(chr);
    OVERLAPPED ov = { .hEvent = s->hwrite };
    DWORD size;
    int done = 0;

    if (!s->connected) {
        /* as a pty without a reader: the output is lost */
        return len;
    }
    while (done < len) {
        ResetEvent(s->hwrite);
        if (!WriteFile(s->pipe, buf + done, len - done, NULL, &ov) &&
            GetLastError() != ERROR_IO_PENDING) {
            break;
        }
        if (!GetOverlappedResult(s->pipe, &ov, &size, TRUE) || size == 0) {
            break;
        }
        done += size;
    }
    /* a broken pipe is noticed by the pending read */
    return done < len ? len : done;
}

static bool pty_chr_open(Chardev *chr, ChardevBackend *backend, Error **errp)
{
    static int sequence;
    PtyChardev *s = PTY_CHARDEV(chr);
    char *path = backend->u.pty.data->path;

    s->pty_name = g_strdup_printf("\\\\.\\pipe\\qemu-pty-%lu-%d",
                                  GetCurrentProcessId(),
                                  qatomic_fetch_inc(&sequence));
    s->pipe = CreateNamedPipeA(s->pty_name,
                               PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
                               FILE_FLAG_FIRST_PIPE_INSTANCE,
                               PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
                               PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                               1, PTY_BUF_LEN, PTY_BUF_LEN, 0, NULL);
    if (s->pipe == INVALID_HANDLE_VALUE) {
        s->pipe = NULL;
        error_setg_win32(errp, GetLastError(), "Failed to create PTY");
        return false;
    }
    s->ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    s->hwrite = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!s->ov.hEvent || !s->hwrite) {
        error_setg_win32(errp, GetLastError(), "Failed to create PTY");
        return false;
    }

    qemu_printf("char device redirected to %s (label %s)\n",
                s->pty_name, chr->label);

    /* create symbolic link */
    if (path) {
        g_autofree gunichar2 *wpath = g_utf8_to_utf16(path, -1, NULL, NULL,
                                                      NULL);
        g_autofree gunichar2 *wtarget = g_utf8_to_utf16(s->pty_name, -1,
                                                        NULL, NULL, NULL);

        if (!wpath || !wtarget ||
            !CreateSymbolicLinkW(wpath, wtarget,
                                 SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
            error_setg_win32(errp, GetLastError(),
                             "Failed to create PTY symlink");
            return false;
        }
        s->path = g_strdup(path);
    }

    qemu_add_wait_object(s->ov.hEvent, pty_chr_completed, s);
    pty_chr_listen(s);
    return true;
}

static void char_pty_finalize(Object *obj)
{
    PtyChardev *s = PTY_CHARDEV(obj);

    if (s->path) {
        unlink(s->path);
        g_free(s->path);
    }
    if (s->retry) {
        g_source_remove(s->retry);
    }
    if (s->ov.hEvent) {
        qemu_del_wait_object(s->ov.hEvent, pty_chr_completed, s);
    }
    if (s->pipe) {
        CancelIoEx(s->pipe, NULL);
        if (s->pending) {
            DWORD size;
            GetOverlappedResult(s->pipe, &s->ov, &size, TRUE);
        }
        CloseHandle(s->pipe);
    }
    if (s->ov.hEvent) {
        CloseHandle(s->ov.hEvent);
    }
    if (s->hwrite) {
        CloseHandle(s->hwrite);
    }
    if (s->connected) {
        qemu_chr_be_event(CHARDEV(obj), CHR_EVENT_CLOSED);
    }
    g_free(s->pty_name);
}

static void pty_chr_parse(QemuOpts *opts, ChardevBackend *backend, Error **errp)
{
    const char *path = qemu_opt_get(opts, "path");
    ChardevPty *pty;

    backend->type = CHARDEV_BACKEND_KIND_PTY;
    pty = backend->u.pty.data = g_new0(ChardevPty, 1);
    qemu_chr_parse_common(opts, qapi_ChardevPty_base(pty));
    pty->path = g_strdup(path);
}

static char *pty_chr_get_pty_name(Chardev *chr)
{
    return g_strdup(PTY_CHARDEV(chr)->pty_name);
}

static char *pty_chr_get_filename(Chardev *chr)
{
    return g_strdup_printf("pty:%s", PTY_CHARDEV(chr)->pty_name);
}

static void char_pty_class_init(ObjectClass *oc, const void *data)
{
    ChardevClass *cc = CHARDEV_CLASS(oc);

    cc->chr_parse = pty_chr_parse;
    cc->chr_open = pty_chr_open;
    cc->chr_write = pty_chr_write;
    cc->chr_update_read_handler = pty_chr_update_read_handler;
    cc->chr_accept_input = pty_chr_accept_input;
    cc->chr_get_pty_name = pty_chr_get_pty_name;
    cc->chr_get_filename = pty_chr_get_filename;
}

static const TypeInfo char_pty_type_info = {
    .name = TYPE_CHARDEV_PTY,
    .parent = TYPE_CHARDEV,
    .instance_size = sizeof(PtyChardev),
    .instance_finalize = char_pty_finalize,
    .class_init = char_pty_class_init,
};

static void register_types(void)
{
    type_register_static(&char_pty_type_info);
}

type_init(register_types);
