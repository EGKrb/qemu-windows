/*
 * Passing handles over AF_UNIX sockets on Windows: see win32-fdpass.h
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "win32-fdpass.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifndef SIO_AF_UNIX_GETPEERPID
#define SIO_AF_UNIX_GETPEERPID _WSAIOR(IOC_VENDOR, 256)
#endif

#define W32FD_MAGIC 0x44464851u   /* "QHFD" */

struct iovec_w32 {
    void *iov_base;
    size_t iov_len;
};

typedef struct {
    uint32_t magic;
    uint32_t data_len;
    uint32_t count;
    uint32_t reserved;
} W32FdHeader;

typedef struct {
    uint32_t type;
    uint32_t reserved;
    uint64_t value;
} W32FdWire;

static int wsa_errno(void)
{
    switch (WSAGetLastError()) {
    case WSAEWOULDBLOCK:
        return EAGAIN;
    case WSAEINTR:
        return EINTR;
    case WSAECONNRESET:
    case WSAECONNABORTED:
    case WSAESHUTDOWN:
        return EPIPE;
    case WSAENOTSOCK:
        return EBADF;
    default:
        return EIO;
    }
}

/* Wait until @s can be read (@out false) or written */
static int wait_socket(SOCKET s, bool out)
{
    WSAPOLLFD p = { .fd = s, .events = out ? POLLWRNORM : POLLRDNORM };

    if (WSAPoll(&p, 1, -1) < 0) {
        errno = wsa_errno();
        return -1;
    }
    return 0;
}

/* send() all of @buf, waiting on a non-blocking socket */
static int send_all(SOCKET s, const void *buf, size_t len)
{
    const char *p = buf;

    while (len) {
        int n = send(s, p, len > INT_MAX ? INT_MAX : (int)len, 0);

        if (n == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                if (wait_socket(s, true) < 0) {
                    return -1;
                }
                continue;
            }
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
            errno = wsa_errno();
            return -1;
        }
        p += n;
        len -= n;
    }
    return 0;
}

/* recv() all of @buf (0: the stream ended before) */
static int recv_all(SOCKET s, void *buf, size_t len)
{
    char *p = buf;

    while (len) {
        int n = recv(s, p, len > INT_MAX ? INT_MAX : (int)len, 0);

        if (n == 0) {
            errno = EPIPE;
            return 0;
        }
        if (n == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                if (wait_socket(s, false) < 0) {
                    return -1;
                }
                continue;
            }
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
            errno = wsa_errno();
            return -1;
        }
        p += n;
        len -= n;
    }
    return 1;
}

static HANDLE peer_process(SOCKET s, W32FdState *st)
{
    DWORD pid = 0, bytes = 0;

    if (st->peer_process) {
        return st->peer_process;
    }
    if (WSAIoctl(s, SIO_AF_UNIX_GETPEERPID, NULL, 0, &pid, sizeof(pid),
                 &bytes, NULL, NULL) == SOCKET_ERROR || !pid) {
        errno = ENOTSUP;
        return NULL;
    }
    st->peer_pid = pid;
    st->peer_process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!st->peer_process) {
        errno = EPERM;
    }
    return st->peer_process;
}

void w32fd_state_free(W32FdState *st)
{
    if (st->peer_process) {
        CloseHandle(st->peer_process);
        st->peer_process = NULL;
    }
}

ssize_t w32fd_send(SOCKET s, W32FdState *st, const struct iovec *iov_,
                   int niov, const W32FdItem *items, int nitems)
{
    const struct iovec_w32 *iov = (const struct iovec_w32 *)iov_;
    W32FdWire wire[W32FD_MAX_ITEMS];
    WSAPROTOCOL_INFOW info[W32FD_MAX_ITEMS];
    W32FdHeader hdr = { W32FD_MAGIC, 0, 0, 0 };
    HANDLE proc = NULL;
    int nsock = 0;
    size_t total = 0;
    int i;

    if (nitems > W32FD_MAX_ITEMS) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < niov; i++) {
        total += iov[i].iov_len;
    }
    if (total == 0 || total > UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }
    hdr.data_len = total;
    hdr.count = nitems;

    if (nitems) {
        proc = peer_process(s, st);
        if (!proc) {
            return -1;
        }
    }
    for (i = 0; i < nitems; i++) {
        memset(&wire[i], 0, sizeof(wire[i]));
        wire[i].type = items[i].type;
        if (items[i].type == W32FD_SOCKET) {
            if (WSADuplicateSocketW((SOCKET)items[i].handle, st->peer_pid,
                                    &info[nsock]) == SOCKET_ERROR) {
                errno = wsa_errno();
                goto undo;
            }
            nsock++;
        } else {
            HANDLE dup = NULL;

            if (!DuplicateHandle(GetCurrentProcess(), items[i].handle, proc,
                                 &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                errno = EBADF;
                goto undo;
            }
            wire[i].value = (uint64_t)(uintptr_t)dup;
        }
    }

    if (send_all(s, &hdr, sizeof(hdr)) < 0 ||
        (nitems && send_all(s, wire, nitems * sizeof(W32FdWire)) < 0) ||
        (nsock && send_all(s, info, nsock * sizeof(WSAPROTOCOL_INFOW)) < 0)) {
        return -1;
    }
    for (i = 0; i < niov; i++) {
        if (send_all(s, iov[i].iov_base, iov[i].iov_len) < 0) {
            return -1;
        }
    }
    return total;

undo:
    /* close what was duplicated into the peer */
    {
        int err = errno, j;

        for (j = 0; j < i; j++) {
            if (wire[j].type != W32FD_SOCKET && wire[j].value) {
                DuplicateHandle(proc, (HANDLE)(uintptr_t)wire[j].value, NULL,
                                NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
            }
        }
        errno = err;
    }
    return -1;
}

static void close_item(W32FdItem *it)
{
    if (it->type == W32FD_SOCKET) {
        closesocket((SOCKET)it->handle);
    } else {
        CloseHandle(it->handle);
    }
}

ssize_t w32fd_recv(SOCKET s, W32FdState *st, const struct iovec *iov_,
                   int niov, W32FdItem *items, int *nitems, int maxitems,
                   bool nonblock)
{
    const struct iovec_w32 *iov = (const struct iovec_w32 *)iov_;
    size_t done = 0;
    int i;

    if (nitems) {
        *nitems = 0;
    }
    if (st->frame_left == 0) {
        W32FdHeader hdr;
        W32FdWire wire[W32FD_MAX_ITEMS];
        WSAPROTOCOL_INFOW info;
        char c;
        int n, r;

        /* is anything there? */
        n = recv(s, &c, 1, MSG_PEEK);
        if (n == 0) {
            return 0;
        }
        if (n == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                if (nonblock) {
                    errno = EAGAIN;
                    return -1;
                }
                if (wait_socket(s, false) < 0) {
                    return -1;
                }
                return w32fd_recv(s, st, iov_, niov, items, nitems,
                                  maxitems, nonblock);
            }
            errno = wsa_errno();
            return -1;
        }
        /* a frame comes whole: wait for the rest of it */
        r = recv_all(s, &hdr, sizeof(hdr));
        if (r <= 0) {
            return r < 0 ? -1 : 0;
        }
        if (hdr.magic != W32FD_MAGIC || hdr.count > W32FD_MAX_ITEMS) {
            errno = EPROTO;
            return -1;
        }
        if (hdr.count && recv_all(s, wire, hdr.count * sizeof(W32FdWire))
                         <= 0) {
            return -1;
        }
        for (i = 0; i < (int)hdr.count; i++) {
            W32FdItem it = { wire[i].type, NULL };

            if (it.type == W32FD_SOCKET) {
                SOCKET so;

                if (recv_all(s, &info, sizeof(info)) <= 0) {
                    return -1;
                }
                so = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                                FROM_PROTOCOL_INFO, &info, 0, 0);
                if (so == INVALID_SOCKET) {
                    continue;
                }
                it.handle = (HANDLE)so;
            } else {
                it.handle = (HANDLE)(uintptr_t)wire[i].value;
            }
            if (nitems && *nitems < maxitems) {
                items[(*nitems)++] = it;
            } else {
                close_item(&it);
            }
        }
        st->frame_left = hdr.data_len;
        if (hdr.data_len == 0) {
            /* items go with data: w32fd_send() never makes such frames */
            errno = EPROTO;
            return -1;
        }
    }

    /* the data of the current frame */
    for (i = 0; i < niov && st->frame_left; i++) {
        size_t want = iov[i].iov_len;
        int n;

        if (want > st->frame_left) {
            want = st->frame_left;
        }
        if (!want) {
            continue;
        }
        n = recv(s, iov[i].iov_base, want > INT_MAX ? INT_MAX : (int)want,
                 0);
        if (n == 0) {
            break;
        }
        if (n == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                if (done || (nitems && *nitems)) {
                    break;
                }
                if (nonblock) {
                    errno = EAGAIN;
                    return -1;
                }
                if (wait_socket(s, false) < 0) {
                    return -1;
                }
                i--;
                continue;
            }
            if (done) {
                break;
            }
            errno = wsa_errno();
            return -1;
        }
        done += n;
        st->frame_left -= n;
        if ((size_t)n < want) {
            break;
        }
    }
    return done;
}
