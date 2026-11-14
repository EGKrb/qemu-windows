/*
 * Passing handles over AF_UNIX sockets on Windows
 *
 * Windows has AF_UNIX sockets but no SCM_RIGHTS.  Both ends of a socket
 * that passes descriptors (vhost-user...) agree to frame what they send:
 *
 *   header  { u32 magic "QHFD", u32 data length, u32 item count, u32 0 }
 *   items   { u32 type, u32 0, u64 value } [count]
 *           followed, for each socket item, by its WSAPROTOCOL_INFOW
 *   data    [data length]
 *
 * The sender duplicates each handle into the receiving process (whose id
 * the socket gives: SIO_AF_UNIX_GETPEERPID) and sends the values the
 * receiver will use; sockets go as WSADuplicateSocket() made them.  As
 * with SCM_RIGHTS, the items belong to the first byte of their data.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef WIN32_FDPASS_H
#define WIN32_FDPASS_H

#include <winsock2.h>
#include <windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define W32FD_MAX_ITEMS 32

typedef enum {
    W32FD_FILE = 1,     /* a file: the descriptor of a C runtime */
    W32FD_HANDLE = 2,   /* another kernel object (an event...) */
    W32FD_SOCKET = 3,   /* a socket */
} W32FdType;

typedef struct {
    W32FdType type;
    HANDLE handle;      /* in the process that has the item */
} W32FdItem;

typedef struct {
    /* receiving */
    uint32_t frame_left;    /* bytes of data left in the current frame */
    /* sending */
    DWORD peer_pid;
    HANDLE peer_process;
} W32FdState;

struct iovec;

/*
 * Send @iov with @items (duplicated for the peer); blocks until the whole
 * frame is sent.  Returns the bytes of data sent, or -1 with errno set.
 */
ssize_t w32fd_send(SOCKET s, W32FdState *st, const struct iovec *iov,
                   int niov, const W32FdItem *items, int nitems);

/*
 * Receive into @iov, within the current frame.  Items arrive with the
 * first byte of their frame: up to @maxitems go to @items (*@nitems),
 * the others are closed.  Returns the bytes read, 0 at the end of the
 * stream, -1 with errno set (EAGAIN: no data, when @nonblock).
 */
ssize_t w32fd_recv(SOCKET s, W32FdState *st, const struct iovec *iov,
                   int niov, W32FdItem *items, int *nitems, int maxitems,
                   bool nonblock);

/* Release the state (the peer's process handle) */
void w32fd_state_free(W32FdState *st);

/*
 * The process at the other end of @s, for a socket the other end of which
 * was passed to a process (a socket pair made here, its other end
 * inherited): AF_UNIX tells the process that made that end.  0 forgets it.
 */
void w32fd_set_peer_pid(SOCKET s, DWORD pid);

/*
 * Descriptors of the C runtime stand for files and sockets; other kernel
 * objects (events) travel as negative "descriptors" that hold a handle.
 */
static inline int w32fd_handle_token(HANDLE h)
{
    return -2 - (int)((uintptr_t)h >> 2);
}

static inline HANDLE w32fd_token_handle(int token)
{
    return (HANDLE)(uintptr_t)((uintptr_t)(-2 - token) << 2);
}

static inline bool w32fd_is_token(int fd)
{
    return fd <= -2;
}

#endif
