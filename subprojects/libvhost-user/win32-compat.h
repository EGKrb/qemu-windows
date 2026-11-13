/*
 * libvhost-user on Windows: the POSIX functions it uses
 *
 * - descriptors: those of the C runtime for files and sockets, negative
 *   "handle tokens" for other kernel objects (win32-fdpass.h): kick and
 *   call "eventfds" are events, as QEMU's EventNotifiers on Windows;
 * - messages: framed with their handles (win32-fdpass.h), as QEMU sends
 *   them on Windows;
 * - mmap(): views of file mappings; memfd: delete-on-close files.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef LIBVHOST_USER_WIN32_COMPAT_H
#define LIBVHOST_USER_WIN32_COMPAT_H

#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include "win32-fdpass.h"

/* x86 and arm64 Windows are little endian */
#define le16toh(x) ((uint16_t)(x))
#define le32toh(x) ((uint32_t)(x))
#define le64toh(x) ((uint64_t)(x))
#define htole16(x) ((uint16_t)(x))
#define htole32(x) ((uint32_t)(x))
#define htole64(x) ((uint64_t)(x))

/* mmap */
#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define MAP_SHARED  0x01
#define MAP_PRIVATE 0x02
#define MAP_NORESERVE 0
#define MAP_FAILED ((void *) -1)
#define MADV_DONTNEED 0
#define MADV_NOHUGEPAGE 0
void *vu_win32_mmap(void *addr, size_t len, int prot, int flags, int fd,
                    int64_t offset);
int vu_win32_munmap(void *addr, size_t len);
#define mmap vu_win32_mmap
#define munmap vu_win32_munmap
#define madvise(addr, len, advice) (0)

/* eventfd: an event */
typedef uint64_t eventfd_t;
int vu_win32_eventfd_read(int fd, eventfd_t *value);
int vu_win32_eventfd_write(int fd, eventfd_t value);
#define eventfd_read vu_win32_eventfd_read
#define eventfd_write vu_win32_eventfd_write

/* memfd: a file deleted when closed */
#define MFD_CLOEXEC       0x0001U
#define MFD_ALLOW_SEALING 0x0002U
#define F_ADD_SEALS 1033
#define F_SEAL_SEAL   0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW   0x0004
int vu_win32_memfd_create(const char *name, unsigned int flags);
#define memfd_create vu_win32_memfd_create
#define fcntl(fd, cmd, ...) (0)
#define ftruncate(fd, len) (_chsize_s((fd), (len)) ? -1 : 0)

/* close() also closes handle tokens and sockets */
int vu_win32_close(int fd);
#define close vu_win32_close

#endif
