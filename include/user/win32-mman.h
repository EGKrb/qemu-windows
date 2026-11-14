/*
 * POSIX memory-mapping API for the native Win32 linux-user prototype.
 *
 * The user-mode core (accel/tcg/user-exec.c, ...) is written against
 * mmap/mprotect.  On Windows these are implemented in linux-user/win32/mem.c
 * on top of VirtualAlloc/VirtualProtect, inside the reserved guest space.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef USER_WIN32_MMAN_H
#define USER_WIN32_MMAN_H

/* not the mmap() of files of system/os-win32.h: the guest's space here */
#undef mmap
#undef munmap
#undef MAP_FAILED
#undef MAP_SHARED
#undef MAP_PRIVATE
#undef PROT_NONE
#undef PROT_READ
#undef PROT_WRITE
#undef PROT_EXEC

#define PROT_NONE       0x0
#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4

#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS
#define MAP_NORESERVE   0x4000
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_FAILED      ((void *)-1)

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off);
int munmap(void *addr, size_t len);
int mprotect(void *addr, size_t len, int prot);

/*
 * Only used on /proc/self/mem by cpu_memory_rw_debug(), whose open() always
 * fails on Windows first: report the descriptor as unseekable.
 */
static inline ssize_t pread(int fd, void *buf, size_t len, off_t off)
{
    errno = ESPIPE;
    return -1;
}
static inline ssize_t pwrite(int fd, const void *buf, size_t len, off_t off)
{
    errno = ESPIPE;
    return -1;
}

/*
 * Host faults are delivered by a vectored exception handler, not a signal
 * handler: there is no host signal mask to restore.
 */
#ifndef _POSIX
typedef _sigset_t sigset_t;
#endif
#ifndef SIG_SETMASK
#define SIG_BLOCK       0
#define SIG_UNBLOCK     1
#define SIG_SETMASK     2
#endif
static inline int sigprocmask(int how, const sigset_t *set, sigset_t *old)
{
    if (old) {
        *old = 0;
    }
    return 0;
}

#endif
