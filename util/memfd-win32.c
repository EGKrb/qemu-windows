/*
 * memfd on Windows
 *
 * Linux's memfd is anonymous memory with a descriptor, to map it and pass
 * it to other processes.  Windows: a temporary file that only lives while
 * open and stays in the cache (qemu_shm_alloc()), whose descriptor maps
 * (qemu_win32_mmap()) and passes (qemu/win32-fdpass.h) the same way.
 * Seals cannot be set: Windows keeps no such state on a file; huge pages
 * would need the "lock pages in memory" privilege and are refused.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/memfd.h"

int memfd_create(const char *name, unsigned int flags)
{
    return qemu_shm_alloc(0, NULL);
}

int qemu_memfd_create(const char *name, size_t size, bool hugetlb,
                      uint64_t hugetlbsize, unsigned int seals, Error **errp)
{
    if (hugetlb) {
        error_setg(errp, "memfd: huge pages are not supported on Windows");
        return -1;
    }
    return qemu_shm_alloc(size, errp);
}

void *qemu_memfd_alloc(const char *name, size_t size, unsigned int seals,
                       int *fd, Error **errp)
{
    int mfd = qemu_memfd_create(name, size, false, 0, seals, errp);
    void *ptr;

    if (mfd < 0) {
        return NULL;
    }
    ptr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    if (ptr == MAP_FAILED) {
        error_setg_errno(errp, errno, "failed to allocate shared memory");
        close(mfd);
        return NULL;
    }
    *fd = mfd;
    return ptr;
}

void qemu_memfd_free(void *ptr, size_t size, int fd)
{
    if (ptr && munmap(ptr, size) != 0) {
        error_report("memfd munmap() failed");
    }
    if (fd != -1) {
        close(fd);
    }
}

bool qemu_memfd_alloc_check(void)
{
    return true;
}

bool qemu_memfd_check(unsigned int flags)
{
    /* no huge pages; the other flags (sealing, close on exec) are fine */
    return !(flags & MFD_HUGETLB);
}
