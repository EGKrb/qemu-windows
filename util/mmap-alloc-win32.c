/*
 * Guest RAM backed by files on Windows: the file mappings of Win32 stand
 * for mmap() of a file descriptor.
 *
 * MAP_SHARED is a view with FILE_MAP_WRITE, MAP_PRIVATE one with
 * FILE_MAP_COPY (copy on write), PROT_READ alone one with FILE_MAP_READ.
 * A mapping larger than the file extends it (when writable), as the
 * ftruncate() before mmap() does on POSIX.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/mmap-alloc.h"
#include "qemu/memfd.h"

size_t qemu_fd_getpagesize(int fd)
{
    return qemu_real_host_page_size();
}

QemuFsType qemu_fd_getfs(int fd)
{
    return QEMU_FS_TYPE_UNKNOWN;
}

/* MapViewOfFile() takes offsets in multiples of this */
static size_t allocation_granularity(void)
{
    SYSTEM_INFO si;

    GetSystemInfo(&si);
    return si.dwAllocationGranularity;
}

void *qemu_ram_mmap(int fd,
                    size_t size,
                    size_t align,
                    uint32_t qemu_map_flags,
                    off_t map_offset)
{
    const bool readonly = qemu_map_flags & QEMU_MAP_READONLY;
    const bool shared = qemu_map_flags & QEMU_MAP_SHARED;
    const size_t granularity = allocation_granularity();
    uint64_t max_size;
    DWORD protect, access;
    HANDLE file, mapping;
    void *ptr = NULL;
    int tries;

    if (fd < 0) {
        /* anonymous memory: qemu_anon_ram_alloc() serves it on Windows */
        errno = EINVAL;
        return MAP_FAILED;
    }
    file = (HANDLE)_get_osfhandle(fd);
    if (file == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return MAP_FAILED;
    }
    if (map_offset % granularity) {
        /* the offset of a view must be a multiple of 64 KiB */
        errno = EINVAL;
        return MAP_FAILED;
    }

    if (readonly) {
        protect = PAGE_READONLY;
        access = FILE_MAP_READ;
    } else if (shared) {
        protect = PAGE_READWRITE;
        access = FILE_MAP_WRITE;
    } else {
        protect = PAGE_WRITECOPY;
        access = FILE_MAP_COPY;
    }

    /*
     * A private or read-only mapping cannot extend the file: map what
     * exists (the size of the file is then 0 for "all of it").
     */
    max_size = (readonly || !shared) ? 0 : (uint64_t)map_offset + size;
    if (!readonly && shared) {
        /* sealed memfds: no shared writable view once write-sealed */
        if (qemu_memfd_win32_map_check(file, PROT_READ | PROT_WRITE,
                                       MAP_SHARED) < 0) {
            return MAP_FAILED;
        }
        /* nor growth of a file sealed against it */
        if (qemu_memfd_win32_truncate_check(file, max_size) < 0) {
            max_size = 0;
        }
    }
    mapping = CreateFileMappingW(file, NULL, protect,
                                 (DWORD)(max_size >> 32), (DWORD)max_size,
                                 NULL);
    if (!mapping) {
        errno = GetLastError() == ERROR_ACCESS_DENIED ? EACCES : ENOMEM;
        return MAP_FAILED;
    }

    if (align <= granularity) {
        ptr = MapViewOfFile(mapping, access,
                            (DWORD)((uint64_t)map_offset >> 32),
                            (DWORD)map_offset, size);
    } else {
        /*
         * Larger alignments: find a free range of size + align, then map
         * the view at its aligned start.  Another thread can take the
         * range in between, hence the retries.
         */
        for (tries = 0; tries < 16 && !ptr; tries++) {
            void *area = VirtualAlloc(NULL, size + align, MEM_RESERVE,
                                      PAGE_NOACCESS);
            uintptr_t aligned;

            if (!area) {
                break;
            }
            aligned = QEMU_ALIGN_UP((uintptr_t)area, align);
            VirtualFree(area, 0, MEM_RELEASE);
            ptr = MapViewOfFileEx(mapping, access,
                                  (DWORD)((uint64_t)map_offset >> 32),
                                  (DWORD)map_offset, size, (void *)aligned);
        }
    }
    /* the view keeps the section alive */
    CloseHandle(mapping);
    if (!ptr) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    if (!readonly && shared) {
        qemu_memfd_win32_mapped(file, ptr);
    }
    return ptr;
}

void qemu_ram_munmap(int fd, void *ptr, size_t size)
{
    if (ptr) {
        qemu_memfd_win32_unmapped(ptr);
        UnmapViewOfFile(ptr);
    }
}

/* The mmap() of os-win32.h */
void *qemu_win32_mmap(void *addr, size_t len, int prot, int flags, int fd,
                      int64_t offset)
{
    HANDLE file, mapping;
    DWORD protect, access;
    void *ptr;

    if (fd <= -2) {
        file = (HANDLE)(uintptr_t)((uintptr_t)(-2 - fd) << 2);
    } else {
        file = (HANDLE)_get_osfhandle(fd);
    }
    if (file == INVALID_HANDLE_VALUE || offset % allocation_granularity()) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    if (qemu_memfd_win32_map_check(file, prot, flags) < 0) {
        return MAP_FAILED;
    }
    if (!(prot & PROT_WRITE)) {
        protect = PAGE_READONLY;
        access = FILE_MAP_READ;
    } else if (flags & MAP_SHARED) {
        protect = PAGE_READWRITE;
        access = FILE_MAP_WRITE;
    } else {
        protect = PAGE_WRITECOPY;
        access = FILE_MAP_COPY;
    }
    /* a section handle maps as it is; a file gets a mapping */
    mapping = CreateFileMappingW(file, NULL, protect, 0, 0, NULL);
    if (!mapping) {
        mapping = file;
    }
    ptr = MapViewOfFileEx(mapping, access, (DWORD)((uint64_t)offset >> 32),
                          (DWORD)offset, len, addr);
    if (mapping != file) {
        CloseHandle(mapping);
    }
    if (!ptr) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    if ((prot & PROT_WRITE) && (flags & MAP_SHARED)) {
        qemu_memfd_win32_mapped(file, ptr);
    }
    return ptr;
}

int qemu_win32_munmap(void *addr, size_t len)
{
    qemu_memfd_win32_unmapped(addr);
    return UnmapViewOfFile(addr) ? 0 : -1;
}
