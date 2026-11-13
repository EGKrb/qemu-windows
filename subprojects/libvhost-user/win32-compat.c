/*
 * libvhost-user on Windows: see win32-compat.h
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "win32-compat.h"
#include <stdio.h>

static HANDLE fd_object(int fd)
{
    if (w32fd_is_token(fd)) {
        return w32fd_token_handle(fd);
    }
    return (HANDLE)_get_osfhandle(fd);
}

static DWORD allocation_granularity(void)
{
    SYSTEM_INFO si;

    GetSystemInfo(&si);
    return si.dwAllocationGranularity;
}

void *vu_win32_mmap(void *addr, size_t len, int prot, int flags, int fd,
                    int64_t offset)
{
    HANDLE file = fd_object(fd), mapping;
    DWORD protect, access;
    void *ptr;

    if (file == INVALID_HANDLE_VALUE || offset % allocation_granularity()) {
        errno = EINVAL;
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
    mapping = CreateFileMappingW(file, NULL, protect, 0, 0, NULL);
    if (!mapping) {
        /* a section already */
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
    return ptr;
}

int vu_win32_munmap(void *addr, size_t len)
{
    return UnmapViewOfFile(addr) ? 0 : -1;
}

int vu_win32_eventfd_read(int fd, eventfd_t *value)
{
    HANDLE h = fd_object(fd);

    /* the caller was told the event is set: clear it */
    if (WaitForSingleObject(h, 0) != WAIT_OBJECT_0) {
        errno = EAGAIN;
        return -1;
    }
    ResetEvent(h);
    *value = 1;
    return 0;
}

int vu_win32_eventfd_write(int fd, eventfd_t value)
{
    if (!SetEvent(fd_object(fd))) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

int vu_win32_memfd_create(const char *name, unsigned int flags)
{
    static volatile LONG sequence;
    wchar_t dir[MAX_PATH + 1], path[MAX_PATH + 64];
    HANDLE h;
    int fd;

    if (!GetTempPathW(MAX_PATH + 1, dir)) {
        errno = EIO;
        return -1;
    }
    swprintf(path, MAX_PATH + 64, L"%lsvhost-user-%lu-%ld", dir,
             GetCurrentProcessId(), InterlockedIncrement(&sequence));
    h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, CREATE_NEW,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                    NULL);
    if (h == INVALID_HANDLE_VALUE) {
        errno = EIO;
        return -1;
    }
    fd = _open_osfhandle((intptr_t)h, _O_RDWR | _O_BINARY);
    if (fd < 0) {
        CloseHandle(h);
        errno = EMFILE;
    }
    return fd;
}

#undef close
int vu_win32_close(int fd)
{
    if (w32fd_is_token(fd)) {
        return CloseHandle(w32fd_token_handle(fd)) ? 0 : -1;
    }
    return close(fd);
}
