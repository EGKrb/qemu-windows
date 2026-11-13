/*
 * memfd seals on Windows (util/memfd-win32.c): what Linux allows and
 * refuses, and what the kernel of Windows refuses to other handles.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/memfd.h"

#define SZ (1024 * 1024)

/* Another handle of the file, as another process would have */
static HANDLE other_handle(int fd)
{
    HANDLE h = ReOpenFile((HANDLE)_get_osfhandle(fd),
                          GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE |
                          FILE_SHARE_DELETE, 0);

    g_assert(h != INVALID_HANDLE_VALUE);
    return h;
}

static BOOL raw_write(HANDLE h, uint64_t off, const void *buf, DWORD len)
{
    OVERLAPPED ov = { 0 };
    DWORD n;

    ov.Offset = (DWORD)off;
    ov.OffsetHigh = (DWORD)(off >> 32);
    return WriteFile(h, buf, len, &n, &ov) && n == len;
}

static BOOL raw_truncate(HANDLE h, int64_t len)
{
    LARGE_INTEGER li;

    li.QuadPart = len;
    return SetFilePointerEx(h, li, NULL, FILE_BEGIN) && SetEndOfFile(h);
}

static void test_no_sealing(void)
{
    int fd = memfd_create("t", 0);

    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(qemu_memfd_get_seals(fd), ==, F_SEAL_SEAL);
    g_assert_cmpint(qemu_memfd_add_seals(fd, F_SEAL_GROW), ==, -1);
    g_assert_cmpint(errno, ==, EPERM);
    close(fd);
}

static void test_not_memfd(void)
{
    g_autofree char *path = NULL;
    int fd = g_file_open_tmp("qemu-test-XXXXXX", &path, NULL);

    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(qemu_memfd_get_seals(fd), ==, -1);
    g_assert_cmpint(errno, ==, EINVAL);
    g_assert_cmpint(qemu_memfd_add_seals(fd, F_SEAL_GROW), ==, -1);
    g_assert_cmpint(errno, ==, EINVAL);
    close(fd);
    unlink(path);
}

static void test_bad_seals(void)
{
    int fd = memfd_create("t", MFD_ALLOW_SEALING);

    g_assert_cmpint(qemu_memfd_get_seals(fd), ==, 0);
    g_assert_cmpint(qemu_memfd_add_seals(fd, 0x100), ==, -1);
    g_assert_cmpint(errno, ==, EINVAL);
    close(fd);
}

/* what memory-backend-memfd,seal=on does */
static void test_grow_shrink_seal(void)
{
    static const char data[4096] = { 1 };
    int fd = qemu_memfd_create("t", SZ, false, 0,
                               F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL,
                               &error_abort);
    HANDLE h = other_handle(fd);
    HANDLE dup;

    g_assert_cmpint(qemu_memfd_get_seals(fd), ==,
                    F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    /* as Linux */
    g_assert_cmpint(ftruncate(fd, 2 * SZ), ==, -1);
    g_assert_cmpint(errno, ==, EPERM);
    g_assert_cmpint(ftruncate(fd, SZ / 2), ==, -1);
    g_assert_cmpint(errno, ==, EPERM);
    g_assert_cmpint(ftruncate(fd, SZ), ==, 0);
    g_assert_cmpint(qemu_memfd_add_seals(fd, F_SEAL_WRITE), ==, -1);
    g_assert_cmpint(errno, ==, EPERM);

    /* the kernel, for another handle */
    g_assert_false(raw_truncate(h, 4096));
    g_assert_cmpint(GetLastError(), ==, ERROR_USER_MAPPED_FILE);
    g_assert_false(raw_write(h, SZ, data, sizeof(data)));
    g_assert_cmpint(GetLastError(), ==, ERROR_LOCK_VIOLATION);
    g_assert_true(raw_write(h, 0, data, sizeof(data)));

    /* the seals are in the file: a duplicate handle sees them */
    g_assert_true(DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(),
                                  &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
    g_assert_cmpint(qemu_memfd_get_seals(-2 - (int)((uintptr_t)dup >> 2)),
                    ==, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    CloseHandle(dup);
    CloseHandle(h);
    close(fd);
}

static void test_write_seal(void)
{
    char buf[16] = "hello";
    int fd = memfd_create("t", MFD_ALLOW_SEALING);
    HANDLE h;
    char *p, *q;

    g_assert_cmpint(ftruncate(fd, 65536), ==, 0);
    p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    g_assert(p != MAP_FAILED);
    p[0] = 0x5a;
    /* a shared writable mapping: busy */
    g_assert_cmpint(qemu_memfd_add_seals(fd, F_SEAL_WRITE), ==, -1);
    g_assert_cmpint(errno, ==, EBUSY);
    munmap(p, 65536);
    g_assert_cmpint(qemu_memfd_add_seals(fd, F_SEAL_WRITE), ==, 0);
    g_assert_cmpint(qemu_memfd_get_seals(fd), ==, F_SEAL_WRITE);

    /* no write, through any handle */
    g_assert_cmpint(write(fd, buf, 5), ==, -1);
    h = other_handle(fd);
    g_assert_false(raw_write(h, 0, buf, 5));
    g_assert_cmpint(GetLastError(), ==, ERROR_LOCK_VIOLATION);
    CloseHandle(h);

    /* no shared writable mapping; reading and private ones are fine */
    p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    g_assert(p == MAP_FAILED);
    g_assert_cmpint(errno, ==, EPERM);
    p = mmap(NULL, 65536, PROT_READ, MAP_SHARED, fd, 0);
    g_assert(p != MAP_FAILED);
    g_assert_cmpint(p[0], ==, 0x5a);
    q = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    g_assert(q != MAP_FAILED);
    q[0] = 1;
    g_assert_cmpint(p[0], ==, 0x5a);
    munmap(q, 65536);
    munmap(p, 65536);
    close(fd);
}

static void test_future_write_seal(void)
{
    int fd = memfd_create("t", MFD_ALLOW_SEALING);
    char *p, *q;

    g_assert_cmpint(ftruncate(fd, 65536), ==, 0);
    p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    g_assert(p != MAP_FAILED);
    /* existing mappings stay writable */
    g_assert_cmpint(qemu_memfd_add_seals(fd, F_SEAL_FUTURE_WRITE), ==, 0);
    p[1] = 7;
    q = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    g_assert(q == MAP_FAILED);
    g_assert_cmpint(errno, ==, EPERM);
    munmap(p, 65536);
    close(fd);
}

/* closing frees what kept the seals: the file goes away */
static void test_close(void)
{
    int fd = qemu_memfd_create("t", SZ, false, 0,
                               F_SEAL_SHRINK | F_SEAL_WRITE, &error_abort);
    wchar_t path[MAX_PATH];

    g_assert(GetFinalPathNameByHandleW((HANDLE)_get_osfhandle(fd), path,
                                       MAX_PATH, 0));
    g_assert(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
    close(fd);
    g_assert(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/memfd/no-sealing", test_no_sealing);
    g_test_add_func("/memfd/not-memfd", test_not_memfd);
    g_test_add_func("/memfd/bad-seals", test_bad_seals);
    g_test_add_func("/memfd/grow-shrink-seal", test_grow_shrink_seal);
    g_test_add_func("/memfd/write", test_write_seal);
    g_test_add_func("/memfd/future-write", test_future_write_seal);
    g_test_add_func("/memfd/close", test_close);
    return g_test_run();
}
