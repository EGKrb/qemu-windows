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

static char *guard_log;

static double now_ms(void)
{
    LARGE_INTEGER t, f;

    QueryPerformanceCounter(&t);
    QueryPerformanceFrequency(&f);
    return t.QuadPart * 1000.0 / f.QuadPart;
}

static uint64_t file_index(HANDLE h)
{
    BY_HANDLE_FILE_INFORMATION info;

    g_assert_true(GetFileInformationByHandle(h, &info));
    return (uint64_t)info.nFileIndexHigh << 32 | info.nFileIndexLow;
}

/*
 * Milliseconds from @t0 until a guard let the memfd @index go (its memory
 * freed), from the log of qemu-memfd-guard; -1 if not within 5 s
 */
static double released_after_ms(uint64_t index, double t0)
{
    g_autofree char *want = g_strdup_printf("released %016llx ",
                                            (unsigned long long)index);

    while (now_ms() - t0 < 5000) {
        g_autofree char *log = NULL;
        char *p;

        if (g_file_get_contents(guard_log, &log, NULL, NULL)) {
            for (p = strstr(log, want); p; p = strstr(p + 1, want)) {
                double t = g_ascii_strtod(p + strlen(want), NULL);

                if (t >= t0) {
                    return t - t0;
                }
            }
        }
        SwitchToThread();
    }
    return -1;
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
    uint64_t index;
    double ms, t0;

    g_assert(GetFinalPathNameByHandleW((HANDLE)_get_osfhandle(fd), path,
                                       MAX_PATH, 0));
    g_assert(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
    index = file_index((HANDLE)_get_osfhandle(fd));
    /* sealed and closed at once: the guard holds it already, then lets go */
    t0 = now_ms();
    close(fd);
    /* close() tells the guard: at once, as on Linux */
    ms = released_after_ms(index, t0);
    g_test_message("released %.2f ms after close()", ms);
    g_assert_cmpfloat(ms, >=, 0);
    g_assert_cmpfloat(ms, <, 50);
}

/*
 * The seals outlive the descriptor that sealed: a duplicate of it (what
 * another process gets by handle passing) still cannot write
 */
static void test_persist(void)
{
    char buf[8] = "x";
    int fd = qemu_memfd_create("t", 65536, false, 0,
                               F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK,
                               &error_abort);
    uint64_t index;
    HANDLE dup;
    double ms, t0;

    g_assert_true(DuplicateHandle(GetCurrentProcess(),
                                  (HANDLE)_get_osfhandle(fd),
                                  GetCurrentProcess(), &dup, 0, FALSE,
                                  DUPLICATE_SAME_ACCESS));
    close(fd);
    g_assert_false(raw_write(dup, 0, buf, 1));
    g_assert_cmpint(GetLastError(), ==, ERROR_LOCK_VIOLATION);
    g_assert_false(raw_write(dup, 65536, buf, 1));
    g_assert_cmpint(GetLastError(), ==, ERROR_LOCK_VIOLATION);
    /*
     * The last handle closed without close() of QEMU, as a program that is
     * not QEMU does: the name of the memfd goes (POSIX deletion), which
     * the guard watches
     */
    index = file_index(dup);
    t0 = now_ms();
    CloseHandle(dup);
    ms = released_after_ms(index, t0);
    g_test_message("released %.2f ms after CloseHandle()", ms);
    g_assert_cmpfloat(ms, >=, 0);
    g_assert_cmpfloat(ms, <, 50);
}

/*
 * A process that receives a sealed memfd enforces the seals too: they
 * stay when the sender lets go of its descriptor
 */
static void test_received(void)
{
    char buf[8] = "x";
    int fd = qemu_memfd_create("t", 65536, false, 0,
                               F_SEAL_SHRINK | F_SEAL_GROW, &error_abort);
    HANDLE dup, other;
    int rfd;

    g_assert_true(DuplicateHandle(GetCurrentProcess(),
                                  (HANDLE)_get_osfhandle(fd),
                                  GetCurrentProcess(), &dup, 0, FALSE,
                                  DUPLICATE_SAME_ACCESS));
    rfd = _open_osfhandle((intptr_t)dup, _O_RDWR | _O_BINARY);
    g_assert_cmpint(rfd, >=, 0);
    qemu_memfd_win32_received(rfd);
    g_assert_cmpint(qemu_memfd_get_seals(rfd), ==,
                    F_SEAL_SHRINK | F_SEAL_GROW);
    close(fd);          /* the sender is gone */

    other = other_handle(rfd);
    g_assert_false(raw_truncate(other, 4096));
    g_assert_cmpint(GetLastError(), ==, ERROR_USER_MAPPED_FILE);
    g_assert_false(raw_write(other, 65536, buf, 1));
    g_assert_cmpint(GetLastError(), ==, ERROR_LOCK_VIOLATION);
    CloseHandle(other);
    close(rfd);
}

/*
 * The seals outlive the process that sealed (qemu-memfd-guard): a child
 * seals, gives us a duplicate and exits; the kernel still refuses writes
 * and truncation; when we let go too, the memfd ends
 */
static void test_guard(void)
{
    const char *hfile = g_getenv("MEMFD_TEST_HANDLE_FILE");
    g_autofree char *contents = NULL;
    wchar_t path[MAX_PATH];
    char buf[8] = "x";
    HANDLE h;
    int rfd;
    uint64_t index;
    double ms, t0;

    if (g_test_subprocess()) {
        HANDLE parent = OpenProcess(PROCESS_DUP_HANDLE, FALSE,
                                    atoi(g_getenv("MEMFD_TEST_PARENT")));
        int fd = qemu_memfd_create("t", 65536, false, 0,
                                   F_SEAL_WRITE | F_SEAL_SHRINK |
                                   F_SEAL_GROW, &error_abort);
        g_autofree char *v = NULL;
        HANDLE dup;

        g_assert(parent);
        g_assert_true(DuplicateHandle(GetCurrentProcess(),
                                      (HANDLE)_get_osfhandle(fd), parent,
                                      &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
        v = g_strdup_printf("%llu", (unsigned long long)(uintptr_t)dup);
        g_assert_true(g_file_set_contents(hfile, v, -1, NULL));
        close(fd);      /* the sealer lets go, then exits */
        return;
    }

    hfile = g_build_filename(g_get_tmp_dir(), "qemu-memfd-guard-test", NULL);
    g_setenv("MEMFD_TEST_HANDLE_FILE", hfile, TRUE);
    g_setenv("MEMFD_TEST_PARENT",
             g_strdup_printf("%lu", GetCurrentProcessId()), TRUE);
    g_test_trap_subprocess(NULL, 0, G_TEST_SUBPROCESS_INHERIT_STDERR);
    g_test_trap_assert_passed();
    g_assert_true(g_file_get_contents(hfile, &contents, NULL, NULL));
    g_remove(hfile);
    h = (HANDLE)(uintptr_t)g_ascii_strtoull(contents, NULL, 10);

    /* the sealer is gone: still sealed, by the kernel */
    Sleep(200);
    g_assert_false(raw_write(h, 0, buf, 1));
    g_assert_cmpint(GetLastError(), ==, ERROR_LOCK_VIOLATION);
    g_assert_false(raw_write(h, 65536, buf, 1));
    g_assert_cmpint(GetLastError(), ==, ERROR_LOCK_VIOLATION);
    g_assert_false(raw_truncate(h, 4096));
    g_assert_cmpint(GetLastError(), ==, ERROR_USER_MAPPED_FILE);

    /*
     * We take it as a receiver: our guard holds it too, with the guard of
     * the child; once we let go, neither keeps the other one alive
     */
    rfd = _open_osfhandle((intptr_t)h, _O_RDWR | _O_BINARY);
    g_assert_cmpint(rfd, >=, 0);
    qemu_memfd_win32_received(rfd);

    /* nobody holds it any more: it ends */
    index = file_index(h);
    t0 = now_ms();
    close(rfd);
    ms = released_after_ms(index, t0);
    g_test_message("released %.2f ms after the last close()", ms);
    g_assert_cmpfloat(ms, >=, 0);
    g_assert_cmpfloat(ms, <, 50);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    guard_log = g_build_filename(g_get_tmp_dir(), "qemu-memfd-guard-test.log",
                                 NULL);
    if (!g_test_subprocess()) {
        g_remove(guard_log);
    }
    g_setenv("QEMU_MEMFD_GUARD_LOG", guard_log, TRUE);
    g_test_add_func("/memfd/no-sealing", test_no_sealing);
    g_test_add_func("/memfd/not-memfd", test_not_memfd);
    g_test_add_func("/memfd/bad-seals", test_bad_seals);
    g_test_add_func("/memfd/grow-shrink-seal", test_grow_shrink_seal);
    g_test_add_func("/memfd/write", test_write_seal);
    g_test_add_func("/memfd/future-write", test_future_write_seal);
    g_test_add_func("/memfd/close", test_close);
    g_test_add_func("/memfd/persist", test_persist);
    g_test_add_func("/memfd/received", test_received);
    g_test_add_func("/memfd/guard", test_guard);
    return g_test_run();
}
