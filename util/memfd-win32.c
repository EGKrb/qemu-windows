/*
 * memfd on Windows
 *
 * Linux's memfd is anonymous memory with a descriptor, to map it and pass
 * it to other processes.  Windows: a temporary file that only lives while
 * open and stays in the cache (qemu_shm_alloc()), whose descriptor maps
 * (qemu_win32_mmap()) and passes (qemu/win32-fdpass.h) the same way.
 * Huge pages would need the "lock pages in memory" privilege and are
 * refused.
 *
 * Seals (fcntl F_ADD_SEALS / F_GET_SEALS):
 *  - the seals live in the file, an extended attribute QEMUSEALS: every
 *    process that has the file reads them; a file without it is not a
 *    memfd (EINVAL, as Linux for files that do not seal);
 *  - the kernel of Windows enforces them for every handle and process:
 *      F_SEAL_WRITE,  a shared lock of every byte: Windows refuses writes
 *      F_SEAL_FUTURE_WRITE  to everyone, the locker included;
 *      F_SEAL_GROW    a shared lock from the end of the file: no write
 *                     makes it grow;
 *    The locks are taken on the file object of the descriptor and never
 *    released: every duplicate of the descriptor (fork, or the handle
 *    passing of qemu/win32-fdpass.h) shares that object, and Windows
 *    keeps its locks until the last duplicate is closed, in any process,
 *    whether the process that sealed is still there or not: they last as
 *    long as the memfd, as on Linux.  A process that receives a sealed
 *    memfd (qemu_memfd_win32_received()) locks it too: the sender cannot
 *    unseal by unlocking, Windows lets a process remove its own locks only.
 *      F_SEAL_SHRINK  a section of the file: Windows refuses to cut a file
 *                     under a section or a view (ERROR_USER_MAPPED_FILE);
 *    each process that holds the memfd (sealed or received it, mapped it)
 *    keeps a section or a view while it holds it.
 *    Locks and sections belong to a process and go when it exits: the
 *    process that seals starts qemu-memfd-guard once and gives it each
 *    sealed memfd, which it locks and maps in its turn until nobody else
 *    has the memfd (qemu-memfd-guard-win32.c): the seals then hold for as
 *    long as the memfd exists, whatever process sealed it.
 *    And what Linux refuses on top of that, in mmap()/ftruncate() of
 *    Windows: shared writable mappings once write-sealed (EPERM), sealing
 *    writes while one exists (EBUSY), growing or shrinking by ftruncate
 *    (EPERM).
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/memfd.h"
#include "qemu/queue.h"
#include <winternl.h>

#define SEALS_EA_NAME "QEMUSEALS"
#define SEALS_ALL (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | \
                   F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)

/* FILE_FULL_EA_INFORMATION and FILE_GET_EA_INFORMATION of the DDK */
typedef struct {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[sizeof(SEALS_EA_NAME)];
    uint32_t value;
} __attribute__((packed)) SealsEa;

typedef struct {
    ULONG NextEntryOffset;
    UCHAR EaNameLength;
    CHAR EaName[sizeof(SEALS_EA_NAME)];
} __attribute__((packed)) SealsEaQuery;

typedef NTSTATUS (NTAPI *NtQueryEaFileFn)(HANDLE, PIO_STATUS_BLOCK, PVOID,
                                          ULONG, BOOLEAN, PVOID, ULONG,
                                          PULONG, BOOLEAN);
typedef NTSTATUS (NTAPI *NtSetEaFileFn)(HANDLE, PIO_STATUS_BLOCK, PVOID,
                                        ULONG);
typedef NTSTATUS (NTAPI *NtQueryObjectFn)(HANDLE, OBJECT_INFORMATION_CLASS,
                                          PVOID, ULONG, PULONG);

static NtQueryEaFileFn nt_query_ea;
static NtSetEaFileFn nt_set_ea;
static NtQueryObjectFn nt_query_object;

/*
 * What a process keeps for a descriptor of a sealed memfd it holds: a
 * section (F_SEAL_SHRINK), until the descriptor is closed
 */
typedef struct SealKeeper {
    int fd;
    HANDLE section;
    uint64_t volume, index;     /* the file: its event for the guards */
    QLIST_ENTRY(SealKeeper) next;
} SealKeeper;

/* Shared writable views of memfds in this process */
typedef struct SealView {
    void *addr;
    uint64_t volume, index;
    QLIST_ENTRY(SealView) next;
} SealView;

static SRWLOCK seal_lock = SRWLOCK_INIT;
static QLIST_HEAD(, SealKeeper) keepers = QLIST_HEAD_INITIALIZER(keepers);
static QLIST_HEAD(, SealView) views = QLIST_HEAD_INITIALIZER(views);

static void nt_init(void)
{
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    BOOL pending;

    if (InitOnceBeginInitialize(&once, 0, &pending, NULL) && pending) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

        nt_query_ea = (NtQueryEaFileFn)(void *)GetProcAddress(ntdll,
                                                             "NtQueryEaFile");
        nt_set_ea = (NtSetEaFileFn)(void *)GetProcAddress(ntdll,
                                                         "NtSetEaFile");
        nt_query_object = (NtQueryObjectFn)(void *)GetProcAddress(ntdll,
                                                         "NtQueryObject");
        InitOnceComplete(&once, 0, NULL);
    }
}

static HANDLE fd_handle(int fd)
{
    if (fd <= -2) {
        return (HANDLE)(uintptr_t)((uintptr_t)(-2 - fd) << 2);
    }
    return (HANDLE)_get_osfhandle(fd);
}

static bool file_id(HANDLE h, uint64_t *volume, uint64_t *index)
{
    BY_HANDLE_FILE_INFORMATION info;

    if (!GetFileInformationByHandle(h, &info)) {
        return false;
    }
    *volume = info.dwVolumeSerialNumber;
    *index = (uint64_t)info.nFileIndexHigh << 32 | info.nFileIndexLow;
    return true;
}

/* The seals of the file of @h; -1 if it is not a memfd */
static int read_seals(HANDLE h)
{
    SealsEaQuery q __attribute__((aligned(8))) = { 0 };
    union {
        SealsEa ea;
        uint8_t room[128];      /* entries are padded */
    } u __attribute__((aligned(8))) = { 0 };
    IO_STATUS_BLOCK iosb;
    NTSTATUS st;

    nt_init();
    if (!nt_query_ea) {
        return -1;
    }
    q.EaNameLength = strlen(SEALS_EA_NAME);
    memcpy(q.EaName, SEALS_EA_NAME, sizeof(SEALS_EA_NAME));
    st = nt_query_ea(h, &iosb, &u, sizeof(u), TRUE, &q, sizeof(q), NULL,
                     TRUE);
    if (st < 0 || u.ea.EaValueLength != sizeof(uint32_t)) {
        return -1;
    }
    return u.ea.value;
}

static bool write_seals(HANDLE h, uint32_t seals)
{
    SealsEa ea __attribute__((aligned(8))) = { 0 };
    IO_STATUS_BLOCK iosb;

    nt_init();
    if (!nt_set_ea) {
        return false;
    }
    ea.EaNameLength = strlen(SEALS_EA_NAME);
    ea.EaValueLength = sizeof(uint32_t);
    memcpy(ea.EaName, SEALS_EA_NAME, sizeof(SEALS_EA_NAME));
    ea.value = seals;
    return nt_set_ea(h, &iosb, &ea, sizeof(ea)) >= 0;
}

/* As Linux: only a descriptor open for writing seals */
static bool handle_writable(HANDLE h)
{
    PUBLIC_OBJECT_BASIC_INFORMATION info;
    ULONG len;

    nt_init();
    if (!nt_query_object ||
        nt_query_object(h, ObjectBasicInformation, &info, sizeof(info),
                        &len) < 0) {
        return true;
    }
    return info.GrantedAccess & FILE_WRITE_DATA;
}

static int64_t file_size(HANDLE h)
{
    LARGE_INTEGER li;

    return GetFileSizeEx(h, &li) ? li.QuadPart : -1;
}

static SealKeeper *find_keeper(int fd)
{
    SealKeeper *k;

    QLIST_FOREACH(k, &keepers, next) {
        if (k->fd == fd) {
            return k;
        }
    }
    return NULL;
}

static bool lock_range(HANDLE h, uint64_t from)
{
    OVERLAPPED ov = { 0 };
    uint64_t len = UINT64_MAX - from;

    ov.Offset = (DWORD)from;
    ov.OffsetHigh = (DWORD)(from >> 32);
    /* shared, not exclusive: everyone reads, nobody writes */
    return LockFileEx(h, LOCKFILE_FAIL_IMMEDIATELY, 0, (DWORD)len,
                      (DWORD)(len >> 32), &ov);
}

/* qemu-memfd-guard: started once, on the first sealed memfd */
static HANDLE guard_process;
static HANDLE guard_pipe;       /* memfds to the guard */
static HANDLE guard_ack;        /* a byte back for each: it holds it */
static bool guard_tried;

static bool guard_start_from(const char *exe)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    STARTUPINFOEXW si = { 0 };
    PROCESS_INFORMATION pi;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs;
    SIZE_T attrs_size = 0;
    g_autofree gunichar2 *wexe = NULL;
    HANDLE rd, wr, ack_rd, ack_wr, inherit[2];
    DWORD flags = DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT;
    BOOL ok;

    if (!exe || !g_file_test(exe, G_FILE_TEST_IS_REGULAR)) {
        return false;
    }
    wexe = g_utf8_to_utf16(exe, -1, NULL, NULL, NULL);
    if (!wexe || !CreatePipe(&rd, &wr, &sa, 0)) {
        return false;
    }
    if (!CreatePipe(&ack_rd, &ack_wr, &sa, 0)) {
        CloseHandle(rd);
        CloseHandle(wr);
        return false;
    }
    SetHandleInformation(wr, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(ack_rd, HANDLE_FLAG_INHERIT, 0);
    inherit[0] = rd;
    inherit[1] = ack_wr;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attrs_size);
    attrs = g_malloc(attrs_size);
    InitializeProcThreadAttributeList(attrs, 1, 0, &attrs_size);
    UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                              inherit, sizeof(inherit), NULL, NULL);
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = rd;
    si.StartupInfo.hStdOutput = ack_wr;
    si.lpAttributeList = attrs;

    /* out of a job that would kill it with us, when the job allows it */
    ok = CreateProcessW((wchar_t *)wexe, NULL, NULL, NULL, TRUE,
                        flags | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL,
                        &si.StartupInfo, &pi);
    if (!ok) {
        ok = CreateProcessW((wchar_t *)wexe, NULL, NULL, NULL, TRUE, flags,
                            NULL, NULL, &si.StartupInfo, &pi);
    }
    DeleteProcThreadAttributeList(attrs);
    g_free(attrs);
    CloseHandle(rd);
    CloseHandle(ack_wr);    /* the guard's end: its exit ends our reads */
    if (!ok) {
        CloseHandle(wr);
        CloseHandle(ack_rd);
        return false;
    }
    CloseHandle(pi.hThread);
    guard_process = pi.hProcess;
    guard_pipe = wr;
    guard_ack = ack_rd;
    return true;
}

static bool guard_start(void)
{
    wchar_t wpath[MAX_PATH];
    g_autofree char *self = NULL, *dir = NULL, *here = NULL, *helper = NULL;

    /*
     * Where it is: QEMU_MEMFD_GUARD, next to the program, or in libexec
     * under the prefix (bindir is the prefix on Windows)
     */
    DWORD len;

    if (guard_process || guard_tried) {
        return guard_process != NULL;
    }
    guard_tried = true;
    len = GetModuleFileNameW(NULL, wpath, MAX_PATH);
    if (len && len < MAX_PATH) {
        self = g_utf16_to_utf8(wpath, len, NULL, NULL, NULL);
        dir = self ? g_path_get_dirname(self) : NULL;
        if (dir) {
            here = g_build_filename(dir, "qemu-memfd-guard.exe", NULL);
            helper = g_build_filename(dir, "libexec", "qemu-memfd-guard.exe",
                                      NULL);
        }
    }
    if (guard_start_from(getenv("QEMU_MEMFD_GUARD")) ||
        guard_start_from(here) || guard_start_from(helper)) {
        return true;
    }
    warn_report_once("memfd: qemu-memfd-guard not found: the seals hold "
                     "while this process holds the memfd");
    return false;
}

/* Give the guard a duplicate of @h (the same file object) and @seals */
static void guard_send(HANDLE h, uint32_t seals)
{
    struct {
        uint64_t handle;
        uint32_t seals;
        uint32_t pad;
    } m = { 0 };
    HANDLE dup;
    DWORD n;

    if (!guard_start()) {
        return;
    }
    if (!DuplicateHandle(GetCurrentProcess(), h, guard_process, &dup, 0,
                         FALSE, DUPLICATE_SAME_ACCESS)) {
        return;
    }
    m.handle = (uint64_t)(uintptr_t)dup;
    m.seals = seals;
    if (!WriteFile(guard_pipe, &m, sizeof(m), &n, NULL) || n != sizeof(m)) {
        /* the guard is gone: close what it would have kept */
        DuplicateHandle(guard_process, dup, NULL, NULL, 0, FALSE,
                        DUPLICATE_CLOSE_SOURCE);
        return;
    }
    /*
     * Wait until it holds it: then the seals hold whatever we do next
     * (close at once, end); a dead guard ends the read
     */
    {
        char ack;

        ReadFile(guard_ack, &ack, 1, &n, NULL);
    }
}

static void keeper_free(SealKeeper *k)
{
    if (k->section) {
        CloseHandle(k->section);
    }
    g_free(k);
}

/*
 * The kernel side of @seals for descriptor @fd (handle @h) of this
 * process: locks on its file object (never released: they go with the
 * file object), a section kept while @fd is open.  Called with seal_lock.
 */
static void enforce(int fd, HANDLE h, uint32_t seals)
{
    SealKeeper *k;

    if (seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) {
        lock_range(h, 0);
    } else if (seals & F_SEAL_GROW) {
        int64_t size = file_size(h);

        if (size >= 0) {
            lock_range(h, size);
        }
    }
    /* past the life of this process */
    guard_send(h, seals);
    /* every descriptor of a sealed memfd: close() tells the guards */
    k = find_keeper(fd);
    if (!k) {
        k = g_new0(SealKeeper, 1);
        k->fd = fd;
        file_id(h, &k->volume, &k->index);
        QLIST_INSERT_HEAD(&keepers, k, next);
    }
    if ((seals & F_SEAL_SHRINK) && file_size(h) > 0) {
        if (!k->section) {
            k->section = CreateFileMappingW(h, NULL, PAGE_READONLY, 0, 0,
                                            NULL);
        }
    }
}

void qemu_memfd_win32_received(int fd)
{
    HANDLE h = fd_handle(fd);
    int seals;

    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    seals = read_seals(h);
    if (seals <= 0) {
        return;
    }
    AcquireSRWLockExclusive(&seal_lock);
    enforce(fd, h, seals);
    ReleaseSRWLockExclusive(&seal_lock);
}

int qemu_memfd_get_seals(int fd)
{
    HANDLE h = fd_handle(fd);
    int seals;

    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    seals = read_seals(h);
    if (seals < 0) {
        errno = EINVAL;
        return -1;
    }
    return seals;
}

int qemu_memfd_add_seals(int fd, unsigned int seals)
{
    HANDLE h = fd_handle(fd);
    uint64_t volume, index;
    SealView *v;
    int cur, ret = 0;

    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    if (seals & ~SEALS_ALL) {
        errno = EINVAL;
        return -1;
    }
    cur = read_seals(h);
    if (cur < 0 || !file_id(h, &volume, &index)) {
        errno = EINVAL;
        return -1;
    }
    if (!handle_writable(h) || (cur & F_SEAL_SEAL)) {
        errno = EPERM;
        return -1;
    }

    AcquireSRWLockExclusive(&seal_lock);
    if ((seals & F_SEAL_WRITE) && !(cur & F_SEAL_WRITE)) {
        /* shared writable mappings must be gone */
        QLIST_FOREACH(v, &views, next) {
            if (v->volume == volume && v->index == index) {
                errno = EBUSY;
                ret = -1;
                goto out;
            }
        }
    }
    if (!write_seals(h, cur | seals)) {
        errno = EIO;
        ret = -1;
        goto out;
    }
    enforce(fd, h, cur | seals);
out:
    ReleaseSRWLockExclusive(&seal_lock);
    return ret;
}

int qemu_memfd_win32_map_check(HANDLE file, int prot, int flags)
{
    int seals = read_seals(file);

    if (seals > 0 && (prot & PROT_WRITE) && (flags & MAP_SHARED) &&
        (seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

void qemu_memfd_win32_mapped(HANDLE file, void *addr)
{
    SealView *v;
    uint64_t volume, index;

    if (read_seals(file) < 0 || !file_id(file, &volume, &index)) {
        return;
    }
    v = g_new0(SealView, 1);
    v->addr = addr;
    v->volume = volume;
    v->index = index;
    AcquireSRWLockExclusive(&seal_lock);
    QLIST_INSERT_HEAD(&views, v, next);
    ReleaseSRWLockExclusive(&seal_lock);
}

void qemu_memfd_win32_unmapped(void *addr)
{
    SealView *v, *tmp;

    AcquireSRWLockExclusive(&seal_lock);
    QLIST_FOREACH_SAFE(v, &views, next, tmp) {
        if (v->addr == addr) {
            QLIST_REMOVE(v, next);
            g_free(v);
            break;
        }
    }
    ReleaseSRWLockExclusive(&seal_lock);
}

int qemu_memfd_win32_truncate_check(HANDLE file, int64_t length)
{
    int seals = read_seals(file);
    int64_t size;

    if (seals <= 0) {
        return 0;
    }
    size = file_size(file);
    if ((length < size && (seals & F_SEAL_SHRINK)) ||
        (length > size && (seals & F_SEAL_GROW))) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

HANDLE qemu_memfd_win32_close(int fd)
{
    SealKeeper *k, *tmp;
    HANDLE ev = NULL;

    if (QLIST_EMPTY(&keepers)) {
        return NULL;
    }
    AcquireSRWLockExclusive(&seal_lock);
    QLIST_FOREACH_SAFE(k, &keepers, next, tmp) {
        if (k->fd == fd) {
            wchar_t name[64];

            /*
             * The event of the guards of this memfd (qemu-memfd-guard):
             * set after the close, it wakes them to see whether it was the
             * last descriptor
             */
            if (!ev) {
                swprintf(name, 64, L"Local\\qemu-memfd-%08llx-%016llx",
                         (unsigned long long)k->volume,
                         (unsigned long long)k->index);
                ev = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
            }
            QLIST_REMOVE(k, next);
            keeper_free(k);
        }
    }
    ReleaseSRWLockExclusive(&seal_lock);
    return ev;
}

int memfd_create(const char *name, unsigned int flags)
{
    int fd;

    if (flags & ~(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB)) {
        errno = EINVAL;
        return -1;
    }
    if (flags & MFD_HUGETLB) {
        errno = EINVAL;
        return -1;
    }
    fd = qemu_shm_alloc(0, NULL);
    if (fd < 0) {
        errno = ENOMEM;
        return -1;
    }
    /* as Linux: without MFD_ALLOW_SEALING, sealing is sealed */
    if (!write_seals(fd_handle(fd),
                     (flags & MFD_ALLOW_SEALING) ? 0 : F_SEAL_SEAL)) {
        close(fd);
        errno = EIO;
        return -1;
    }
    return fd;
}

int qemu_memfd_create(const char *name, size_t size, bool hugetlb,
                      uint64_t hugetlbsize, unsigned int seals, Error **errp)
{
    int mfd;

    if (hugetlb) {
        error_setg(errp, "memfd: huge pages are not supported on Windows");
        return -1;
    }
    mfd = memfd_create(name, seals ? MFD_ALLOW_SEALING : 0);
    if (mfd < 0) {
        error_setg_errno(errp, errno, "failed to create memfd");
        return -1;
    }
    if (qemu_ftruncate64(mfd, size) == -1) {
        error_setg_errno(errp, errno, "failed to resize memfd to %zu", size);
        close(mfd);
        return -1;
    }
    if (seals && qemu_memfd_add_seals(mfd, seals) == -1) {
        error_setg_errno(errp, errno, "failed to add seals 0x%x", seals);
        close(mfd);
        return -1;
    }
    return mfd;
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
    /* no huge pages; sealing and close on exec are fine */
    return !(flags & MFD_HUGETLB);
}
