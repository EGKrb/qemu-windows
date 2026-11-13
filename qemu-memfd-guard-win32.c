/*
 * qemu-memfd-guard: keeps the seals of memfds on Windows
 *
 * Linux enforces the seals of a memfd in the kernel, for as long as the
 * memfd exists, whatever process sealed it.  Windows enforces them through
 * byte-range locks and sections (util/memfd-win32.c), which belong to a
 * process: they go when it exits.  A process that seals (or receives) a
 * memfd starts this guard once and gives it a duplicate of each sealed
 * memfd (the same file object) over a pipe, with the seals; the guard
 * locks and maps it in its turn, so the seals hold after the process that
 * sealed is gone.
 *
 * When to let a memfd go: when nobody but guards has a handle to its file
 * object.  Each guard holds one handle per memfd (a second one given to it
 * is merged into the first) and counts itself in the file, an extended
 * attribute QEMUGUARDS changed under a named mutex: the memfd is free when
 * NtQueryObject's HandleCount is no more than that count.  The memfd then
 * ends as on Linux when its last descriptor is closed.  A guard that is
 * killed leaves the count too high: the others let go a little early,
 * never too late.  A guard exits when its parent is gone and it guards
 * nothing more.
 *
 * Messages on the pipe (standard input): { uint64 handle in the guard,
 * uint32 seals, uint32 0 }.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <windows.h>
#include <winternl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define F_SEAL_SHRINK       0x0002
#define F_SEAL_GROW         0x0004
#define F_SEAL_WRITE        0x0008
#define F_SEAL_FUTURE_WRITE 0x0010

#define GUARDS_EA_NAME "QEMUGUARDS"
#define POLL_MS 250

typedef struct {
    uint64_t handle;
    uint32_t seals;
    uint32_t pad;
} GuardMsg;

typedef struct Guarded {
    HANDLE file;
    HANDLE section;
    uint32_t seals;
    struct Guarded *next;
} Guarded;

/* FILE_FULL_EA_INFORMATION / FILE_GET_EA_INFORMATION of the DDK */
typedef struct {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[sizeof(GUARDS_EA_NAME)];
    int32_t value;
} __attribute__((packed)) CountEa;

typedef struct {
    ULONG NextEntryOffset;
    UCHAR EaNameLength;
    CHAR EaName[sizeof(GUARDS_EA_NAME)];
} __attribute__((packed)) CountEaQuery;

typedef NTSTATUS (NTAPI *NtQueryObjectFn)(HANDLE, OBJECT_INFORMATION_CLASS,
                                          PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtQueryEaFileFn)(HANDLE, PIO_STATUS_BLOCK, PVOID,
                                          ULONG, BOOLEAN, PVOID, ULONG,
                                          PULONG, BOOLEAN);
typedef NTSTATUS (NTAPI *NtSetEaFileFn)(HANDLE, PIO_STATUS_BLOCK, PVOID,
                                        ULONG);
typedef BOOL (WINAPI *CompareObjectHandlesFn)(HANDLE, HANDLE);

static NtQueryObjectFn nt_query_object;
static NtQueryEaFileFn nt_query_ea;
static NtSetEaFileFn nt_set_ea;
static CompareObjectHandlesFn compare_handles;
static HANDLE count_mutex;

static CRITICAL_SECTION lock;
static Guarded *guarded;
static volatile LONG parent_gone;

/* The number of guards that hold the memfd of @h */
static int32_t count_read(HANDLE h)
{
    CountEaQuery q __attribute__((aligned(8))) = { 0 };
    union {
        CountEa ea;
        uint8_t room[128];
    } u __attribute__((aligned(8))) = { 0 };
    IO_STATUS_BLOCK iosb;

    q.EaNameLength = strlen(GUARDS_EA_NAME);
    memcpy(q.EaName, GUARDS_EA_NAME, sizeof(GUARDS_EA_NAME));
    if (nt_query_ea(h, &iosb, &u, sizeof(u), TRUE, &q, sizeof(q), NULL,
                    TRUE) < 0 || u.ea.EaValueLength != sizeof(int32_t)) {
        return 0;
    }
    return u.ea.value;
}

static void count_add(HANDLE h, int32_t delta)
{
    CountEa ea __attribute__((aligned(8))) = { 0 };
    IO_STATUS_BLOCK iosb;
    int32_t n;

    WaitForSingleObject(count_mutex, INFINITE);
    n = count_read(h) + delta;
    ea.EaNameLength = strlen(GUARDS_EA_NAME);
    ea.EaValueLength = sizeof(int32_t);
    memcpy(ea.EaName, GUARDS_EA_NAME, sizeof(GUARDS_EA_NAME));
    ea.value = n > 0 ? n : 0;
    nt_set_ea(h, &iosb, &ea, sizeof(ea));
    ReleaseMutex(count_mutex);
}

static void lock_from(HANDLE h, uint64_t from)
{
    OVERLAPPED ov = { 0 };
    uint64_t len = UINT64_MAX - from;

    ov.Offset = (DWORD)from;
    ov.OffsetHigh = (DWORD)(from >> 32);
    LockFileEx(h, LOCKFILE_FAIL_IMMEDIATELY, 0, (DWORD)len,
               (DWORD)(len >> 32), &ov);
}

/* The seals of @g that it does not enforce yet */
static void enforce(Guarded *g, uint32_t seals)
{
    uint32_t added = seals & ~g->seals;
    LARGE_INTEGER size;

    if (!GetFileSizeEx(g->file, &size)) {
        size.QuadPart = 0;
    }
    if (added & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) {
        lock_from(g->file, 0);
    } else if ((added & F_SEAL_GROW) &&
               !(g->seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))) {
        lock_from(g->file, size.QuadPart);
    }
    if ((seals & F_SEAL_SHRINK) && !g->section && size.QuadPart > 0) {
        g->section = CreateFileMappingW(g->file, NULL, PAGE_READONLY, 0, 0,
                                        NULL);
    }
    g->seals |= seals;
}

static void guard(HANDLE h, uint32_t seals)
{
    Guarded *g;

    EnterCriticalSection(&lock);
    /* a memfd we hold already: one handle per memfd */
    for (g = guarded; g; g = g->next) {
        if (compare_handles && compare_handles(g->file, h)) {
            CloseHandle(h);
            enforce(g, seals);
            LeaveCriticalSection(&lock);
            return;
        }
    }
    g = calloc(1, sizeof(*g));
    if (!g) {
        LeaveCriticalSection(&lock);
        CloseHandle(h);
        return;
    }
    g->file = h;
    count_add(h, 1);
    enforce(g, seals);
    g->next = guarded;
    guarded = g;
    LeaveCriticalSection(&lock);
}

/* The pipe from the parent: memfds to guard, then its end */
static DWORD WINAPI reader(void *opaque)
{
    HANDLE in = opaque;
    GuardMsg m;
    DWORD n;

    while (ReadFile(in, &m, sizeof(m), &n, NULL) && n == sizeof(m)) {
        guard((HANDLE)(uintptr_t)m.handle, m.seals);
    }
    InterlockedExchange(&parent_gone, 1);
    return 0;
}

int main(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE t;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    nt_query_object = (NtQueryObjectFn)(void *)GetProcAddress(ntdll,
                                                              "NtQueryObject");
    nt_query_ea = (NtQueryEaFileFn)(void *)GetProcAddress(ntdll,
                                                          "NtQueryEaFile");
    nt_set_ea = (NtSetEaFileFn)(void *)GetProcAddress(ntdll, "NtSetEaFile");
    compare_handles = (CompareObjectHandlesFn)(void *)GetProcAddress(
        GetModuleHandleW(L"kernelbase.dll"), "CompareObjectHandles");
    count_mutex = CreateMutexW(NULL, FALSE, L"Local\\qemu-memfd-guard-count");
    if (!nt_query_object || !nt_query_ea || !nt_set_ea || !count_mutex ||
        in == NULL || in == INVALID_HANDLE_VALUE) {
        return 1;
    }
    InitializeCriticalSection(&lock);
    t = CreateThread(NULL, 0, reader, in, 0, NULL);
    if (!t) {
        return 1;
    }
    CloseHandle(t);

    for (;;) {
        Guarded **pp, *g;
        bool empty;

        Sleep(POLL_MS);
        EnterCriticalSection(&lock);
        for (pp = &guarded; (g = *pp);) {
            PUBLIC_OBJECT_BASIC_INFORMATION info;
            ULONG len;

            /* only guards hold the memfd: let it end */
            if (nt_query_object(g->file, ObjectBasicInformation, &info,
                                sizeof(info), &len) < 0 ||
                (LONG)info.HandleCount <= count_read(g->file)) {
                *pp = g->next;
                count_add(g->file, -1);
                if (g->section) {
                    CloseHandle(g->section);
                }
                CloseHandle(g->file);      /* its locks go with it */
                free(g);
            } else {
                pp = &g->next;
            }
        }
        empty = guarded == NULL;
        LeaveCriticalSection(&lock);
        if (empty && parent_gone) {
            return 0;
        }
    }
}
