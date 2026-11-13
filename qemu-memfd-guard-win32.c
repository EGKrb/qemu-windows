/*
 * qemu-memfd-guard: keeps the seals of memfds on Windows
 *
 * Linux enforces the seals of a memfd in the kernel, for as long as the
 * memfd exists, whatever process sealed it.  Windows enforces them through
 * byte-range locks and sections (util/memfd-win32.c), which belong to a
 * process: they go when it exits.  A process that seals (or receives) a
 * memfd starts this guard once and gives it a duplicate of each sealed
 * memfd over a pipe, with the seals; the guard opens the file again (its
 * own open: it does not keep the memfd's descriptors alive), locks and
 * maps it, so the seals hold after the process that sealed is gone.
 *
 * The end of a memfd: it is created delete-on-close, so when the last
 * descriptor of the memfd is closed, in any process, Windows marks the file
 * delete pending (its name is gone at once, as on Linux).  The guard then
 * closes its open and the file goes.  Being told at once: each memfd has
 * a named event Local\qemu-memfd-<volume>-<index>, which close() of QEMU
 * sets after closing a sealed memfd, and which a guard sets for all its
 * memfds when its parent ends (its pipe closes); guards wait on it in the
 * thread pool.  A program that is not QEMU closes without telling: a check
 * every 100 ms catches that (Windows gives no notice of the last close of
 * a locked file: oplocks, the only such notice, cannot be held on a file
 * with byte-range locks).
 *
 * Messages on the pipe (standard input): { uint64 handle in the guard,
 * uint32 seals, uint32 0 }; the guard answers each with one byte on its
 * standard output once it holds the memfd: the process that seals goes on
 * then, so the seals hold even if it ends at once.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define F_SEAL_SHRINK       0x0002
#define F_SEAL_GROW         0x0004
#define F_SEAL_WRITE        0x0008
#define F_SEAL_FUTURE_WRITE 0x0010

#define POLL_MS 100

typedef struct {
    uint64_t handle;
    uint32_t seals;
    uint32_t pad;
} GuardMsg;

typedef struct Guarded {
    HANDLE file;            /* our own open of the memfd's file */
    HANDLE section;
    HANDLE event;           /* Local\qemu-memfd-<volume>-<index> */
    HANDLE wait;
    uint64_t volume, index;
    uint32_t seals;
    bool released;
    struct Guarded *next;
} Guarded;

static CRITICAL_SECTION lock;
static Guarded *guarded;
static volatile LONG parent_gone;

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

/* Every last descriptor of the memfd closed: Windows deletes it */
static bool ended(Guarded *g)
{
    FILE_STANDARD_INFO si;

    return !GetFileInformationByHandleEx(g->file, FileStandardInfo, &si,
                                         sizeof(si)) || si.DeletePending;
}

/* Let @g go (with the lock held): the file goes with our open */
static void release(Guarded *g)
{
    if (g->released) {
        return;
    }
    g->released = true;
    /* a pending wait is unregistered by the main loop, before freeing */
    if (g->section) {
        CloseHandle(g->section);
        g->section = NULL;
    }
    CloseHandle(g->file);
    g->file = NULL;
}

static void CALLBACK woken(void *opaque, BOOLEAN timeout);

static void watch(Guarded *g)
{
    if (!g->event || !RegisterWaitForSingleObject(&g->wait, g->event, woken,
                                                  g, INFINITE,
                                                  WT_EXECUTEONLYONCE)) {
        g->wait = NULL;
    }
}

/* A process closed a sealed memfd, or ended: is this one over? */
static void CALLBACK woken(void *opaque, BOOLEAN timeout)
{
    Guarded *g = opaque;

    EnterCriticalSection(&lock);
    if (!g->released) {
        /* reset first: a close after it sets the event again */
        ResetEvent(g->event);
        if (g->wait) {
            UnregisterWait(g->wait);
            g->wait = NULL;
        }
        if (ended(g)) {
            release(g);
        } else {
            watch(g);
        }
    }
    LeaveCriticalSection(&lock);
}

static void guard(HANDLE dup, uint32_t seals)
{
    BY_HANDLE_FILE_INFORMATION info;
    wchar_t name[64];
    Guarded *g;
    HANDLE h;

    /* our own open: the memfd's descriptors end without us */
    h = ReOpenFile(dup, GENERIC_READ,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);
    CloseHandle(dup);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    if (!GetFileInformationByHandle(h, &info)) {
        CloseHandle(h);
        return;
    }

    EnterCriticalSection(&lock);
    for (g = guarded; g; g = g->next) {
        if (!g->released && g->volume == info.dwVolumeSerialNumber &&
            g->index == ((uint64_t)info.nFileIndexHigh << 32 |
                         info.nFileIndexLow)) {
            /* a memfd we hold already: more seals perhaps */
            CloseHandle(h);
            enforce(g, seals);
            /* the duplicate we closed may have been its last descriptor */
            if (g->event) {
                SetEvent(g->event);
            }
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
    g->volume = info.dwVolumeSerialNumber;
    g->index = (uint64_t)info.nFileIndexHigh << 32 | info.nFileIndexLow;
    swprintf(name, 64, L"Local\\qemu-memfd-%08llx-%016llx",
             (unsigned long long)g->volume, (unsigned long long)g->index);
    g->event = CreateEventW(NULL, TRUE, FALSE, name);
    enforce(g, seals);
    g->next = guarded;
    guarded = g;
    /*
     * The duplicate we closed may have been the last descriptor of the
     * memfd: tell the other guards of it (we look ourselves just below)
     */
    if (g->event) {
        SetEvent(g->event);
    }
    if (ended(g)) {
        release(g);
    } else {
        watch(g);
    }
    LeaveCriticalSection(&lock);
}

/* The pipe from the parent: memfds to guard, then its end */
static DWORD WINAPI reader(void *opaque)
{
    HANDLE in = opaque;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    GuardMsg m;
    DWORD n;
    Guarded *g;
    char ack = 1;

    while (ReadFile(in, &m, sizeof(m), &n, NULL) && n == sizeof(m)) {
        guard((HANDLE)(uintptr_t)m.handle, m.seals);
        /* held: the parent may go on */
        WriteFile(out, &ack, 1, &n, NULL);
    }
    /*
     * The parent ended: its descriptors are closed now, without close() of
     * QEMU: wake every guard of its memfds (us included)
     */
    InterlockedExchange(&parent_gone, 1);
    EnterCriticalSection(&lock);
    for (g = guarded; g; g = g->next) {
        if (!g->released && g->event) {
            SetEvent(g->event);
        }
    }
    LeaveCriticalSection(&lock);
    return 0;
}

int main(void)
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE t;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (in == NULL || in == INVALID_HANDLE_VALUE) {
        return 1;
    }
    InitializeCriticalSection(&lock);
    t = CreateThread(NULL, 0, reader, in, 0, NULL);
    if (!t) {
        return 1;
    }
    CloseHandle(t);

    for (;;) {
        Guarded **pp, *g, *done = NULL;
        bool empty;

        Sleep(POLL_MS);
        EnterCriticalSection(&lock);
        for (pp = &guarded; (g = *pp);) {
            /* programs that are not QEMU close without telling us */
            if (!g->released && ended(g)) {
                release(g);
            }
            if (g->released) {
                *pp = g->next;
                g->next = done;
                done = g;
            } else {
                pp = &g->next;
            }
        }
        empty = guarded == NULL;
        LeaveCriticalSection(&lock);
        /* out of the lock: a callback in progress may want it */
        while ((g = done)) {
            done = g->next;
            if (g->wait) {
                UnregisterWaitEx(g->wait, INVALID_HANDLE_VALUE);
            }
            if (g->event) {
                CloseHandle(g->event);
            }
            free(g);
        }
        if (empty && parent_gone) {
            return 0;
        }
    }
}
