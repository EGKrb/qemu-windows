/*
 * Native Win32 linux-user prototype: guest address space
 *
 * The whole guest address space (reserved_va) is reserved at startup with
 * VirtualAlloc(MEM_RESERVE).  Guest mappings commit pages inside it at the
 * 4 KiB page granularity of VirtualAlloc/VirtualProtect; only reservations
 * and file views are 64 KiB grained on Windows, and we use neither per
 * mapping.  File-backed mappings are private copies (MAP_SHARED of a file
 * is not supported yet).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/error-report.h"
#include "exec/mmap-lock.h"
#include "exec/page-protection.h"
#include "user/guest-base.h"
#include "user/guest-host.h"
#include "user/page-protection.h"
#include "user/mmap.h"
#include "win32-user.h"

uintptr_t guest_base;
bool have_guest_base;
uintptr_t reserved_va;
uintptr_t guest_addr_max;
abi_ulong mmap_next_start;

static QemuMutex mmap_mutex;
static __thread int mmap_lock_count;

static abi_ulong initial_brk, target_brk, brk_page;

void mmap_lock(void)
{
    if (mmap_lock_count++ == 0) {
        qemu_mutex_lock(&mmap_mutex);
    }
}

void mmap_unlock(void)
{
    assert(mmap_lock_count > 0);
    if (--mmap_lock_count == 0) {
        qemu_mutex_unlock(&mmap_mutex);
    }
}

bool have_mmap_lock(void)
{
    return mmap_lock_count > 0;
}

/* Guest code never runs natively: PROT_EXEC needs no host permission */
static DWORD host_prot(int prot)
{
    if (prot & PROT_WRITE) {
        return PAGE_READWRITE;
    }
    if (prot & (PROT_READ | PROT_EXEC)) {
        return PAGE_READONLY;
    }
    return PAGE_NOACCESS;
}

/* Replace [host, host + len) by fresh zeroed pages */
static bool commit_zero(void *host, size_t len, int prot)
{
    VirtualFree(host, len, MEM_DECOMMIT);
    if (prot == PROT_NONE) {
        /* reserved but uncommitted: any access faults, contents are zero */
        return true;
    }
    return VirtualAlloc(host, len, MEM_COMMIT, host_prot(prot)) != NULL;
}

/*
 * POSIX API used by the user-mode core (accel/tcg/user-exec.c write-protects
 * translated code pages with mprotect).  Committed pages keep their contents,
 * uncommitted ones are committed (zeroed) when they become accessible.
 */
int mprotect(void *addr, size_t len, int prot)
{
    uintptr_t p = (uintptr_t)addr, end = p + len;

    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t run_end;
        DWORD old;

        if (!VirtualQuery((void *)p, &mbi, sizeof(mbi))) {
            errno = ENOMEM;
            return -1;
        }
        run_end = MIN(end, (uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        if (mbi.State == MEM_COMMIT) {
            if (!VirtualProtect((void *)p, run_end - p, host_prot(prot), &old)) {
                errno = EACCES;
                return -1;
            }
        } else if (mbi.State == MEM_RESERVE && prot != PROT_NONE) {
            if (!VirtualAlloc((void *)p, run_end - p, MEM_COMMIT,
                              host_prot(prot))) {
                errno = ENOMEM;
                return -1;
            }
        } else if (mbi.State == MEM_FREE) {
            errno = ENOMEM;
            return -1;
        }
        p = run_end;
    }
    return 0;
}

static bool in_guest_space(const void *host, size_t len)
{
    uintptr_t p = (uintptr_t)host;

    return p >= guest_base && p + len <= guest_base + reserved_va + 1;
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
    void *p;

    if (!(flags & MAP_ANONYMOUS) || fd != -1) {
        errno = ENOSYS;
        return MAP_FAILED;
    }
    if (flags & MAP_FIXED) {
        if (!in_guest_space(addr, len) || !commit_zero(addr, len, prot)) {
            errno = ENOMEM;
            return MAP_FAILED;
        }
        return addr;
    }
    p = VirtualAlloc(NULL, len, MEM_RESERVE | MEM_COMMIT, host_prot(prot));
    if (!p) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    return p;
}

int munmap(void *addr, size_t len)
{
    if (in_guest_space(addr, len)) {
        VirtualFree(addr, len, MEM_DECOMMIT);
        return 0;
    }
    if (!VirtualFree(addr, 0, MEM_RELEASE)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

void w32u_mem_init(void)
{
    void *base;

    qemu_mutex_init(&mmap_mutex);
    base = VirtualAlloc(NULL, W32U_GUEST_SPACE, MEM_RESERVE, PAGE_NOACCESS);
    if (!base) {
        error_report("cannot reserve %llu GiB for the guest address space",
                     W32U_GUEST_SPACE >> 30);
        exit(EXIT_FAILURE);
    }
    guest_base = (uintptr_t)base;
    have_guest_base = true;
    reserved_va = W32U_GUEST_SPACE - 1;
    guest_addr_max = reserved_va;
    mmap_next_start = W32U_MMAP_BASE;
}

abi_long w32u_mmap(abi_ulong start, abi_ulong len, int prot, int flags,
                   int fd, int64_t offset)
{
    bool anon = flags & MAP_ANONYMOUS;
    abi_ulong addr, last;
    void *host;

    if (len == 0 || (start & ~TARGET_PAGE_MASK) ||
        (!anon && (offset & ~TARGET_PAGE_MASK))) {
        return -LX_EINVAL;
    }
    len = TARGET_PAGE_ALIGN(len);
    if (len == 0) {
        return -LX_ENOMEM;
    }

    mmap_lock();
    if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
        if (!guest_range_valid_untagged(start, len)) {
            mmap_unlock();
            return -LX_ENOMEM;
        }
        if ((flags & MAP_FIXED_NOREPLACE) &&
            !page_check_range_empty(start, start + len - 1)) {
            mmap_unlock();
            return -LX_EEXIST;
        }
        addr = start;
    } else {
        if (start && guest_range_valid_untagged(start, len) &&
            page_check_range_empty(start, start + len - 1)) {
            addr = start;
        } else {
            addr = page_find_range_empty(mmap_next_start, reserved_va,
                                         len, TARGET_PAGE_SIZE);
            if (addr == (abi_ulong)-1) {
                addr = page_find_range_empty(TARGET_PAGE_SIZE, reserved_va,
                                             len, TARGET_PAGE_SIZE);
            }
            if (addr == (abi_ulong)-1) {
                mmap_unlock();
                return -LX_ENOMEM;
            }
            mmap_next_start = addr + len;
        }
    }

    last = addr + len - 1;
    host = g2h_untagged(addr);
    if (!commit_zero(host, len, anon ? prot : PROT_READ | PROT_WRITE)) {
        mmap_unlock();
        return -LX_ENOMEM;
    }
    if (!anon) {
        /* Private copy of the file; past EOF the pages stay zeroed */
        if (w32u_fd_pread(fd, host, len, offset) < 0 ||
            mprotect(host, len, prot) < 0) {
            commit_zero(host, len, PROT_NONE);
            mmap_unlock();
            return -LX_EBADF;
        }
    }
    page_set_flags(addr, last,
                   (prot & PAGE_RWX) | PAGE_VALID | (anon ? PAGE_ANON : 0),
                   PAGE_VALID);
    mmap_unlock();
    return addr;
}

abi_long w32u_munmap(abi_ulong start, abi_ulong len)
{
    if ((start & ~TARGET_PAGE_MASK) || len == 0) {
        return -LX_EINVAL;
    }
    len = TARGET_PAGE_ALIGN(len);
    if (!guest_range_valid_untagged(start, len)) {
        return -LX_EINVAL;
    }
    mmap_lock();
    commit_zero(g2h_untagged(start), len, PROT_NONE);
    page_set_flags(start, start + len - 1, 0, PAGE_VALID);
    mmap_unlock();
    return 0;
}

abi_long w32u_mprotect(abi_ulong start, abi_ulong len, int prot)
{
    abi_ulong last;

    if (start & ~TARGET_PAGE_MASK) {
        return -LX_EINVAL;
    }
    if (len == 0) {
        return 0;
    }
    len = TARGET_PAGE_ALIGN(len);
    last = start + len - 1;
    if (!guest_range_valid_untagged(start, len) ||
        !page_check_range(start, len, PAGE_VALID)) {
        return -LX_ENOMEM;
    }
    mmap_lock();
    if (mprotect(g2h_untagged(start), len, prot) < 0) {
        mmap_unlock();
        return -LX_ENOMEM;
    }
    page_set_flags(start, last, (prot & PAGE_RWX) | PAGE_VALID, PAGE_RWX);
    mmap_unlock();
    return 0;
}

void w32u_set_brk(abi_ulong brk)
{
    initial_brk = target_brk = brk;
    brk_page = TARGET_PAGE_ALIGN(brk);
}

void w32u_mem_get_state(abi_ulong st[4])
{
    st[0] = initial_brk;
    st[1] = target_brk;
    st[2] = brk_page;
    st[3] = mmap_next_start;
}

void w32u_mem_set_state(const abi_ulong st[4])
{
    initial_brk = st[0];
    target_brk = st[1];
    brk_page = st[2];
    mmap_next_start = st[3];
}

abi_ulong w32u_brk(abi_ulong new_brk)
{
    abi_ulong new_page;

    if (new_brk == 0 || new_brk < initial_brk) {
        return target_brk;
    }
    new_page = TARGET_PAGE_ALIGN(new_brk);
    if (new_page > brk_page) {
        abi_long ret;

        if (!page_check_range_empty(brk_page, new_page - 1)) {
            return target_brk;
        }
        ret = w32u_mmap(brk_page, new_page - brk_page, PROT_READ | PROT_WRITE,
                        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ret < 0) {
            return target_brk;
        }
    } else if (new_page < brk_page) {
        w32u_munmap(new_page, brk_page - new_page);
    }
    brk_page = new_page;
    target_brk = new_brk;
    return target_brk;
}
