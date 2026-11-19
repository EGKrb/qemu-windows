/*
 * linux-user on Windows: threads (clone), futex, the end of threads
 *
 * A thread of the guest is a thread of Windows with a vCPU of its own
 * (cpu_copy), as linux-user does with pthreads.  Its TID is the ID of the
 * Windows thread; the first thread's is the PID, as on Linux.  Futexes
 * are queues of waiters keyed by the guest address, under one lock that
 * the value is checked under.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/rcu.h"
#include "qemu/queue.h"
#include "qemu/timer.h"
#include "exec/cpu-common.h"
#include "exec/tb-flush.h"
#include "exec/translation-block.h"
#include "tcg/startup.h"
#include "user/cpu_loop.h"
#include "user/guest-host.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "win32-user.h"

#define LX_CLONE_VM             0x00000100
#define LX_CLONE_FS             0x00000200
#define LX_CLONE_FILES          0x00000400
#define LX_CLONE_SIGHAND        0x00000800
#define LX_CLONE_VFORK          0x00004000
#define LX_CLONE_THREAD         0x00010000
#define LX_CLONE_SYSVSEM        0x00040000
#define LX_CLONE_SETTLS         0x00080000
#define LX_CLONE_PARENT_SETTID  0x00100000
#define LX_CLONE_CHILD_CLEARTID 0x00200000
#define LX_CLONE_CHILD_SETTID   0x01000000

#define LX_FUTEX_WAIT           0
#define LX_FUTEX_WAKE           1
#define LX_FUTEX_REQUEUE        3
#define LX_FUTEX_CMP_REQUEUE    4
#define LX_FUTEX_WAKE_OP        5
#define LX_FUTEX_WAIT_BITSET    9
#define LX_FUTEX_WAKE_BITSET    10
#define LX_FUTEX_CLOCK_REALTIME 256
#define LX_FUTEX_CMD_MASK       0x7f

const char *w32u_cpu_type;
static __thread abi_long thread_tid;            /* 0: the first thread */
static __thread abi_ulong clear_child_tid;
static int nthreads = 1;
static QemuMutex clone_lock;

abi_long w32u_gettid(void)
{
    return thread_tid ? thread_tid : GetCurrentProcessId();
}

abi_long w32u_set_tid_address(abi_ulong addr)
{
    clear_child_tid = addr;
    return w32u_gettid();
}

/* ---- futex --------------------------------------------------------- */

typedef struct FutexWaiter {
    abi_ulong addr;
    uint32_t bitset;
    CONDITION_VARIABLE cv;
    bool woken;
    QTAILQ_ENTRY(FutexWaiter) next;
} FutexWaiter;

static SRWLOCK futex_lock = SRWLOCK_INIT;
static QTAILQ_HEAD(, FutexWaiter) futex_waiters =
    QTAILQ_HEAD_INITIALIZER(futex_waiters);

static uint32_t *futex_word(abi_ulong addr, int prot)
{
    if ((addr & 3) || !guest_range_valid_untagged(addr, 4) ||
        !page_check_range(addr, 4, prot)) {
        return NULL;
    }
    return g2h_untagged(addr);
}

/* wake up to @n waiters on @addr with a bit of @bitset; lock held */
static int futex_wake_locked(abi_ulong addr, int n, uint32_t bitset)
{
    FutexWaiter *w, *next;
    int woken = 0;

    QTAILQ_FOREACH_SAFE(w, &futex_waiters, next, next) {
        if (woken >= n) {
            break;
        }
        if (w->addr == addr && (w->bitset & bitset)) {
            QTAILQ_REMOVE(&futex_waiters, w, next);
            w->woken = true;
            WakeConditionVariable(&w->cv);
            woken++;
        }
    }
    return woken;
}

int w32u_futex_wake(abi_ulong addr, int n)
{
    int r;

    AcquireSRWLockExclusive(&futex_lock);
    r = futex_wake_locked(addr, n, ~0u);
    ReleaseSRWLockExclusive(&futex_lock);
    return r;
}

static int64_t clock_now_ns(bool realtime)
{
    return realtime ? g_get_real_time() * 1000 :
                      get_clock();
}

/* a struct timespec of the guest */
static abi_long read_timespec(abi_ulong addr, int64_t *ns)
{
    int64_t *ts;

    if (!guest_range_valid_untagged(addr, 16) ||
        !page_check_range(addr, 16, PAGE_READ)) {
        return -LX_EFAULT;
    }
    ts = g2h_untagged(addr);
    if (ts[0] < 0 || ts[1] < 0 || ts[1] >= NANOSECONDS_PER_SECOND) {
        return -LX_EINVAL;
    }
    *ns = ts[0] * NANOSECONDS_PER_SECOND + ts[1];
    return 0;
}

static abi_long futex_wait(abi_ulong addr, uint32_t val, abi_ulong timeout,
                           uint32_t bitset, bool absolute, bool realtime)
{
    uint32_t *p = futex_word(addr, PAGE_READ);
    int64_t deadline = -1, ns;
    FutexWaiter w = { .addr = addr, .bitset = bitset };
    abi_long ret = 0;

    if (!p) {
        return -LX_EFAULT;
    }
    if (!bitset) {
        return -LX_EINVAL;
    }
    if (timeout) {
        ret = read_timespec(timeout, &ns);
        if (ret) {
            return ret;
        }
        deadline = absolute ? ns : clock_now_ns(realtime) + ns;
    }
    InitializeConditionVariable(&w.cv);
    AcquireSRWLockExclusive(&futex_lock);
    if (qatomic_read(p) != val) {
        ReleaseSRWLockExclusive(&futex_lock);
        return -LX_EAGAIN;
    }
    QTAILQ_INSERT_TAIL(&futex_waiters, &w, next);
    while (!w.woken) {
        DWORD ms = INFINITE;

        if (deadline >= 0) {
            int64_t left = deadline - clock_now_ns(realtime);

            if (left <= 0) {
                ret = -LX_ETIMEDOUT;
                break;
            }
            ms = MIN(DIV_ROUND_UP(left, 1000000), 0x7fffffff);
        }
        if (w32u_signal_pending()) {
            ret = -LX_EINTR;
            break;
        }
        /* a signal does not wake us: look at it now and then */
        SleepConditionVariableSRW(&w.cv, &futex_lock, MIN(ms, 50), 0);
    }
    if (!w.woken) {
        QTAILQ_REMOVE(&futex_waiters, &w, next);
    } else {
        ret = 0;
    }
    ReleaseSRWLockExclusive(&futex_lock);
    return ret;
}

/* FUTEX_WAKE_OP: *uaddr2 changes, then waiters of both may wake */
static abi_long futex_wake_op(abi_ulong uaddr, int n, int n2,
                              abi_ulong uaddr2, uint32_t val3)
{
    uint32_t *p2 = futex_word(uaddr2, PAGE_READ | PAGE_WRITE);
    int op = (val3 >> 28) & 7, cmp = (val3 >> 24) & 15;
    uint32_t oparg = (val3 >> 12) & 0xfff, cmparg = val3 & 0xfff;
    uint32_t old, new;
    bool hit;
    int r;

    if (!p2) {
        return -LX_EFAULT;
    }
    if (val3 & (8u << 28)) {
        oparg = 1u << oparg;
    }
    AcquireSRWLockExclusive(&futex_lock);
    do {
        old = qatomic_read(p2);
        switch (op) {
        case 0:
            new = oparg;
            break;
        case 1:
            new = old + oparg;
            break;
        case 2:
            new = old | oparg;
            break;
        case 3:
            new = old & ~oparg;
            break;
        case 4:
            new = old ^ oparg;
            break;
        default:
            ReleaseSRWLockExclusive(&futex_lock);
            return -LX_ENOSYS;
        }
    } while (qatomic_cmpxchg(p2, old, new) != old);
    switch (cmp) {
    case 0:
        hit = old == cmparg;
        break;
    case 1:
        hit = old != cmparg;
        break;
    case 2:
        hit = (int32_t)old < (int32_t)cmparg;
        break;
    case 3:
        hit = (int32_t)old <= (int32_t)cmparg;
        break;
    case 4:
        hit = (int32_t)old > (int32_t)cmparg;
        break;
    case 5:
        hit = (int32_t)old >= (int32_t)cmparg;
        break;
    default:
        ReleaseSRWLockExclusive(&futex_lock);
        return -LX_ENOSYS;
    }
    r = futex_wake_locked(uaddr, n, ~0u);
    if (hit) {
        r += futex_wake_locked(uaddr2, n2, ~0u);
    }
    ReleaseSRWLockExclusive(&futex_lock);
    return r;
}

abi_long w32u_futex(abi_ulong uaddr, int op, uint32_t val, abi_ulong timeout,
                    abi_ulong uaddr2, uint32_t val3)
{
    bool realtime = op & LX_FUTEX_CLOCK_REALTIME;
    FutexWaiter *w, *next;
    uint32_t *p;
    int woken, moved;

    switch (op & LX_FUTEX_CMD_MASK) {
    case LX_FUTEX_WAIT:
        return futex_wait(uaddr, val, timeout, ~0u, false, realtime);
    case LX_FUTEX_WAIT_BITSET:
        return futex_wait(uaddr, val, timeout, val3, true, realtime);
    case LX_FUTEX_WAKE:
        return w32u_futex_wake(uaddr, (int)val);
    case LX_FUTEX_WAKE_BITSET:
        if (!val3) {
            return -LX_EINVAL;
        }
        AcquireSRWLockExclusive(&futex_lock);
        woken = futex_wake_locked(uaddr, (int)val, val3);
        ReleaseSRWLockExclusive(&futex_lock);
        return woken;
    case LX_FUTEX_REQUEUE:
    case LX_FUTEX_CMP_REQUEUE:
        /* timeout is the number of waiters to move here */
        p = futex_word(uaddr, PAGE_READ);
        if (!p) {
            return -LX_EFAULT;
        }
        AcquireSRWLockExclusive(&futex_lock);
        if ((op & LX_FUTEX_CMD_MASK) == LX_FUTEX_CMP_REQUEUE &&
            qatomic_read(p) != val3) {
            ReleaseSRWLockExclusive(&futex_lock);
            return -LX_EAGAIN;
        }
        woken = futex_wake_locked(uaddr, (int)val, ~0u);
        moved = 0;
        QTAILQ_FOREACH_SAFE(w, &futex_waiters, next, next) {
            if (moved >= (int)timeout) {
                break;
            }
            if (w->addr == uaddr) {
                w->addr = uaddr2;
                moved++;
            }
        }
        ReleaseSRWLockExclusive(&futex_lock);
        return woken + moved;
    case LX_FUTEX_WAKE_OP:
        return futex_wake_op(uaddr, (int)val, (int)timeout, uaddr2, val3);
    default:
        return -LX_ENOSYS;
    }
}

/* ---- threads -------------------------------------------------------- */

static CPUArchState *cpu_copy(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    CPUState *new_cpu = cpu_create(w32u_cpu_type);
    CPUArchState *new_env = cpu_env(new_cpu);

    cpu_reset(new_cpu);
    new_cpu->tcg_cflags = cpu->tcg_cflags;
    memcpy(new_env, env, sizeof(CPUArchState));
    QTAILQ_INIT(&new_cpu->breakpoints);
    return new_env;
}

typedef struct NewThread {
    CPUArchState *env;
    abi_ulong clear_tid;
    abi_long tid;
} NewThread;

static DWORD WINAPI thread_main(void *opaque)
{
    NewThread *t = opaque;
    CPUArchState *env = t->env;

    rcu_register_thread();
    tcg_register_thread();
    thread_cpu = env_cpu(env);
    thread_tid = t->tid;
    clear_child_tid = t->clear_tid;
    g_free(t);
    /* the parent finished setting up the thread */
    qemu_mutex_lock(&clone_lock);
    qemu_mutex_unlock(&clone_lock);
    cpu_loop(env);
    return 0;
}

static void put_u32(abi_ulong addr, uint32_t v)
{
    if (addr && guest_range_valid_untagged(addr, 4) &&
        page_check_range(addr, 4, PAGE_WRITE)) {
        qatomic_set((uint32_t *)g2h_untagged(addr), v);
    }
}

abi_long w32u_clone_thread(CPUArchState *env, uint64_t flags,
                           abi_ulong newsp, abi_ulong ptid, abi_ulong ctid,
                           abi_ulong tls)
{
    const uint64_t thread = LX_CLONE_VM | LX_CLONE_FS | LX_CLONE_FILES |
                            LX_CLONE_SIGHAND | LX_CLONE_THREAD;
    CPUState *cpu = env_cpu(env);
    CPUArchState *new_env;
    NewThread *t;
    HANDLE h;
    DWORD id;

    if ((flags & thread) != thread) {
        return -LX_EINVAL;
    }
    qemu_mutex_lock(&clone_lock);
    /* the first other thread: code for parallel execution from now on */
    if (!tcg_cflags_has(cpu, CF_PARALLEL)) {
        tb_flush__exclusive_or_serial();
        tcg_cflags_set(cpu, CF_PARALLEL);
    }
    new_env = cpu_copy(env);
    w32u_clone_regs(new_env, newsp, flags & LX_CLONE_SETTLS, tls);

    t = g_new0(NewThread, 1);
    t->env = new_env;
    if (flags & LX_CLONE_CHILD_CLEARTID) {
        t->clear_tid = ctid;
    }
    /* the host stack of TCG code: as large as linux-user's default */
    h = CreateThread(NULL, 8 * 1024 * 1024, thread_main, t,
                     CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION,
                     &id);
    if (!h) {
        qemu_mutex_unlock(&clone_lock);
        object_unparent(OBJECT(env_cpu(new_env)));
        object_unref(OBJECT(env_cpu(new_env)));
        g_free(t);
        return -LX_EAGAIN;
    }
    t->tid = id;
    if (flags & LX_CLONE_PARENT_SETTID) {
        put_u32(ptid, id);
    }
    if (flags & LX_CLONE_CHILD_SETTID) {
        put_u32(ctid, id);
    }
    qatomic_inc(&nthreads);
    ResumeThread(h);
    CloseHandle(h);
    qemu_mutex_unlock(&clone_lock);
    return id;
}

/* exit: the thread ends; the process with its last thread */
G_NORETURN void w32u_exit_thread(int status)
{
    CPUState *cpu = thread_cpu;

    qemu_mutex_lock(&clone_lock);
    if (qatomic_read(&nthreads) == 1) {
        qemu_mutex_unlock(&clone_lock);
        fflush(NULL);
        exit(status & 0xff);
    }
    qatomic_dec(&nthreads);
    if (clear_child_tid) {
        put_u32(clear_child_tid, 0);
        w32u_futex_wake(clear_child_tid, INT_MAX);
    }
    object_unparent(OBJECT(cpu));
    object_unref(OBJECT(cpu));
    qemu_mutex_unlock(&clone_lock);
    thread_cpu = NULL;
    rcu_unregister_thread();
    ExitThread(0);
}

void w32u_thread_init(void)
{
    qemu_mutex_init(&clone_lock);
}
