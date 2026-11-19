/*
 * linux-user on Windows: signals
 *
 * The guest's signals are emulated here: Windows has none.
 *
 * - kill() to another guest process: its mailbox, a named section with the
 *   signals pending ("Local\qemu-lu-sig-<pid>") and a named event; a thread
 *   of the receiver takes them and stops the vCPUs (cpu_exit), which then
 *   deliver them (w32u_handle_signals, from cpu_loop).
 * - The actions of Linux: default (end, ignore), ignore, a handler run on a
 *   signal frame of the architecture (cpu_loop-<target>.c), back through
 *   rt_sigreturn.  Masks per thread, sigaltstack, SA_RESTART, SA_NODEFER,
 *   SA_RESETHAND.
 * - Ctrl-C and Ctrl-Break of the console: SIGINT and SIGQUIT; a pipe
 *   without reader: SIGPIPE; the end of a child: SIGCHLD; faults of the
 *   guest: SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP to its handler.
 * - fork keeps the actions; execve keeps the ignored ones and the mask.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "exec/cpu-common.h"
#include "hw/core/cpu.h"
#include "user/guest-host.h"
#include "win32-user.h"

#define SIG_BIT(s)      (1ULL << ((s) - 1))
#define LX_SIG_DFL      0
#define LX_SIG_IGN      1
#define LX_SA_NODEFER   0x40000000
#define LX_SA_RESETHAND 0x80000000
#define LX_SA_RESTART   0x10000000
#define LX_SA_ONSTACK   0x08000000
#define LX_SS_ONSTACK   1
#define LX_SS_DISABLE   2
#define LX_SI_USER      0
#define LX_SI_KERNEL    0x80

W32USigAction w32u_sigact[65];
static SRWLOCK sig_lock = SRWLOCK_INIT;
static uint64_t proc_pending;               /* atomic */
static __thread uint64_t thread_mask, thread_pending;
static __thread W32USigInfo thread_info[65];
static __thread bool suspend_mask_valid;
static __thread uint64_t suspend_old_mask;
static __thread abi_ulong alt_sp, alt_size;
static __thread int alt_flags = LX_SS_DISABLE;
static uint64_t *mailbox;
static HANDLE mailbox_map, mailbox_event, stop_event;
static bool proxy;

/* ---- default actions ------------------------------------------------------ */

static bool default_ignored(int sig)
{
    switch (sig) {
    case 17: case 18: case 23: case 28:     /* CHLD CONT URG WINCH */
    case 19: case 20: case 21: case 22:     /* STOP TSTP TTIN TTOU: no jobs */
        return true;
    }
    return sig >= 32;                       /* real-time ones: end, see below */
}

static bool dumps_core(int sig)
{
    switch (sig) {
    case 3: case 4: case 5: case 6: case 7: case 8: case 11:
    case 24: case 25: case 31:
        return true;
    }
    return false;
}

static G_NORETURN void die(int sig)
{
    if (dumps_core(sig)) {
        w32u_die_with_signal(sig);
    }
    fflush(NULL);
    ExitProcess(w32u_qemu_parent ? 0x40000000 | sig : 128 + sig);
}

/* what @sig does now: 0 nothing, 1 a handler, 2 the end of the process */
static int action_of(int sig)
{
    abi_ulong h = w32u_sigact[sig].handler;

    if (sig == 9) {
        return 2;
    }
    if (h == LX_SIG_IGN) {
        return 0;
    }
    if (h == LX_SIG_DFL) {
        return sig < 32 && default_ignored(sig) ? 0 : 2;
    }
    return 1;
}

/* ---- pending signals ----------------------------------------------------- */

static void kick_cpus(void)
{
    CPUState *cpu;

    /* out of translated code, to cpu_loop and its signals */
    CPU_FOREACH(cpu) {
        cpu_exit(cpu);
    }
}

void w32u_raise_process(int sig)
{
    if (sig < 1 || sig > 64) {
        return;
    }
    if (sig == 9) {
        die(9);
    }
    qatomic_or(&proc_pending, SIG_BIT(sig));
    kick_cpus();
}

void w32u_raise_thread(int sig, int code, abi_ulong addr)
{
    thread_pending |= SIG_BIT(sig);
    thread_info[sig] = (W32USigInfo) { sig, code, addr, 0 };
}

/* a signal deliverable to this thread (blocking calls end with EINTR) */
static int next_signal(bool take)
{
    uint64_t ready = (thread_pending | qatomic_read(&proc_pending)) &
                     ~thread_mask;
    int sig;

    while (ready) {
        sig = ctz64(ready) + 1;
        ready &= ready - 1;
        if (action_of(sig) == 0) {
            /* nothing to do: it goes */
            thread_pending &= ~SIG_BIT(sig);
            qatomic_and(&proc_pending, ~SIG_BIT(sig));
            continue;
        }
        if (take) {
            if (thread_pending & SIG_BIT(sig)) {
                thread_pending &= ~SIG_BIT(sig);
            } else if (!(qatomic_fetch_and(&proc_pending, ~SIG_BIT(sig)) &
                         SIG_BIT(sig))) {
                continue;               /* another thread took it */
            }
        }
        return sig;
    }
    return 0;
}

bool w32u_signal_pending(void)
{
    return next_signal(false) != 0;
}

/* a syscall that ended with EINTR starts again under SA_RESTART */
abi_long w32u_syscall_restart(abi_long ret)
{
    int sig;

    if (ret != -LX_EINTR) {
        return ret;
    }
    sig = next_signal(false);
    if (sig && action_of(sig) == 1 &&
        (w32u_sigact[sig].flags & LX_SA_RESTART)) {
        return W32U_ERESTART;
    }
    return ret;
}

/* faults of the guest: its handler, or the end */
void w32u_force_signal(int sig, int code, abi_ulong addr)
{
    if (action_of(sig) != 1 || (thread_mask & SIG_BIT(sig))) {
        die(sig);
    }
    w32u_raise_thread(sig, code, addr);
}

void w32u_handle_signals(CPUArchState *env)
{
    int sig;

    while ((sig = next_signal(true))) {
        W32USigAction act;
        W32USigInfo info;
        uint64_t old_mask;
        abi_ulong sp = 0;

        AcquireSRWLockShared(&sig_lock);
        act = w32u_sigact[sig];
        ReleaseSRWLockShared(&sig_lock);
        switch (action_of(sig)) {
        case 0:
            continue;
        case 2:
            die(sig);
        }
        info = thread_info[sig];
        if (info.signo != sig) {
            info = (W32USigInfo) { sig, LX_SI_USER, 0, 0 };
        }
        thread_info[sig].signo = 0;
        old_mask = suspend_mask_valid ? suspend_old_mask : thread_mask;
        suspend_mask_valid = false;
        if ((act.flags & LX_SA_ONSTACK) && !(alt_flags & LX_SS_DISABLE) &&
            !w32u_on_alt_stack(env)) {
            sp = alt_sp + alt_size;
        }
        if (!w32u_setup_frame(env, sig, &info, &act, old_mask, sp,
                              alt_sp, alt_size, alt_flags)) {
            die(11);
        }
        thread_mask |= act.mask;
        if (!(act.flags & LX_SA_NODEFER)) {
            thread_mask |= SIG_BIT(sig);
        }
        thread_mask &= ~(SIG_BIT(9) | SIG_BIT(19));
        if (act.flags & LX_SA_RESETHAND) {
            AcquireSRWLockExclusive(&sig_lock);
            w32u_sigact[sig].handler = LX_SIG_DFL;
            ReleaseSRWLockExclusive(&sig_lock);
        }
    }
}

bool w32u_on_alt_stack(CPUArchState *env)
{
    abi_ulong sp = w32u_stack_pointer(env);

    return !(alt_flags & LX_SS_DISABLE) && sp - alt_sp < alt_size;
}

/* rt_sigreturn: the state of the frame, the mask of before */
abi_long w32u_sigreturn(CPUArchState *env)
{
    uint64_t mask;

    if (!w32u_restore_frame(env, &mask)) {
        die(11);
    }
    thread_mask = mask & ~(SIG_BIT(9) | SIG_BIT(19));
    return W32U_ESIGRETURN;
}

/* ---- syscalls -------------------------------------------------------------- */

abi_long w32u_rt_sigaction(int sig, abi_ulong act, abi_ulong oact)
{
    W32USigAction a;

    if (sig < 1 || sig > 64 || (act && (sig == 9 || sig == 19))) {
        return -LX_EINVAL;
    }
    if (act && w32u_get_guest(act, &a, sizeof(a))) {
        return -LX_EFAULT;
    }
    AcquireSRWLockExclusive(&sig_lock);
    if (oact) {
        W32USigAction o = w32u_sigact[sig];

        if (w32u_put_guest(oact, &o, sizeof(o))) {
            ReleaseSRWLockExclusive(&sig_lock);
            return -LX_EFAULT;
        }
    }
    if (act) {
        w32u_sigact[sig] = a;
    }
    ReleaseSRWLockExclusive(&sig_lock);
    return 0;
}

abi_long w32u_rt_sigprocmask(int how, abi_ulong set, abi_ulong oset)
{
    uint64_t m;

    if (oset && w32u_put_guest(oset, &thread_mask, 8)) {
        return -LX_EFAULT;
    }
    if (!set) {
        return 0;
    }
    if (w32u_get_guest(set, &m, 8)) {
        return -LX_EFAULT;
    }
    switch (how) {
    case 0:                                 /* SIG_BLOCK */
        thread_mask |= m;
        break;
    case 1:                                 /* SIG_UNBLOCK */
        thread_mask &= ~m;
        break;
    case 2:                                 /* SIG_SETMASK */
        thread_mask = m;
        break;
    default:
        return -LX_EINVAL;
    }
    thread_mask &= ~(SIG_BIT(9) | SIG_BIT(19));
    return 0;
}

abi_long w32u_rt_sigpending(abi_ulong set)
{
    uint64_t p = (thread_pending | qatomic_read(&proc_pending)) & thread_mask;

    return w32u_put_guest(set, &p, 8);
}

/* wait for a signal to deliver: sigsuspend, pause */
static abi_long wait_signal(void)
{
    while (!w32u_signal_pending()) {
        Sleep(5);
    }
    return -LX_EINTR;
}

abi_long w32u_rt_sigsuspend(abi_ulong set)
{
    uint64_t m;

    if (w32u_get_guest(set, &m, 8)) {
        return -LX_EFAULT;
    }
    /* the handler runs with this mask; the old one after it */
    suspend_old_mask = thread_mask;
    suspend_mask_valid = true;
    thread_mask = m & ~(SIG_BIT(9) | SIG_BIT(19));
    return wait_signal();
}

abi_long w32u_pause(void)
{
    return wait_signal();
}

abi_long w32u_sigaltstack(abi_ulong ss, abi_ulong oss, CPUArchState *env)
{
    struct {
        uint64_t sp;
        int32_t flags;
        int32_t pad;
        uint64_t size;
    } s;

    if (oss) {
        s.sp = alt_sp;
        s.flags = alt_flags | (w32u_on_alt_stack(env) ? LX_SS_ONSTACK : 0);
        s.pad = 0;
        s.size = alt_size;
        if (w32u_put_guest(oss, &s, sizeof(s))) {
            return -LX_EFAULT;
        }
    }
    if (ss) {
        if (w32u_get_guest(ss, &s, sizeof(s))) {
            return -LX_EFAULT;
        }
        if (w32u_on_alt_stack(env)) {
            return -LX_EPERM;
        }
        if (s.flags & LX_SS_DISABLE) {
            alt_flags = LX_SS_DISABLE;
            alt_sp = alt_size = 0;
        } else {
            if (s.size < 2048) {
                return -LX_ENOMEM;
            }
            alt_flags = 0;
            alt_sp = s.sp;
            alt_size = s.size;
        }
    }
    return 0;
}

/* kill, tkill, tgkill */
abi_long w32u_kill(abi_long pid, int sig)
{
    char name[64];
    HANDLE map, ev;
    uint64_t *box;

    if (sig < 0 || sig > 64) {
        return -LX_EINVAL;
    }
    /* this process, its group (it leads it), everyone */
    if (pid == 0 || pid == w32u_vpid || pid == -w32u_vpid || pid == -1) {
        if (sig) {
            w32u_raise_process(sig);
        }
        return 0;
    }
    if (pid < 0) {
        pid = -pid;
    }
    snprintf(name, sizeof(name), "Local\\qemu-lu-sig-%lld", (long long)pid);
    map = OpenFileMappingA(FILE_MAP_WRITE, FALSE, name);
    if (!map) {
        return -LX_ESRCH;
    }
    if (sig) {
        box = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 8);
        if (box) {
            qatomic_or(box, SIG_BIT(sig));
            UnmapViewOfFile(box);
        }
        snprintf(name, sizeof(name), "Local\\qemu-lu-sigev-%lld",
                 (long long)pid);
        ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, name);
        if (ev) {
            SetEvent(ev);
            CloseHandle(ev);
        }
    }
    CloseHandle(map);
    return 0;
}

abi_long w32u_tgkill(abi_long tgid, abi_long tid, int sig)
{
    if (tgid != -1 && tgid != w32u_vpid) {
        return w32u_kill(tgid, sig);
    }
    if (sig < 0 || sig > 64) {
        return -LX_EINVAL;
    }
    /* a thread of ours: this one when it is the caller (raise) */
    if (sig && tid == w32u_gettid()) {
        if (sig == 9) {
            die(9);
        }
        w32u_raise_thread(sig, -6 /* SI_TKILL */, 0);
    } else if (sig) {
        w32u_raise_process(sig);
    }
    return 0;
}

/* ITIMER_REAL (alarm, setitimer): SIGALRM when it runs out */
static HANDLE itimer;
static int64_t itimer_due, itimer_interval;     /* us */
static SRWLOCK itimer_lock = SRWLOCK_INIT;

static VOID CALLBACK itimer_fired(PVOID p, BOOLEAN fired)
{
    AcquireSRWLockExclusive(&itimer_lock);
    itimer_due = itimer_interval ? g_get_monotonic_time() + itimer_interval
                                 : 0;
    ReleaseSRWLockExclusive(&itimer_lock);
    w32u_raise_process(14);
}

/* set to @value_us (0: off), every @interval_us; the old ones back */
static void itimer_set(int64_t value_us, int64_t interval_us,
                       int64_t *old_value, int64_t *old_interval)
{
    int64_t now = g_get_monotonic_time();
    HANDLE t;

    AcquireSRWLockExclusive(&itimer_lock);
    *old_value = itimer_due > now ? itimer_due - now : 0;
    *old_interval = itimer_interval;
    t = itimer;
    itimer = NULL;
    itimer_due = value_us ? now + value_us : 0;
    itimer_interval = interval_us;
    ReleaseSRWLockExclusive(&itimer_lock);
    if (t) {
        DeleteTimerQueueTimer(NULL, t, NULL);
    }
    if (value_us) {
        HANDLE n;

        if (CreateTimerQueueTimer(&n, NULL, itimer_fired, NULL,
                                  DIV_ROUND_UP(value_us, 1000),
                                  DIV_ROUND_UP(interval_us, 1000), 0)) {
            AcquireSRWLockExclusive(&itimer_lock);
            itimer = n;
            ReleaseSRWLockExclusive(&itimer_lock);
        }
    }
}

abi_long w32u_alarm(unsigned sec)
{
    int64_t ov, oi;

    itimer_set((int64_t)sec * G_USEC_PER_SEC, 0, &ov, &oi);
    return DIV_ROUND_UP(ov, G_USEC_PER_SEC);
}

/* setitimer, getitimer (val 0): ITIMER_REAL only */
abi_long w32u_setitimer(int which, abi_ulong val, abi_ulong old)
{
    int64_t v[4], ov, oi, now = g_get_monotonic_time();

    if (which != 0) {
        return -LX_EINVAL;
    }
    if (val) {
        if (w32u_get_guest(val, v, sizeof(v))) {
            return -LX_EFAULT;
        }
        /* struct itimerval: it_interval, it_value (timevals) */
        itimer_set(v[2] * G_USEC_PER_SEC + v[3], v[0] * G_USEC_PER_SEC + v[1],
                   &ov, &oi);
    } else {
        AcquireSRWLockShared(&itimer_lock);
        ov = itimer_due > now ? itimer_due - now : 0;
        oi = itimer_interval;
        ReleaseSRWLockShared(&itimer_lock);
    }
    if (old) {
        int64_t o[4] = { oi / G_USEC_PER_SEC, oi % G_USEC_PER_SEC,
                         ov / G_USEC_PER_SEC, ov % G_USEC_PER_SEC };

        return w32u_put_guest(old, o, sizeof(o));
    }
    return 0;
}

/* ---- the mailbox, the console --------------------------------------------- */

static DWORD WINAPI listener(void *opaque)
{
    HANDLE hs[2] = { mailbox_event, stop_event };

    while (WaitForMultipleObjects(2, hs, FALSE, INFINITE) == WAIT_OBJECT_0) {
        uint64_t sigs = qatomic_xchg(mailbox, 0);

        while (sigs) {
            int sig = ctz64(sigs) + 1;

            sigs &= sigs - 1;
            w32u_raise_process(sig);
        }
    }
    return 0;
}

static BOOL WINAPI console_ctrl(DWORD type)
{
    if (proxy) {
        return TRUE;            /* for the program execve() started */
    }
    switch (type) {
    case CTRL_C_EVENT:
        w32u_raise_process(2);
        return TRUE;
    case CTRL_BREAK_EVENT:
        w32u_raise_process(3);
        return TRUE;
    case CTRL_CLOSE_EVENT:
        w32u_raise_process(1);
        Sleep(2000);
        return TRUE;
    }
    return FALSE;
}

void w32u_signal_init(const W32ULaunch *l)
{
    char name[64];

    snprintf(name, sizeof(name), "Local\\qemu-lu-sig-%lld",
             (long long)w32u_vpid);
    mailbox_map = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
                                     PAGE_READWRITE, 0, 4096, name);
    mailbox = mailbox_map ? MapViewOfFile(mailbox_map, FILE_MAP_WRITE, 0, 0,
                                          8) : NULL;
    snprintf(name, sizeof(name), "Local\\qemu-lu-sigev-%lld",
             (long long)w32u_vpid);
    mailbox_event = CreateEventA(NULL, FALSE, FALSE, name);
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (mailbox && mailbox_event) {
        HANDLE t = CreateThread(NULL, 64 * 1024, listener, NULL, 0, NULL);

        if (t) {
            CloseHandle(t);
        }
    }
    SetConsoleCtrlHandler(console_ctrl, TRUE);
    if (l && l->signals) {
        int i;

        /* fork: all the actions; execve: the ignored ones (handlers go) */
        for (i = 1; i <= 64; i++) {
            W32USigAction *a = &l->signals->act[i];

            if (l->fork || a->handler == LX_SIG_IGN) {
                w32u_sigact[i] = *a;
            }
        }
        thread_mask = l->signals->mask;
    }
}

void w32u_signal_export(W32USignalState *s)
{
    AcquireSRWLockShared(&sig_lock);
    memcpy(s->act, w32u_sigact, sizeof(s->act));
    ReleaseSRWLockShared(&sig_lock);
    s->mask = thread_mask;
}

void w32u_become_proxy(void)
{
    /* the signals of this PID are the new program's now */
    proxy = true;
    if (stop_event) {
        SetEvent(stop_event);
    }
}
