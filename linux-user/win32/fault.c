/*
 * Native Win32 linux-user prototype: host faults
 *
 * A vectored exception handler plays the role of the SIGSEGV handler of
 * linux-user/signal.c:
 *  - writes to guest pages write-protected because they hold translated
 *    code go through page_unprotect() (self-modifying code);
 *  - other faults on guest memory become guest SIGSEGV.
 *
 * Nothing longjmps out of the handler itself: when the current TB must be
 * abandoned, the faulting context is redirected to a trampoline that runs
 * on the normal thread stack and leaves through cpu_loop_exit*().
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "exec/page-protection.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/cpu-ops.h"
#include "user/cpu_loop.h"
#include "user/guest-host.h"
#include "user/page-protection.h"
#include "win32-user.h"

typedef struct W32UFault {
    vaddr addr;
    MMUAccessType access;
    bool maperr;
    uintptr_t pc;
} W32UFault;

static __thread W32UFault pending_fault;
/* Fatal guest signal raised while running translated code */
static __thread int pending_signal;

void cpu_loop_exit_sigsegv(CPUState *cpu, vaddr addr,
                           MMUAccessType access_type, bool maperr, uintptr_t ra)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops->record_sigsegv) {
        tcg_ops->record_sigsegv(cpu, addr, access_type, maperr, ra);
    }
    pending_signal = 11;
    cpu->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit_restore(cpu, ra);
}

void cpu_loop_exit_sigbus(CPUState *cpu, vaddr addr,
                          MMUAccessType access_type, uintptr_t ra)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops->record_sigbus) {
        tcg_ops->record_sigbus(cpu, addr, access_type, ra);
    }
    pending_signal = 7;
    cpu->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit_restore(cpu, ra);
}

int w32u_take_pending_signal(void)
{
    int sig = pending_signal;

    pending_signal = 0;
    return sig;
}

static const char *signal_name(int sig)
{
    switch (sig) {
    case 4:
        return "Illegal instruction";
    case 5:
        return "Trace/breakpoint trap";
    case 6:
        return "Aborted";
    case 7:
        return "Bus error";
    case 11:
        return "Segmentation fault";
    default:
        return "Unknown signal";
    }
}

/* Default action of a fatal signal, as reported by linux-user */
void w32u_die_with_signal(int sig)
{
    fprintf(stderr, "qemu: uncaught target signal %d (%s) - core dumped\n",
            sig, signal_name(sig));
    fflush(NULL);
    /* the shell convention for "killed by signal N" */
    ExitProcess(128 + sig);
}

static void G_NORETURN guest_segv_trampoline(void)
{
    W32UFault f = pending_fault;

    cpu_loop_exit_sigsegv(thread_cpu, f.addr, f.access, f.maperr, f.pc);
}

static void G_NORETURN exit_tb_trampoline(void)
{
    cpu_loop_exit_noexc(thread_cpu);
}

/* Resume the faulting thread in fn(), on its own stack, as if called */
static LONG redirect(PCONTEXT ctx, void (*fn)(void))
{
    ctx->Rsp = ((ctx->Rsp - 256) & ~(DWORD64)15) - 8;
    ctx->Rip = (DWORD64)fn;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG CALLBACK w32u_veh(PEXCEPTION_POINTERS ep)
{
    PEXCEPTION_RECORD rec = ep->ExceptionRecord;
    CPUState *cpu = thread_cpu;
    uintptr_t host_addr, pc;
    bool is_write;
    vaddr guest_addr;
    MMUAccessType access;
    int flags;

    if (rec->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
        rec->NumberParameters < 2 || !cpu) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    host_addr = rec->ExceptionInformation[1];
    if (!h2g_valid(host_addr)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    is_write = rec->ExceptionInformation[0] == 1;
    guest_addr = h2g_nocheck(host_addr);
    pc = ep->ContextRecord->Rip;
    access = adjust_signal_pc(&pc, is_write);
    flags = page_get_flags(guest_addr);

    if (is_write && (flags & PAGE_VALID) && (flags & PAGE_WRITE_ORG)) {
        switch (page_unprotect(cpu, guest_addr, pc)) {
        case 1:
            /* translations invalidated, the store can be retried */
            return EXCEPTION_CONTINUE_EXECUTION;
        case 2:
            /* the running TB was modified: leave it */
            return redirect(ep->ContextRecord, exit_tb_trampoline);
        default:
            break;
        }
    }

    pending_fault = (W32UFault) {
        .addr = guest_addr,
        .access = access,
        .maperr = !(flags & PAGE_VALID),
        .pc = pc,
    };
    return redirect(ep->ContextRecord, guest_segv_trampoline);
}

void w32u_fault_init(void)
{
    if (!AddVectoredExceptionHandler(1, w32u_veh)) {
        error_report("cannot install the vectored exception handler");
        exit(EXIT_FAILURE);
    }
}

bool w32u_signal_pending(void)
{
    return pending_signal != 0;
}
