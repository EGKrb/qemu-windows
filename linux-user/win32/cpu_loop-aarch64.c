/*
 * Native Win32 linux-user prototype: AArch64 cpu loop and ABI
 *
 * Same structure as linux-user/aarch64/cpu_loop.c, without guest signal
 * delivery: faults take the default action of the signal (terminate).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/guest-random.h"
#include "accel/tcg/cpu-loop.h"
#include "user/cpu_loop.h"
#include "target/arm/cpu-features.h"
#include "win32-user.h"

enum {
    HWCAP_FP        = 1 << 0,
    HWCAP_ASIMD     = 1 << 1,
    HWCAP_AES       = 1 << 3,
    HWCAP_PMULL     = 1 << 4,
    HWCAP_SHA1      = 1 << 5,
    HWCAP_SHA2      = 1 << 6,
    HWCAP_CRC32     = 1 << 7,
    HWCAP_ATOMICS   = 1 << 8,
    HWCAP_FPHP      = 1 << 9,
    HWCAP_ASIMDHP   = 1 << 10,
    HWCAP_ASIMDRDM  = 1 << 12,
    HWCAP_JSCVT     = 1 << 13,
    HWCAP_FCMA      = 1 << 14,
    HWCAP_LRCPC     = 1 << 15,
    HWCAP_DCPOP     = 1 << 16,
    HWCAP_ASIMDDP   = 1 << 20,
};

abi_ulong w32u_elf_hwcap(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);
    abi_ulong hwcaps = HWCAP_FP | HWCAP_ASIMD;

#define GET(feat, hwcap) \
    do { if (cpu_isar_feature(feat, cpu)) { hwcaps |= hwcap; } } while (0)
    GET(aa64_aes, HWCAP_AES);
    GET(aa64_pmull, HWCAP_PMULL);
    GET(aa64_sha1, HWCAP_SHA1);
    GET(aa64_sha256, HWCAP_SHA2);
    GET(aa64_crc32, HWCAP_CRC32);
    GET(aa64_lse, HWCAP_ATOMICS);
    GET(aa64_fp16, HWCAP_FPHP | HWCAP_ASIMDHP);
    GET(aa64_rdm, HWCAP_ASIMDRDM);
    GET(aa64_jscvt, HWCAP_JSCVT);
    GET(aa64_fcma, HWCAP_FCMA);
    GET(aa64_rcpc_8_3, HWCAP_LRCPC);
    GET(aa64_dcpop, HWCAP_DCPOP);
    GET(aa64_dp, HWCAP_ASIMDDP);
#undef GET
    return hwcaps;
}

void w32u_init_main_thread(CPUState *cs, const W32UImage *image)
{
    CPUARMState *env = cpu_env(cs);
    ARMCPU *cpu = env_archcpu(env);

    if (!arm_feature(env, ARM_FEATURE_AARCH64)) {
        fprintf(stderr, "The selected ARM CPU does not support 64 bit mode\n");
        exit(EXIT_FAILURE);
    }
    env->pc = image->entry & ~0x3ULL;
    env->xregs[31] = image->start_stack;
    if (cpu_isar_feature(aa64_pauth, cpu)) {
        qemu_guest_getrandom_nofail(&env->keys, sizeof(env->keys));
    }
}

void w32u_clone_regs(CPUArchState *env, abi_ulong newsp, bool settls,
                     abi_ulong tls)
{
    if (newsp) {
        env->xregs[31] = newsp;
    }
    env->xregs[0] = 0;
    if (settls) {
        env->cp15.tpidr_el[0] = tls;
    }
}

void w32u_env_after_fork(CPUArchState *env)
{
    memset(env->cpu_breakpoint, 0, sizeof(env->cpu_breakpoint));
    memset(env->cpu_watchpoint, 0, sizeof(env->cpu_watchpoint));
    env->tlb_fi = NULL;
}

void cpu_loop(CPUARMState *env)
{
    CPUState *cs = env_cpu(env);
    int trapnr, sig;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        qemu_process_cpu_events(cs);

        switch (trapnr) {
        case EXCP_SWI:
            /* On syscall, PSTATE.ZA is preserved, PSTATE.SM is cleared. */
            aarch64_set_svcr(env, 0, R_SVCR_SM_MASK);
            env->xregs[0] = w32u_syscall(env, env->xregs[8],
                                         env->xregs[0], env->xregs[1],
                                         env->xregs[2], env->xregs[3],
                                         env->xregs[4], env->xregs[5]);
            break;
        case EXCP_INTERRUPT:
        case EXCP_YIELD:
            break;
        case EXCP_UDEF:
            w32u_die_with_signal(4);          /* SIGILL */
        case EXCP_PREFETCH_ABORT:
        case EXCP_DATA_ABORT:
            w32u_die_with_signal(11);         /* SIGSEGV */
        case EXCP_DEBUG:
        case EXCP_BKPT:
            w32u_die_with_signal(5);          /* SIGTRAP */
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            fprintf(stderr, "qemu: unhandled CPU exception 0x%x - aborting\n",
                    trapnr);
            abort();
        }

        sig = w32u_take_pending_signal();
        if (sig) {
            w32u_die_with_signal(sig);
        }
        /* Exception return on AArch64 always clears the exclusive monitor */
        env->exclusive_addr = -1;
    }
}
