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
#include "exec/page-protection.h"
#include "user/guest-host.h"
#include "user/page-protection.h"
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

/*
 * The signal frame of AArch64 (arch/arm64/kernel/signal.c): siginfo,
 * struct ucontext (struct sigcontext, fpsimd_context in its __reserved,
 * then the end record), then a frame record (fp, lr).  Without
 * SA_RESTORER the handler returns to a trampoline (rt_sigreturn), at a
 * fixed address: the kernel has its vDSO there.
 */
#define F_UC        128
#define F_MC        (F_UC + 176)        /* uc_mcontext */
#define F_RES       (F_MC + 288)        /* __reserved */
#define F_REC       (F_UC + 176 + 288 + 4096)
#define F_SIZE      (F_REC + 16)
#define TRAMPOLINE  (W32U_GUEST_SPACE - 8 * TARGET_PAGE_SIZE)

abi_ulong w32u_stack_pointer(CPUArchState *env)
{
    return env->xregs[31];
}

static bool trampoline(void)
{
    uint32_t code[2] = { 0xd2801168, 0xd4000001 };  /* mov x8, #139; svc 0 */

    if (page_get_flags(TRAMPOLINE) & PAGE_VALID) {
        return true;
    }
    if (w32u_mmap(TRAMPOLINE, TARGET_PAGE_SIZE, PROT_READ | PROT_WRITE,
                  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) < 0) {
        return false;
    }
    memcpy(g2h_untagged(TRAMPOLINE), code, sizeof(code));
    return w32u_mprotect(TRAMPOLINE, TARGET_PAGE_SIZE,
                         PROT_READ | PROT_EXEC) == 0;
}

bool w32u_setup_frame(CPUArchState *env, int sig, const W32USigInfo *info,
                      const W32USigAction *act, uint64_t old_mask,
                      abi_ulong sp, abi_ulong ss_sp, abi_ulong ss_size,
                      int ss_flags)
{
    abi_ulong frame, ret;
    uint8_t *f, *mc, *res;
    int i;

    if (act->flags & 0x04000000) {         /* SA_RESTORER */
        ret = act->restorer;
    } else if (trampoline()) {
        ret = TRAMPOLINE;
    } else {
        return false;
    }
    sp = sp ? sp : env->xregs[31];
    frame = (sp - F_SIZE) & ~(abi_ulong)15;
    if (!guest_range_valid_untagged(frame, sp - frame) ||
        !page_check_range(frame, sp - frame, PAGE_WRITE)) {
        return false;
    }
    f = g2h_untagged(frame);
    memset(f, 0, F_SIZE);
    stl_le_p(f, info->signo);
    stl_le_p(f + 8, info->code);
    stq_le_p(f + 16, info->addr);
    stq_le_p(f + F_UC + 16, ss_sp);
    stl_le_p(f + F_UC + 24, ss_flags);
    stq_le_p(f + F_UC + 32, ss_size);
    stq_le_p(f + F_UC + 40, old_mask);
    mc = f + F_MC;
    stq_le_p(mc, info->addr);
    for (i = 0; i < 31; i++) {
        stq_le_p(mc + 8 + i * 8, env->xregs[i]);
    }
    stq_le_p(mc + 256, env->xregs[31]);
    stq_le_p(mc + 264, env->pc);
    stq_le_p(mc + 272, pstate_read(env));
    res = f + F_RES;
    stl_le_p(res, 0x46508001);              /* FPSIMD_MAGIC */
    stl_le_p(res + 4, 528);
    stl_le_p(res + 8, vfp_get_fpsr(env));
    stl_le_p(res + 12, vfp_get_fpcr(env));
    for (i = 0; i < 32; i++) {
        uint64_t *q = aa64_vfp_qreg(env, i);

        stq_le_p(res + 16 + i * 16, q[0]);
        stq_le_p(res + 24 + i * 16, q[1]);
    }
    /* then the end record: zeros */
    stq_le_p(f + F_REC, env->xregs[29]);
    stq_le_p(f + F_REC + 8, env->xregs[30]);

    env->xregs[0] = sig;
    env->xregs[1] = frame;
    env->xregs[2] = frame + F_UC;
    env->xregs[29] = frame + F_REC;
    env->xregs[30] = ret;
    env->xregs[31] = frame;
    env->pc = act->handler;
    env->btype = 0;
    return true;
}

bool w32u_restore_frame(CPUArchState *env, uint64_t *mask)
{
    abi_ulong frame = env->xregs[31];
    uint8_t *f, *mc, *res;
    uint64_t pstate;
    int i;

    if ((frame & 15) || !guest_range_valid_untagged(frame, F_SIZE) ||
        !page_check_range(frame, F_SIZE, PAGE_READ)) {
        return false;
    }
    f = g2h_untagged(frame);
    mc = f + F_MC;
    for (i = 0; i < 31; i++) {
        env->xregs[i] = ldq_le_p(mc + 8 + i * 8);
    }
    env->xregs[31] = ldq_le_p(mc + 256);
    env->pc = ldq_le_p(mc + 264);
    /* the flags only: the guest stays at EL0 */
    pstate = ldq_le_p(mc + 272);
    pstate_write(env, (pstate_read(env) & ~PSTATE_NZCV) |
                      (pstate & PSTATE_NZCV));
    res = f + F_RES;
    if (ldl_le_p(res) == 0x46508001) {
        vfp_set_fpsr(env, ldl_le_p(res + 8));
        vfp_set_fpcr(env, ldl_le_p(res + 12));
        for (i = 0; i < 32; i++) {
            uint64_t *q = aa64_vfp_qreg(env, i);

            q[0] = ldq_le_p(res + 16 + i * 16);
            q[1] = ldq_le_p(res + 24 + i * 16);
        }
    }
    *mask = ldq_le_p(f + F_UC + 40);
    return true;
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
        case EXCP_SWI: {
            abi_long ret;

            /* On syscall, PSTATE.ZA is preserved, PSTATE.SM is cleared. */
            aarch64_set_svcr(env, 0, R_SVCR_SM_MASK);
            ret = w32u_syscall(env, env->xregs[8], env->xregs[0],
                               env->xregs[1], env->xregs[2], env->xregs[3],
                               env->xregs[4], env->xregs[5]);
            if (ret == W32U_ERESTART) {
                env->pc -= 4;               /* the svc again */
            } else if (ret != W32U_ESIGRETURN) {
                env->xregs[0] = ret;
            }
            break;
        }
        case EXCP_INTERRUPT:
        case EXCP_YIELD:
            break;
        case EXCP_UDEF:
            w32u_force_signal(4, 2, env->pc);           /* ILL_ILLOPN */
            break;
        case EXCP_PREFETCH_ABORT:
        case EXCP_DATA_ABORT:
            w32u_force_signal(11, 1, env->exception.vaddress);
            break;
        case EXCP_DEBUG:
        case EXCP_BKPT:
            w32u_force_signal(5, 1, env->pc);           /* TRAP_BRKPT */
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        default:
            fprintf(stderr, "qemu: unhandled CPU exception 0x%x - aborting\n",
                    trapnr);
            abort();
        }

        /* faults of the host on guest memory (fault.c) */
        sig = w32u_take_pending_signal();
        if (sig) {
            w32u_force_signal(sig, 1, 0);
        }
        w32u_handle_signals(env);
        /* Exception return on AArch64 always clears the exclusive monitor */
        env->exclusive_addr = -1;
    }
}
