/*
 * linux-user on Windows: x86_64 cpu loop and ABI
 *
 * Same setup as linux-user/i386/cpu_loop.c (long mode, the GDT and IDT of
 * Linux in guest memory), with the syscalls of linux-user/win32.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-loop.h"
#include "user/cpu_loop.h"
#include "user/guest-host.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "win32-user.h"
#include "target/i386/tcg/helper-tcg.h"

#define TARGET_GDT_ENTRIES  16
#define USER_CS             0x33
#define USER_DS             0x2b

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_host_ticks();
}

abi_ulong w32u_elf_hwcap(CPUState *cs)
{
    /* AT_HWCAP of x86: the CPUID.1 EDX features */
    return cpu_env(cs)->features[FEAT_1_EDX];
}

static void write_dt(void *ptr, unsigned long addr, unsigned long limit,
                     int flags)
{
    uint32_t *p = ptr, e1, e2;

    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000);
    e2 |= flags;
    p[0] = e1;
    p[1] = e2;
}

static void set_gate64(void *ptr, unsigned int type, unsigned int dpl,
                       uint64_t addr, unsigned int sel)
{
    uint32_t *p = ptr, e1, e2;

    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p[0] = e1;
    p[1] = e2;
    p[2] = addr >> 32;
    p[3] = 0;
}

void w32u_init_main_thread(CPUState *cs, const W32UImage *image)
{
    CPUX86State *env = cpu_env(cs);
    uint64_t *idt, *gdt;
    abi_long base;
    int i;

    if (!(env->features[FEAT_8000_0001_EDX] & CPUID_EXT2_LM)) {
        fprintf(stderr, "The selected x86 CPU does not support 64 bit mode\n");
        exit(EXIT_FAILURE);
    }
    env->cr[0] = CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK;
    env->hflags |= HF_PE_MASK | HF_CPL_MASK;
    if (env->features[FEAT_1_EDX] & CPUID_SSE) {
        env->cr[4] |= CR4_OSFXSR_MASK;
        env->hflags |= HF_OSFXSR_MASK;
    }
    env->cr[4] |= CR4_PAE_MASK;
    env->efer |= MSR_EFER_LMA | MSR_EFER_LME;
    env->hflags |= HF_LMA_MASK;
    env->eflags |= IF_MASK;

    /* the kernel's ELF_PLAT_INIT: all registers zero */
    memset(env->regs, 0, sizeof(env->regs));
    env->regs[R_ESP] = image->start_stack;
    env->eip = image->entry;

    /* the interrupts of Linux */
    env->idt.limit = 511;
    base = w32u_mmap(0, sizeof(uint64_t) * (env->idt.limit + 1),
                     PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
                     -1, 0);
    if (base < 0) {
        fprintf(stderr, "qemu: no memory for the IDT\n");
        exit(EXIT_FAILURE);
    }
    env->idt.base = base;
    idt = g2h_untagged(env->idt.base);
    for (i = 0; i < 20; i++) {
        set_gate64(idt + i * 2, 0, 0, 0, 0);
    }
    set_gate64(idt + 3 * 2, 0, 3, 0, 0);
    set_gate64(idt + 4 * 2, 0, 3, 0, 0);
    set_gate64(idt + 0x80 * 2, 0, 3, 0, 0);

    /* the segments of Linux */
    base = w32u_mmap(0, sizeof(uint64_t) * TARGET_GDT_ENTRIES,
                     PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
                     -1, 0);
    if (base < 0) {
        fprintf(stderr, "qemu: no memory for the GDT\n");
        exit(EXIT_FAILURE);
    }
    env->gdt.base = base;
    env->gdt.limit = sizeof(uint64_t) * TARGET_GDT_ENTRIES - 1;
    gdt = g2h_untagged(env->gdt.base);
    write_dt(&gdt[USER_CS >> 3], 0, 0xfffff,
             DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
             DESC_L_MASK | (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
    write_dt(&gdt[USER_DS >> 3], 0, 0xfffff,
             DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
             (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    cpu_x86_load_seg(env, R_CS, USER_CS);
    cpu_x86_load_seg(env, R_SS, USER_DS);
    cpu_x86_load_seg(env, R_DS, 0);
    cpu_x86_load_seg(env, R_ES, 0);
    cpu_x86_load_seg(env, R_FS, 0);
    cpu_x86_load_seg(env, R_GS, 0);
}

void w32u_clone_regs(CPUArchState *env, abi_ulong newsp, bool settls,
                     abi_ulong tls)
{
    if (newsp) {
        env->regs[R_ESP] = newsp;
    }
    env->regs[R_EAX] = 0;
    if (settls) {
        cpu_x86_load_seg(env, R_FS, 0);
        env->segs[R_FS].base = tls;
    }
}

/*
 * The signal frame of x86_64 (arch/x86/include/asm/sigframe.h):
 * pretcode, struct ucontext (with struct sigcontext), siginfo; the FPU
 * state (fxsave) above it, 64-byte aligned; 128 bytes of red zone kept.
 */
#define F_UC        8
#define F_SC        (F_UC + 40)         /* uc_mcontext */
#define F_MASK      (F_UC + 296)        /* uc_sigmask */
#define F_INFO      (F_UC + 304)
#define F_SIZE      (F_INFO + 128)

static const int sc_regs[] = {         /* the order of struct sigcontext */
    8, 9, 10, 11, 12, 13, 14, 15, R_EDI, R_ESI, R_EBP, R_EBX, R_EDX, R_EAX,
    R_ECX, R_ESP,
};

abi_ulong w32u_stack_pointer(CPUArchState *env)
{
    return env->regs[R_ESP];
}

bool w32u_setup_frame(CPUArchState *env, int sig, const W32USigInfo *info,
                      const W32USigAction *act, uint64_t old_mask,
                      abi_ulong sp, abi_ulong ss_sp, abi_ulong ss_size,
                      int ss_flags)
{
    abi_ulong fp, frame;
    uint8_t *f, *sc;
    int i;

    if (!(act->flags & 0x04000000)) {      /* SA_RESTORER: glibc's */
        return false;
    }
    sp = sp ? sp : env->regs[R_ESP] - 128;
    fp = (sp - 512) & ~(abi_ulong)63;
    frame = ((fp - F_SIZE) & ~(abi_ulong)15) - 8;
    if (!guest_range_valid_untagged(frame, sp - frame) ||
        !page_check_range(frame, sp - frame, PAGE_WRITE)) {
        return false;
    }
    f = g2h_untagged(frame);
    memset(f, 0, F_SIZE);
    stq_le_p(f, act->restorer);
    stq_le_p(f + F_UC + 16, ss_sp);
    stl_le_p(f + F_UC + 24, ss_flags);
    stq_le_p(f + F_UC + 32, ss_size);
    sc = f + F_SC;
    for (i = 0; i < 16; i++) {
        stq_le_p(sc + i * 8, env->regs[sc_regs[i]]);
    }
    stq_le_p(sc + 128, env->eip);
    stq_le_p(sc + 136, cpu_compute_eflags(env));
    stw_le_p(sc + 144, env->segs[R_CS].selector);
    stw_le_p(sc + 150, env->segs[R_SS].selector);
    stq_le_p(sc + 160, env->trap_nr);
    stq_le_p(sc + 168, old_mask);
    stq_le_p(sc + 176, info->addr);
    stq_le_p(sc + 184, fp);
    stq_le_p(f + F_MASK, old_mask);
    stl_le_p(f + F_INFO, info->signo);
    stl_le_p(f + F_INFO + 8, info->code);
    stq_le_p(f + F_INFO + 16, info->addr);
    cpu_x86_fxsave(env, g2h_untagged(fp), 512);

    env->regs[R_EDI] = sig;
    env->regs[R_ESI] = frame + F_INFO;
    env->regs[R_EDX] = frame + F_UC;
    env->regs[R_EAX] = 0;
    env->regs[R_ESP] = frame;
    env->eip = act->handler;
    env->eflags &= ~TF_MASK;
    env->df = 1;
    return true;
}

bool w32u_restore_frame(CPUArchState *env, uint64_t *mask)
{
    /* the handler returned: pretcode was popped */
    abi_ulong frame = env->regs[R_ESP] - 8, fp;
    uint8_t *f, *sc;
    int i;

    if (!guest_range_valid_untagged(frame, F_SIZE) ||
        !page_check_range(frame, F_SIZE, PAGE_READ)) {
        return false;
    }
    f = g2h_untagged(frame);
    sc = f + F_SC;
    for (i = 0; i < 16; i++) {
        env->regs[sc_regs[i]] = ldq_le_p(sc + i * 8);
    }
    env->eip = ldq_le_p(sc + 128);
    cpu_load_eflags(env, ldq_le_p(sc + 136),
                    TF_MASK | AC_MASK | ID_MASK | CC_O | DF_MASK |
                    CC_S | CC_Z | CC_A | CC_P | CC_C | RF_MASK);
    fp = ldq_le_p(sc + 184);
    if (fp) {
        if (!guest_range_valid_untagged(fp, 512) ||
            !page_check_range(fp, 512, PAGE_READ)) {
            return false;
        }
        cpu_x86_fxrstor(env, g2h_untagged(fp), 512);
    }
    *mask = ldq_le_p(f + F_MASK);
    return true;
}

void w32u_env_after_fork(CPUArchState *env)
{
    memset(env->cpu_breakpoint, 0, sizeof(env->cpu_breakpoint));
}

void cpu_loop(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    abi_long ret;
    int trapnr, sig;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        qemu_process_cpu_events(cs);

        if (trapnr >= EXCP00_DIVZ && trapnr <= EXCP12_MCHK) {
            env->trap_nr = trapnr;
        }
        switch (trapnr) {
        case EXCP_SYSCALL:
            /* the syscall instruction: rax, then rdi rsi rdx r10 r8 r9 */
            ret = w32u_syscall(env, env->regs[R_EAX], env->regs[R_EDI],
                               env->regs[R_ESI], env->regs[R_EDX],
                               env->regs[10], env->regs[8], env->regs[9]);
            if (ret == W32U_ERESTART) {
                env->eip -= 2;              /* the syscall again */
            } else if (ret != W32U_ESIGRETURN) {
                env->regs[R_EAX] = ret;
            }
            break;
        case 0x80:
            /* int $0x80 of a 64-bit program: the i386 numbers, not here */
            env->regs[R_EAX] = -LX_ENOSYS;
            break;
        case EXCP_INTERRUPT:
            break;
        case EXCP06_ILLOP:
            w32u_force_signal(4, 2, env->eip);          /* ILL_ILLOPN */
            break;
        case EXCP00_DIVZ:
            w32u_force_signal(8, 1, env->eip);          /* FPE_INTDIV */
            break;
        case EXCP0B_NOSEG:
        case EXCP0C_STACK:
            w32u_force_signal(7, 0x80, 0);              /* SIGBUS */
            break;
        case EXCP0E_PAGE:
            w32u_force_signal(11, env->error_code & PG_ERROR_P_MASK ? 2 : 1,
                              env->cr[2]);              /* SEGV_ACCERR/MAPERR */
            break;
        case EXCP0D_GPF:
        case EXCP04_INTO:
        case EXCP05_BOUND:
            w32u_force_signal(11, 0x80, 0);
            break;
        case EXCP01_DB:
        case EXCP_DEBUG:
            w32u_force_signal(5, 1, env->eip);          /* TRAP_BRKPT */
            break;
        case EXCP03_INT3:
            w32u_force_signal(5, 0x80, 0);
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
    }
}
