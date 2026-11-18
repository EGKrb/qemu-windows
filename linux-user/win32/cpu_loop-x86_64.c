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
#include "win32-user.h"

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

void cpu_loop(CPUX86State *env)
{
    CPUState *cs = env_cpu(env);
    int trapnr, sig;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        qemu_process_cpu_events(cs);

        switch (trapnr) {
        case EXCP_SYSCALL:
            /* the syscall instruction: rax, then rdi rsi rdx r10 r8 r9 */
            env->regs[R_EAX] = w32u_syscall(env, env->regs[R_EAX],
                                            env->regs[R_EDI],
                                            env->regs[R_ESI],
                                            env->regs[R_EDX],
                                            env->regs[10], env->regs[8],
                                            env->regs[9]);
            break;
        case 0x80:
            /* int $0x80 of a 64-bit program: the i386 numbers, not here */
            env->regs[R_EAX] = -LX_ENOSYS;
            break;
        case EXCP_INTERRUPT:
            break;
        case EXCP06_ILLOP:
            w32u_die_with_signal(4);          /* SIGILL */
        case EXCP00_DIVZ:
            w32u_die_with_signal(8);          /* SIGFPE */
        case EXCP0B_NOSEG:
        case EXCP0C_STACK:
            w32u_die_with_signal(7);          /* SIGBUS */
        case EXCP0D_GPF:
        case EXCP0E_PAGE:
        case EXCP04_INTO:
        case EXCP05_BOUND:
            w32u_die_with_signal(11);         /* SIGSEGV */
        case EXCP01_DB:
        case EXCP03_INT3:
        case EXCP_DEBUG:
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
    }
}
