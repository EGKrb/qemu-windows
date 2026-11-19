/*
 * Native Win32 linux-user prototype: internal interfaces
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WIN32_USER_H
#define WIN32_USER_H

#include "cpu.h"
#include "exec/target_page.h"
#include "user/abitypes.h"

#if TARGET_BIG_ENDIAN
#error "the Win32 linux-user prototype only supports little-endian guests"
#endif

/* Size of the guest address space reserved at startup (reserved_va + 1) */
#define W32U_GUEST_SPACE    (64ULL << 30)
#define W32U_STACK_SIZE     (8 * 1024 * 1024)
/* Load address of position independent (static-pie) executables */
#define W32U_PIE_BASE       0x400000000ULL
/* Load address of the program interpreter (ld.so) */
#define W32U_INTERP_BASE    0x600000000ULL
/* First address searched for mmap without a hint */
#define W32U_MMAP_BASE      0x800000000ULL

/* Linux errno values (asm-generic) */
#define LX_EPERM        1
#define LX_ENOENT       2
#define LX_ESRCH        3
#define LX_EINTR        4
#define LX_EIO          5
#define LX_EBADF        9
#define LX_ECHILD       10
#define LX_EAGAIN       11
#define LX_ENOMEM       12
#define LX_EACCES       13
#define LX_EFAULT       14
#define LX_EEXIST       17
#define LX_EXDEV        18
#define LX_ENODEV       19
#define LX_ENOTDIR      20
#define LX_EISDIR       21
#define LX_EINVAL       22
#define LX_EMFILE       24
#define LX_ENOTTY       25
#define LX_ENOSPC       28
#define LX_ESPIPE       29
#define LX_EPIPE        32
#define LX_ERANGE       34
#define LX_EDEADLK      35
#define LX_ENAMETOOLONG 36
#define LX_ENOLCK       37
#define LX_ENOSYS       38
#define LX_ENOTEMPTY    39
#define LX_EILSEQ       84
#define LX_EOPNOTSUPP   95
#define LX_ETIMEDOUT    110

typedef struct W32UImage {
    abi_ulong entry;
    abi_ulong load_bias;
    abi_ulong phdr;
    abi_ulong phnum;
    abi_ulong brk;
    abi_ulong start_stack;
    abi_ulong prog_entry;           /* AT_ENTRY: the program's */
    abi_ulong interp_bias;          /* AT_BASE: ld.so's, 0 without one */
} W32UImage;

/* -L / QEMU_LD_PREFIX: guest files are looked for there first */
extern const char *w32u_sysroot;
/* the host path of a guest path */
char *w32u_host_path(const char *guest);

extern __thread CPUState *thread_cpu;
extern bool w32u_strace;

/* mem.c: guest address space on top of VirtualAlloc */
void w32u_mem_init(void);
abi_long w32u_mmap(abi_ulong start, abi_ulong len, int prot, int flags,
                   int fd, int64_t offset);
abi_long w32u_munmap(abi_ulong start, abi_ulong len);
abi_long w32u_mprotect(abi_ulong start, abi_ulong len, int prot);
void w32u_set_brk(abi_ulong brk);
abi_ulong w32u_brk(abi_ulong new_brk);

/* elf.c */
int w32u_load_elf(const char *path, char **argv, char **envp,
                  W32UImage *image);

/* fault.c: vectored exception handler replacing SIGSEGV */
void w32u_fault_init(void);
int w32u_take_pending_signal(void);
/* a signal waits for the guest: blocking syscalls end with EINTR */
bool w32u_signal_pending(void);
G_NORETURN void w32u_die_with_signal(int sig);

/* cpu_loop-<target>.c: per-architecture ABI */
#ifdef TARGET_AARCH64
#define W32U_ELF_MACHINE    183     /* EM_AARCH64 */
#define W32U_ELF_PLATFORM   "aarch64"
#endif
#ifdef TARGET_X86_64
#define W32U_ELF_MACHINE    62      /* EM_X86_64 */
#define W32U_ELF_PLATFORM   "x86_64"
#endif
abi_ulong w32u_elf_hwcap(CPUState *cs);
void w32u_init_main_thread(CPUState *cs, const W32UImage *image);

/* syscall.c */
void w32u_syscall_init(const char *exec_path);
abi_long w32u_syscall(CPUArchState *env, int num, abi_long arg1,
                      abi_long arg2, abi_long arg3, abi_long arg4,
                      abi_long arg5, abi_long arg6);
/* Guest fd reading for the ELF loader and file-backed mmap */
int64_t w32u_fd_pread(int fd, void *buf, size_t len, int64_t offset);

#endif
