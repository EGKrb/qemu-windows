/*
 * Native Win32 linux-user prototype: static ELF loader
 *
 * Loads ET_EXEC and static-pie ET_DYN executables (no PT_INTERP yet).
 * Segments are copied into anonymous guest memory, which works whatever
 * their alignment; protections are then applied per 4 KiB page, with the
 * union of the segments sharing a page.  Builds the initial stack the way
 * the Linux kernel does: argc, argv, envp, auxv, then the strings.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/error-report.h"
#include "qemu/guest-random.h"
#include "elf.h"
#include "user/guest-host.h"
#include "win32-user.h"

static int elf_prot(uint32_t p_flags)
{
    return (p_flags & PF_R ? PROT_READ : 0) |
           (p_flags & PF_W ? PROT_WRITE : 0) |
           (p_flags & PF_X ? PROT_EXEC : 0);
}

static abi_ulong push_bytes(abi_ulong sp, const void *data, size_t len)
{
    sp -= len;
    memcpy(g2h_untagged(sp), data, len);
    return sp;
}

static abi_ulong push_str(abi_ulong sp, const char *s)
{
    return push_bytes(sp, s, strlen(s) + 1);
}

static int load_segments(const uint8_t *data, gsize size, const Elf64_Ehdr *eh,
                         W32UImage *image)
{
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(data + eh->e_phoff);
    abi_ulong lo = -1, hi = 0, bias = 0, npages, i;
    g_autofree uint8_t *page_prot = NULL;
    abi_long ret;

    for (i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_INTERP) {
            error_report("dynamically linked executables are not supported "
                         "yet: link with -static");
            return -LX_ENOSYS;
        }
        if (ph[i].p_type != PT_LOAD || ph[i].p_memsz == 0) {
            continue;
        }
        if (ph[i].p_offset + ph[i].p_filesz > size ||
            ph[i].p_filesz > ph[i].p_memsz) {
            return -LX_EINVAL;
        }
        lo = MIN(lo, ph[i].p_vaddr & TARGET_PAGE_MASK);
        hi = MAX(hi, TARGET_PAGE_ALIGN(ph[i].p_vaddr + ph[i].p_memsz));
    }
    if (hi == 0) {
        return -LX_EINVAL;
    }
    if (eh->e_type == ET_DYN) {
        bias = W32U_PIE_BASE - lo;
    }

    /* One writable mapping for the whole image, filled segment by segment */
    ret = w32u_mmap(lo + bias, hi - lo, PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret < 0) {
        return ret;
    }
    npages = (hi - lo) >> TARGET_PAGE_BITS;
    page_prot = g_new0(uint8_t, npages);
    for (i = 0; i < eh->e_phnum; i++) {
        abi_ulong first, last, p;

        if (ph[i].p_type != PT_LOAD || ph[i].p_memsz == 0) {
            continue;
        }
        memcpy(g2h_untagged(ph[i].p_vaddr + bias), data + ph[i].p_offset,
               ph[i].p_filesz);
        first = (ph[i].p_vaddr - lo) >> TARGET_PAGE_BITS;
        last = (ph[i].p_vaddr + ph[i].p_memsz - 1 - lo) >> TARGET_PAGE_BITS;
        for (p = first; p <= last; p++) {
            page_prot[p] |= elf_prot(ph[i].p_flags);
        }
        /* AT_PHDR: the program headers as loaded in memory */
        if (eh->e_phoff >= ph[i].p_offset &&
            eh->e_phoff < ph[i].p_offset + ph[i].p_filesz) {
            image->phdr = ph[i].p_vaddr + (eh->e_phoff - ph[i].p_offset) + bias;
        }
    }
    for (i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_PHDR) {
            image->phdr = ph[i].p_vaddr + bias;
        }
    }
    for (i = 0; i < npages; ) {
        abi_ulong j = i;

        while (j < npages && page_prot[j] == page_prot[i]) {
            j++;
        }
        ret = w32u_mprotect(lo + bias + (i << TARGET_PAGE_BITS),
                            (j - i) << TARGET_PAGE_BITS, page_prot[i]);
        if (ret < 0) {
            return ret;
        }
        i = j;
    }

    image->load_bias = bias;
    image->entry = eh->e_entry + bias;
    image->phnum = eh->e_phnum;
    image->brk = hi + bias;
    return 0;
}

static int setup_stack(const char *path, char **argv, char **envp,
                       W32UImage *image)
{
    abi_ulong stack_hi = W32U_GUEST_SPACE - 16 * TARGET_PAGE_SIZE;
    abi_ulong stack_lo = stack_hi - W32U_STACK_SIZE;
    int argc = 0, envc = 0, i, n = 0;
    abi_ulong sp, execfn, platform, random_addr, *argv_p, *envp_p;
    abi_ulong auxv[2 * 24];
    uint8_t rnd[16];
    abi_long ret;

    ret = w32u_mmap(stack_lo, W32U_STACK_SIZE, PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret < 0) {
        return ret;
    }
    while (argv[argc]) {
        argc++;
    }
    while (envp[envc]) {
        envc++;
    }
    argv_p = g_new(abi_ulong, argc);
    envp_p = g_new(abi_ulong, envc);

    sp = stack_hi;
    sp = execfn = push_str(sp, path);
    for (i = envc - 1; i >= 0; i--) {
        sp = envp_p[i] = push_str(sp, envp[i]);
    }
    for (i = argc - 1; i >= 0; i--) {
        sp = argv_p[i] = push_str(sp, argv[i]);
    }
    sp = platform = push_str(sp, W32U_ELF_PLATFORM);
    qemu_guest_getrandom_nofail(rnd, sizeof(rnd));
    sp = random_addr = push_bytes(sp & ~15, rnd, sizeof(rnd));

#define AUX(t, v) do { auxv[n++] = (t); auxv[n++] = (v); } while (0)
    AUX(AT_PHDR, image->phdr);
    AUX(AT_PHENT, sizeof(Elf64_Phdr));
    AUX(AT_PHNUM, image->phnum);
    AUX(AT_PAGESZ, TARGET_PAGE_SIZE);
    AUX(AT_BASE, 0);
    AUX(AT_FLAGS, 0);
    AUX(AT_ENTRY, image->entry);
    AUX(AT_UID, 1000);
    AUX(AT_EUID, 1000);
    AUX(AT_GID, 1000);
    AUX(AT_EGID, 1000);
    AUX(AT_SECURE, 0);
    AUX(AT_CLKTCK, 100);
    AUX(AT_HWCAP, w32u_elf_hwcap(thread_cpu));
    AUX(AT_HWCAP2, 0);
    AUX(AT_RANDOM, random_addr);
    AUX(AT_PLATFORM, platform);
    AUX(AT_EXECFN, execfn);
    AUX(AT_NULL, 0);
#undef AUX

    /* argc, argv[], NULL, envp[], NULL, auxv[]: 16-byte aligned on entry */
    sp -= (1 + argc + 1 + envc + 1 + n) * 8;
    sp &= ~(abi_ulong)15;
    image->start_stack = sp;
    stq_le_p(g2h_untagged(sp), argc);
    sp += 8;
    for (i = 0; i < argc; i++, sp += 8) {
        stq_le_p(g2h_untagged(sp), argv_p[i]);
    }
    stq_le_p(g2h_untagged(sp), 0);
    sp += 8;
    for (i = 0; i < envc; i++, sp += 8) {
        stq_le_p(g2h_untagged(sp), envp_p[i]);
    }
    stq_le_p(g2h_untagged(sp), 0);
    sp += 8;
    for (i = 0; i < n; i++, sp += 8) {
        stq_le_p(g2h_untagged(sp), auxv[i]);
    }

    g_free(argv_p);
    g_free(envp_p);
    return 0;
}

int w32u_load_elf(const char *path, char **argv, char **envp,
                  W32UImage *image)
{
    g_autofree gchar *data = NULL;
    g_autoptr(GError) err = NULL;
    const Elf64_Ehdr *eh;
    gsize size;
    int ret;

    if (!g_file_get_contents(path, &data, &size, &err)) {
        error_report("%s", err->message);
        return -LX_ENOENT;
    }
    eh = (const Elf64_Ehdr *)data;
    if (size < sizeof(*eh) || memcmp(eh->e_ident, ELFMAG, SELFMAG) ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB ||
        (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) ||
        eh->e_phentsize != sizeof(Elf64_Phdr) ||
        eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr) > size) {
        error_report("%s: not a 64-bit little-endian ELF executable", path);
        return -LX_EINVAL;
    }
    if (eh->e_machine != W32U_ELF_MACHINE) {
        error_report("%s: Invalid ELF image for this architecture", path);
        return -LX_EINVAL;
    }

    memset(image, 0, sizeof(*image));
    ret = load_segments((const uint8_t *)data, size, eh, image);
    if (ret < 0) {
        return ret;
    }
    return setup_stack(path, argv, envp, image);
}
