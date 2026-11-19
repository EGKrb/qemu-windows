/*
 * linux-user on Windows: processes (execve, fork, vfork, wait4)
 *
 * Windows has neither fork() nor execve() replacing a process:
 *
 * - A new guest process is a new qemu-ARCH.exe, started with a "launch
 *   block": a section it inherits, with the guest's argv and envp, its
 *   file descriptors (inherited handles), PIDs, the sysroot, the CPU.
 *   Its Windows environment stays the host's (it finds its DLLs there).
 *
 * - execve() starts the program that way, keeping the PID of the guest
 *   process (its "virtual" PID); the old process waits for it and ends
 *   with its status, as exec of Cygwin does.  "#!" scripts run their
 *   interpreter; a program of another architecture runs under its
 *   qemu-ARCH.exe, next to this one, as binfmt_misc would have it.
 *
 * - fork(), vfork() and clone() without CLONE_THREAD start a process
 *   that copies the guest's memory from its parent (ReadProcessMemory,
 *   the other vCPUs stopped), the CPU state, the descriptors, then goes
 *   on from the syscall with 0.  A vfork child has memory of its own:
 *   what it writes before execve is not seen by its parent.
 *
 * - The status of a child: its exit code, or 0x40000000 | the signal
 *   that ended it (for a parent that is qemu-ARCH.exe too).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "exec/cpu-common.h"
#include "exec/mmap-lock.h"
#include "exec/page-protection.h"
#include "tcg/startup.h"
#include "user/cpu_loop.h"
#include "user/guest-host.h"
#include "user/page-protection.h"
#include "win32-user.h"

abi_long w32u_vpid, w32u_vppid;
bool w32u_qemu_parent;

/* ---- the launch block ------------------------------------------------- */

enum {
    L_ARG = 1, L_ENV, L_FDS, L_VPID, L_PPID, L_SYSROOT, L_CPU, L_PATH,
    L_FORK_PARENT = 20, L_FORK_BASE, L_REGION, L_MEMSTATE, L_ENVBYTES,
    L_FORK_EVENT, L_CLONE, L_SIGNALS,
};

static void put_rec(GByteArray *b, uint32_t tag, const void *data,
                    uint32_t len)
{
    g_byte_array_append(b, (guint8 *)&tag, 4);
    g_byte_array_append(b, (guint8 *)&len, 4);
    g_byte_array_append(b, data, len);
}

static void put_str(GByteArray *b, uint32_t tag, const char *s)
{
    put_rec(b, tag, s, strlen(s) + 1);
}

static void put_u64(GByteArray *b, uint32_t tag, uint64_t v)
{
    put_rec(b, tag, &v, 8);
}

/* the block in an inheritable section */
static HANDLE launch_section(GByteArray *b)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE,
                                  0, b->len + 8, NULL);
    void *p;

    if (!h) {
        return NULL;
    }
    p = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, 0);
    if (!p) {
        CloseHandle(h);
        return NULL;
    }
    stl_le_p(p, b->len);
    memcpy((char *)p + 8, b->data, b->len);
    UnmapViewOfFile(p);
    return h;
}

W32ULaunch *w32u_launch_read(void)
{
    const char *s = g_getenv("QEMU_W32U_LAUNCH");
    W32ULaunch *l;
    HANDLE h;
    uint8_t *p, *q, *end;

    if (!s) {
        return NULL;
    }
    h = (HANDLE)(uintptr_t)g_ascii_strtoull(s, NULL, 10);
    /* not for the processes this one starts */
    SetEnvironmentVariableW(L"QEMU_W32U_LAUNCH", NULL);
    g_unsetenv("QEMU_W32U_LAUNCH");
    p = MapViewOfFile(h, FILE_MAP_READ, 0, 0, 0);
    if (!p) {
        fprintf(stderr, "qemu: cannot read the launch block\n");
        exit(EXIT_FAILURE);
    }
    l = g_new0(W32ULaunch, 1);
    l->args = g_ptr_array_new();
    l->env = g_ptr_array_new();
    l->regions = g_array_new(false, false, sizeof(uint64_t) * 3);
    q = p + 8;
    end = q + ldl_le_p(p);
    while (q + 8 <= end) {
        uint32_t tag = ldl_le_p(q), len = ldl_le_p(q + 4);
        uint8_t *d = q + 8;
        uint64_t v = len >= 8 ? ldq_le_p(d) : 0;

        switch (tag) {
        case L_ARG:
            g_ptr_array_add(l->args, g_strdup((char *)d));
            break;
        case L_ENV:
            g_ptr_array_add(l->env, g_strdup((char *)d));
            break;
        case L_FDS:
            l->fds = g_strdup((char *)d);
            break;
        case L_VPID:
            l->vpid = v;
            break;
        case L_PPID:
            l->ppid = v;
            break;
        case L_SYSROOT:
            l->sysroot = g_strdup((char *)d);
            break;
        case L_CPU:
            l->cpu = g_strdup((char *)d);
            break;
        case L_PATH:
            l->path = g_strdup((char *)d);
            break;
        case L_FORK_PARENT:
            l->fork = true;
            l->parent = (HANDLE)(uintptr_t)v;
            break;
        case L_FORK_BASE:
            l->parent_base = v;
            break;
        case L_REGION:
            g_array_append_vals(l->regions, d, 1);
            break;
        case L_MEMSTATE:
            memcpy(l->memstate, d, MIN(len, sizeof(l->memstate)));
            break;
        case L_ENVBYTES:
            l->envbytes = g_memdup2(d, len);
            l->envlen = len;
            break;
        case L_FORK_EVENT:
            l->copied = (HANDLE)(uintptr_t)v;
            break;
        case L_CLONE:
            memcpy(l->clone, d, MIN(len, sizeof(l->clone)));
            break;
        case L_SIGNALS:
            if (len == sizeof(W32USignalState)) {
                l->signals = g_memdup2(d, len);
            }
            break;
        }
        q = d + len;
    }
    g_ptr_array_add(l->args, NULL);
    g_ptr_array_add(l->env, NULL);
    UnmapViewOfFile(p);
    CloseHandle(h);
    w32u_qemu_parent = true;
    return l;
}

/* ---- children ---------------------------------------------------------- */

typedef struct Child {
    abi_long pid;
    HANDLE process;
} Child;

static GArray *children;            /* Child */
static QemuMutex children_lock;

static VOID CALLBACK child_ended(PVOID opaque, BOOLEAN timeout)
{
    w32u_raise_process(17);                 /* SIGCHLD */
}

static void child_add(abi_long pid, HANDLE process)
{
    Child c = { pid, process };
    HANDLE wait;

    RegisterWaitForSingleObject(&wait, process, child_ended, NULL, INFINITE,
                                WT_EXECUTEONLYONCE);

    qemu_mutex_lock(&children_lock);
    g_array_append_val(children, c);
    qemu_mutex_unlock(&children_lock);
}

/* the wait status of Linux for an exit code of Windows */
static int wait_status(DWORD code)
{
    if ((code & 0xff000000) == 0x40000000) {
        int sig = code & 0x7f;
        bool core = sig == 3 || sig == 4 || sig == 5 || sig == 6 ||
                    sig == 7 || sig == 8 || sig == 11;

        return sig | (core ? 0x80 : 0);
    }
    if (code >= 0xc0000000) {
        return 11;                      /* a crash of the host: SIGSEGV */
    }
    return (code & 0xff) << 8;
}

#define LX_WNOHANG 1

abi_long w32u_wait4(abi_long pid, abi_ulong status_addr, int options,
                    abi_ulong rusage)
{
    for (;;) {
        HANDLE hs[MAXIMUM_WAIT_OBJECTS];
        int idx[MAXIMUM_WAIT_OBJECTS];
        int n = 0, i;
        DWORD r;

        qemu_mutex_lock(&children_lock);
        for (i = 0; i < children->len && n < MAXIMUM_WAIT_OBJECTS; i++) {
            Child *c = &g_array_index(children, Child, i);

            if (pid <= 0 || pid == -1 || c->pid == pid) {
                hs[n] = c->process;
                idx[n++] = i;
            }
        }
        if (!n) {
            qemu_mutex_unlock(&children_lock);
            return -LX_ECHILD;
        }
        r = WaitForMultipleObjects(n, hs, FALSE, 0);
        if (r < WAIT_OBJECT_0 + n) {
            Child c = g_array_index(children, Child, idx[r - WAIT_OBJECT_0]);
            DWORD code = 0;
            int32_t st;

            g_array_remove_index(children, idx[r - WAIT_OBJECT_0]);
            qemu_mutex_unlock(&children_lock);
            GetExitCodeProcess(c.process, &code);
            CloseHandle(c.process);
            st = wait_status(code);
            if (status_addr) {
                w32u_put_guest(status_addr, &st, sizeof(st));
            }
            if (rusage) {
                uint8_t zero[144] = { 0 };

                w32u_put_guest(rusage, zero, sizeof(zero));
            }
            return c.pid;
        }
        qemu_mutex_unlock(&children_lock);
        if (options & LX_WNOHANG) {
            return 0;
        }
        if (w32u_signal_pending()) {
            return -LX_EINTR;
        }
        WaitForMultipleObjects(n, hs, FALSE, 50);
    }
}

/* ---- starting a process ------------------------------------------------- */

static void common_records(GByteArray *b)
{
    W32USignalState sigs;

    /* the actions and the mask: execve keeps the ignored ones */
    w32u_signal_export(&sigs);
    put_rec(b, L_SIGNALS, &sigs, sizeof(sigs));
    if (w32u_sysroot) {
        put_str(b, L_SYSROOT, w32u_sysroot);
    }
    put_str(b, L_CPU, w32u_cpu_type);
}

/*
 * Start @exe with the launch block @b and the guest's descriptors; returns
 * the process (its ID in *pid), or NULL with errno of Linux in *err
 */
static HANDLE start_process(const char *exe, GByteArray *b, bool exec,
                            const HANDLE *extra, int nextra,
                            DWORD *pid, abi_long *err)
{
    GArray *list = g_array_new(false, false, sizeof(HANDLE));
    GArray *inherit = g_array_new(false, false, sizeof(HANDLE));
    HANDLE std[3] = { NULL, NULL, NULL }, section;
    g_autofree char *fds = w32u_fds_export(inherit, exec, std);
    g_autofree gunichar2 *wexe = g_utf8_to_utf16(exe, -1, NULL, NULL, NULL);
    g_autofree gunichar2 *wcmd = NULL;
    STARTUPINFOEXW si = { 0 };
    PROCESS_INFORMATION pi;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs;
    SIZE_T attrs_size = 0;
    g_autofree char *cmd = NULL;
    wchar_t var[32];
    BOOL ok;
    guint i;

    put_str(b, L_FDS, fds);
    section = launch_section(b);
    if (!section) {
        *err = -LX_ENOMEM;
        goto out;
    }
    g_array_append_val(inherit, section);
    swprintf(var, 32, L"%llu", (unsigned long long)(uintptr_t)section);
    SetEnvironmentVariableW(L"QEMU_W32U_LAUNCH", var);

    cmd = g_strdup_printf("\"%s\"", exe);
    wcmd = g_utf8_to_utf16(cmd, -1, NULL, NULL, NULL);
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = std[0];
    si.StartupInfo.hStdOutput = std[1];
    si.StartupInfo.hStdError = std[2];
    /* what the child inherits: ours to close after, the caller's */
    g_array_append_vals(list, inherit->data, inherit->len);
    g_array_append_vals(list, extra, nextra);
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrs_size);
    attrs = g_malloc(attrs_size);
    InitializeProcThreadAttributeList(attrs, 1, 0, &attrs_size);
    UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                              list->data, list->len * sizeof(HANDLE),
                              NULL, NULL);
    si.lpAttributeList = attrs;
    ok = CreateProcessW((wchar_t *)wexe, (wchar_t *)wcmd, NULL, NULL, TRUE,
                        EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                        &si.StartupInfo, &pi);
    SetEnvironmentVariableW(L"QEMU_W32U_LAUNCH", NULL);
    DeleteProcThreadAttributeList(attrs);
    g_free(attrs);
    if (!ok) {
        *err = GetLastError() == ERROR_FILE_NOT_FOUND ? -LX_ENOENT : -LX_EAGAIN;
        goto out;
    }
    CloseHandle(pi.hThread);
    *pid = pi.dwProcessId;
    *err = 0;

out:
    /* our copies of what the child inherited */
    for (i = 0; i < inherit->len; i++) {
        CloseHandle(g_array_index(inherit, HANDLE, i));
    }
    g_array_free(inherit, true);
    g_array_free(list, true);
    return *err ? NULL : pi.hProcess;
}

/* ---- execve ------------------------------------------------------------ */

static char *qemu_for_machine(int machine)
{
    const char *arch = machine == 62 ? "x86_64" :
                       machine == 183 ? "aarch64" : NULL;
    wchar_t self[MAX_PATH];
    g_autofree char *s = NULL, *dir = NULL;
    char *exe;

    if (!arch || !GetModuleFileNameW(NULL, self, MAX_PATH)) {
        return NULL;
    }
    s = g_utf16_to_utf8((gunichar2 *)self, -1, NULL, NULL, NULL);
    dir = g_path_get_dirname(s);
    exe = g_strdup_printf("%s\\qemu-%s.exe", dir, arch);
    if (!g_file_test(exe, G_FILE_TEST_EXISTS)) {
        g_free(exe);
        return NULL;
    }
    return exe;
}

/*
 * The program to run for @path and @argv: "#!" scripts become their
 * interpreter; *exe is the qemu-ARCH.exe for its architecture
 */
static abi_long resolve_program(char **path, GPtrArray *argv, char **exe)
{
    int depth;

    for (depth = 0; depth < 5; depth++) {
        g_autofree char *hp = w32u_host_path(*path);
        char head[256];
        FILE *f = fopen(hp, "rb");
        size_t n;

        if (!f) {
            return errno == ENOENT ? -LX_ENOENT : -LX_EACCES;
        }
        n = fread(head, 1, sizeof(head) - 1, f);
        fclose(f);
        head[n] = 0;
        if (n >= 20 && !memcmp(head, "\x7f" "ELF", 4)) {
            *exe = qemu_for_machine(lduw_le_p(head + 18));
            return *exe ? 0 : -LX_ENOEXEC;
        }
        if (n >= 2 && head[0] == '#' && head[1] == '!') {
            char *p = head + 2, *nl = strchr(p, '\n'), *interp, *arg;

            if (nl) {
                *nl = 0;
            }
            while (*p == ' ' || *p == '\t') {
                p++;
            }
            interp = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\r') {
                p++;
            }
            arg = NULL;
            if (*p) {
                *p++ = 0;
                while (*p == ' ' || *p == '\t') {
                    p++;
                }
                g_strchomp(p);
                if (*p) {
                    arg = p;
                }
            }
            if (!*interp) {
                return -LX_ENOEXEC;
            }
            /* argv: interpreter, its argument, the script, the rest */
            g_free(g_ptr_array_index(argv, 0));
            argv->pdata[0] = g_strdup(*path);
            if (arg) {
                g_ptr_array_insert(argv, 0, g_strdup(arg));
            }
            g_ptr_array_insert(argv, 0, g_strdup(interp));
            g_free(*path);
            *path = g_strdup(interp);
            continue;
        }
        return -LX_ENOEXEC;
    }
    return -LX_ELOOP;
}

/* a string of argv or envp: up to MAX_ARG_STRLEN (128 KiB), as Linux */
static abi_long read_arg(abi_ulong addr, char **out)
{
    GString *g = g_string_new(NULL);

    while (g->len < 128 * 1024) {
        char c;

        if (w32u_get_guest(addr++, &c, 1)) {
            g_string_free(g, true);
            return -LX_EFAULT;
        }
        if (!c) {
            *out = g_string_free(g, false);
            return 0;
        }
        g_string_append_c(g, c);
    }
    g_string_free(g, true);
    return -LX_E2BIG;
}

static abi_long read_strv(abi_ulong addr, GPtrArray *out)
{
    for (;; addr += 8) {
        uint64_t s;
        char *str;
        abi_long ret;

        if (w32u_get_guest(addr, &s, sizeof(s))) {
            return -LX_EFAULT;
        }
        if (!s) {
            return 0;
        }
        ret = read_arg(s, &str);
        if (ret) {
            return ret;
        }
        g_ptr_array_add(out, str);
        if (out->len > 100000) {
            return -LX_E2BIG;
        }
    }
}

abi_long w32u_execve(abi_ulong path_addr, abi_ulong argv_addr,
                     abi_ulong envp_addr)
{
    g_autoptr(GPtrArray) argv = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GPtrArray) envp = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GByteArray) b = g_byte_array_new();
    g_autofree char *path = NULL, *exe = NULL, *hp = NULL;
    HANDLE process;
    DWORD pid, code = 0;
    abi_long ret;
    guint i;

    ret = w32u_get_guest_str(path_addr, &path);
    if (!ret && argv_addr) {
        ret = read_strv(argv_addr, argv);
    }
    if (!ret && envp_addr) {
        ret = read_strv(envp_addr, envp);
    }
    if (ret) {
        return ret;
    }
    if (!argv->len) {
        g_ptr_array_add(argv, g_strdup(path));
    }
    ret = resolve_program(&path, argv, &exe);
    if (ret) {
        return ret;
    }
    hp = w32u_host_path(path);
    for (i = 0; i < argv->len; i++) {
        put_str(b, L_ARG, g_ptr_array_index(argv, i));
    }
    for (i = 0; i < envp->len; i++) {
        put_str(b, L_ENV, g_ptr_array_index(envp, i));
    }
    put_str(b, L_PATH, hp);
    /* the same process for the guest: its PIDs */
    put_u64(b, L_VPID, w32u_vpid);
    put_u64(b, L_PPID, w32u_vppid);
    common_records(b);
    process = start_process(exe, b, true, NULL, 0, &pid, &ret);
    if (!process) {
        return ret;
    }

    /*
     * This process is now the new program's: its descriptors go (the
     * readers of its pipes see their end), it ends with the program
     */
    w32u_become_proxy();
    w32u_fds_close_all();
    WaitForSingleObject(process, INFINITE);
    GetExitCodeProcess(process, &code);
    fflush(NULL);
    ExitProcess(code);
}

/* ---- fork ----------------------------------------------------------------- */

typedef struct RegionWalk {
    GByteArray *b;
} RegionWalk;

static int add_region(void *opaque, vaddr start, vaddr end, int flags)
{
    RegionWalk *w = opaque;
    uint64_t r[3] = { start, end, flags };

    put_rec(w->b, L_REGION, r, sizeof(r));
    return 0;
}

/*
 * fork(), vfork(), clone() of a process: a qemu-ARCH.exe that copies our
 * memory while our other vCPUs are stopped, then goes on with 0
 */
abi_long w32u_fork(CPUArchState *env, uint64_t flags, abi_ulong newsp,
                   abi_ulong ptid, abi_ulong ctid, abi_ulong tls)
{
    g_autoptr(GByteArray) b = g_byte_array_new();
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    RegionWalk w = { b };
    HANDLE self = NULL, copied, process;
    wchar_t exe[MAX_PATH];
    g_autofree char *exe8 = NULL;
    abi_ulong mem[4];
    uint64_t clone[4] = { newsp, (flags & 0x00080000) != 0, tls, 0 };
    DWORD pid;
    abi_long ret;

    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) {
        return -LX_EAGAIN;
    }
    exe8 = g_utf16_to_utf8((gunichar2 *)exe, -1, NULL, NULL, NULL);
    copied = CreateEventW(&sa, TRUE, FALSE, NULL);
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                    GetCurrentProcess(), &self,
                    PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION |
                    SYNCHRONIZE, TRUE, 0);
    if (!copied || !self) {
        ret = -LX_EAGAIN;
        goto out;
    }

    /* a snapshot: no other vCPU runs until the child has the memory */
    start_exclusive();
    mmap_lock();
    put_u64(b, L_FORK_PARENT, (uintptr_t)self);
    put_u64(b, L_FORK_BASE, guest_base);
    put_u64(b, L_FORK_EVENT, (uintptr_t)copied);
    put_u64(b, L_PPID, w32u_vpid);
    put_str(b, L_PATH, w32u_exec_path());
    walk_memory_regions(&w, add_region);
    w32u_mem_get_state(mem);
    put_rec(b, L_MEMSTATE, mem, sizeof(mem));
    put_rec(b, L_ENVBYTES, env, offsetof(CPUArchState, end_reset_fields));
    put_rec(b, L_CLONE, clone, sizeof(clone));
    common_records(b);
    {
        HANDLE extra[2] = { self, copied };

        process = start_process(exe8, b, false, extra, 2, &pid, &ret);
    }
    if (process) {
        HANDLE hs[2] = { copied, process };

        WaitForMultipleObjects(2, hs, FALSE, INFINITE);
    }
    mmap_unlock();
    end_exclusive();
    if (!process) {
        goto out;
    }
    child_add(pid, process);
    if (flags & 0x00100000) {           /* CLONE_PARENT_SETTID */
        uint32_t v = pid;

        w32u_put_guest(ptid, &v, sizeof(v));
    }
    ret = pid;

out:
    if (copied) {
        CloseHandle(copied);
    }
    if (self) {
        CloseHandle(self);
    }
    return ret;
}

/* the child of fork: the parent's memory and CPU, then its cpu_loop */
G_NORETURN void w32u_fork_child(W32ULaunch *l, CPUState *cpu)
{
    CPUArchState *env = cpu_env(cpu);
    guint i;

    for (i = 0; i < l->regions->len; i++) {
        uint64_t *r = &g_array_index(l->regions, uint64_t, i * 3);
        abi_ulong start = r[0], len = r[1] - r[0];
        int prot = r[2] & (PAGE_READ | PAGE_WRITE | PAGE_EXEC);
        SIZE_T got = 0;

        if (w32u_mmap(start, len, PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) < 0) {
            fprintf(stderr, "qemu: fork: no memory for 0x%llx\n",
                    (unsigned long long)start);
            exit(EXIT_FAILURE);
        }
        if (prot & PAGE_READ &&
            !ReadProcessMemory(l->parent,
                               (void *)(uintptr_t)(l->parent_base + start),
                               g2h_untagged(start), len, &got)) {
            fprintf(stderr, "qemu: fork: cannot copy 0x%llx: error %lu\n",
                    (unsigned long long)start, GetLastError());
            exit(EXIT_FAILURE);
        }
        w32u_mprotect(start, len, prot);
    }
    w32u_mem_set_state(l->memstate);
    SetEvent(l->copied);
    CloseHandle(l->copied);
    CloseHandle(l->parent);

    memcpy(env, l->envbytes, MIN(l->envlen,
                                 offsetof(CPUArchState, end_reset_fields)));
    w32u_env_after_fork(env);
    /* clone() of a process: its stack and TLS; and 0 as the result */
    w32u_clone_regs(env, l->clone[0], l->clone[1], l->clone[2]);
    tcg_prologue_init();
    cpu_loop(env);
}

void w32u_process_init(W32ULaunch *l)
{
    children = g_array_new(false, false, sizeof(Child));
    qemu_mutex_init(&children_lock);
    w32u_vpid = l && l->vpid ? l->vpid : GetCurrentProcessId();
    w32u_vppid = l && l->ppid ? l->ppid : 1;
}
