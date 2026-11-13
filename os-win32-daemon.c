/*
 * -daemonize on Windows
 *
 * There is no fork(): the process starts itself again, detached from the
 * console, with the same command line and a pipe in QEMU_DAEMON_PIPE.
 * As with the double fork() of os-posix.c, the first process waits on
 * that pipe and exits with success only when the daemon writes a zero
 * byte to it at the end of its initialization (os_setup_post()).
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"

#define DAEMON_PIPE_ENV "QEMU_DAEMON_PIPE"

static bool daemonize;
static HANDLE daemon_pipe = INVALID_HANDLE_VALUE;

int os_set_daemonize(bool d)
{
    daemonize = d;
    return 0;
}

bool is_daemonized(void)
{
    return daemonize;
}

/* @h duplicated as inheritable into @list, if it is a valid handle */
static void add_inheritable(HANDLE h, HANDLE *list, DWORD *n)
{
    HANDLE dup;

    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        return;
    }
    if (DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &dup,
                        0, TRUE, DUPLICATE_SAME_ACCESS)) {
        list[(*n)++] = dup;
    }
}

static void G_NORETURN start_daemon(void)
{
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    STARTUPINFOEXW si = { 0 };
    PROCESS_INFORMATION pi;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs;
    HANDLE inherit[4], rd, wr;
    wchar_t exe[MAX_PATH * 4], env[32];
    DWORD n = 0, len = 0, i;
    SIZE_T attrs_size = 0;
    uint8_t status = 1;
    BOOL ok;

    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        error_report("daemonize: cannot create a pipe (error %lu)",
                     GetLastError());
        exit(1);
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    inherit[n++] = wr;

    /* the daemon keeps stdout and stderr until os_setup_post() */
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    add_inheritable(GetStdHandle(STD_INPUT_HANDLE), inherit, &n);
    si.StartupInfo.hStdInput = n > 1 ? inherit[n - 1] : NULL;
    i = n;
    add_inheritable(GetStdHandle(STD_OUTPUT_HANDLE), inherit, &n);
    si.StartupInfo.hStdOutput = n > i ? inherit[n - 1] : NULL;
    i = n;
    add_inheritable(GetStdHandle(STD_ERROR_HANDLE), inherit, &n);
    si.StartupInfo.hStdError = n > i ? inherit[n - 1] : NULL;

    /* only these handles are inherited */
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrs_size);
    attrs = g_malloc(attrs_size);
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attrs_size) ||
        !UpdateProcThreadAttribute(attrs, 0,
                                   PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inherit, n * sizeof(HANDLE), NULL, NULL)) {
        error_report("daemonize: cannot set up the process (error %lu)",
                     GetLastError());
        exit(1);
    }
    si.lpAttributeList = attrs;

    swprintf(env, G_N_ELEMENTS(env), L"%llu",
             (unsigned long long)(uintptr_t)wr);
    SetEnvironmentVariableW(L"" DAEMON_PIPE_ENV, env);
    GetModuleFileNameW(NULL, exe, G_N_ELEMENTS(exe));

    ok = CreateProcessW(exe, GetCommandLineW(), NULL, NULL, TRUE,
                        DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP |
                        EXTENDED_STARTUPINFO_PRESENT,
                        NULL, NULL, &si.StartupInfo, &pi);
    if (!ok) {
        error_report("daemonize: cannot start the daemon (error %lu)",
                     GetLastError());
        exit(1);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    for (i = 0; i < n; i++) {
        CloseHandle(inherit[i]);
    }
    DeleteProcThreadAttributeList(attrs);
    g_free(attrs);

    /*
     * only exit successfully if our child actually wrote a one-byte zero
     * to our pipe, upon successful init
     */
    ok = ReadFile(rd, &status, 1, &len, NULL);
    exit(ok && len == 1 && status == 0 ? 0 : 1);
}

void os_daemonize(void)
{
    const char *pipe_env;

    if (!daemonize) {
        return;
    }
    pipe_env = getenv(DAEMON_PIPE_ENV);
    if (!pipe_env) {
        start_daemon();
    }

    /* the daemon */
    daemon_pipe = (HANDLE)(uintptr_t)g_ascii_strtoull(pipe_env, NULL, 10);
    SetEnvironmentVariableW(L"" DAEMON_PIPE_ENV, NULL);
    g_unsetenv(DAEMON_PIPE_ENV);
    SetHandleInformation(daemon_pipe, HANDLE_FLAG_INHERIT, 0);
}

void os_setup_post(void)
{
    uint8_t status = 0;
    DWORD len;
    int fd;

    if (!daemonize) {
        return;
    }
    if (chdir("/")) {
        error_report("not able to chdir to /: %s", strerror(errno));
        exit(1);
    }
    fd = qemu_open_old("NUL", O_RDWR);
    if (fd == -1) {
        exit(1);
    }
    dup2(fd, 0);
    dup2(fd, 1);
    SetStdHandle(STD_INPUT_HANDLE, (HANDLE)_get_osfhandle(0));
    SetStdHandle(STD_OUTPUT_HANDLE, (HANDLE)_get_osfhandle(1));
    /* In case -D is given do not redirect stderr to NUL */
    if (!qemu_log_enabled()) {
        dup2(fd, 2);
        SetStdHandle(STD_ERROR_HANDLE, (HANDLE)_get_osfhandle(2));
    }
    close(fd);

    if (!WriteFile(daemon_pipe, &status, 1, &len, NULL) || len != 1) {
        exit(1);
    }
    CloseHandle(daemon_pipe);
    daemon_pipe = INVALID_HANDLE_VALUE;
}
