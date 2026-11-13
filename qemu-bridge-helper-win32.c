/*
 * QEMU bridge helper for Windows
 *
 * The helper of -netdev bridge and -netdev tap,helper=, as qemu-bridge-helper
 * on Linux: it checks the bridge against bridge.conf (allow/deny/include),
 * makes a TAP-Windows adapter, adds it to the network bridge of Windows
 * named by --br= and sends the handle of the TAP device to QEMU over the
 * socket --fd= (a handle QEMU let it inherit), as a handle in a frame
 * (qemu/win32-fdpass.h).  A TAP device of Linux goes away when QEMU closes
 * it: this helper stays until QEMU closes the socket, then takes the
 * adapter out of the bridge and removes it.
 *
 * Like the setuid helper of Linux, it needs privileges: administrator
 * rights, to make adapters and change bridges.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/queue.h"
#include "qemu/cutils.h"
#include "qemu/sockets.h"
#include "qemu/error-report.h"
#include "qemu/win32-fdpass.h"
#include "qapi/error.h"
#include "net/tap-win32-adapter.h"

#ifndef SIO_AF_UNIX_GETPEERPID
#define SIO_AF_UNIX_GETPEERPID _WSAIOR(IOC_VENDOR, 256)
#endif

#define DEFAULT_ACL_FILE CONFIG_QEMU_CONFDIR "/bridge.conf"
#define NAME_MAX_LEN 256

enum {
    ACL_ALLOW = 0,
    ACL_ALLOW_ALL,
    ACL_DENY,
    ACL_DENY_ALL,
};

typedef struct ACLRule {
    int type;
    char iface[NAME_MAX_LEN];
    QSIMPLEQ_ENTRY(ACLRule) entry;
} ACLRule;

typedef QSIMPLEQ_HEAD(ACLList, ACLRule) ACLList;

/* QEMU_BRIDGE_HELPER_DEBUG=1: the steps on stderr, with times */
static void dbg(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
static void dbg(const char *fmt, ...)
{
    static int on = -1;
    va_list ap;

    if (on < 0) {
        on = getenv("QEMU_BRIDGE_HELPER_DEBUG") != NULL;
    }
    if (!on) {
        return;
    }
    fprintf(stderr, "bridge-helper %lu %llu ms: ", GetCurrentProcessId(),
            (unsigned long long)GetTickCount64());
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/* The process that started us (QEMU) */
static DWORD parent_pid(void)
{
    typedef LONG (NTAPI *QueryFn)(HANDLE, int, PVOID, ULONG, PULONG);
    struct {
        PVOID reserved1;
        PVOID peb;
        PVOID reserved2[2];
        ULONG_PTR pid;
        ULONG_PTR parent;
    } info;
    QueryFn query = (QueryFn)(void *)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    ULONG len;

    if (!query || query(GetCurrentProcess(), 0 /* basic */, &info,
                        sizeof(info), &len) < 0) {
        return 0;
    }
    return (DWORD)info.parent;
}

static void usage(void)
{
    fprintf(stderr,
            "Usage: qemu-bridge-helper [--use-vnet] --br=bridge --fd=handle\n");
}

static int parse_acl_file(const char *filename, ACLList *acl_list)
{
    FILE *f;
    char line[4096];
    ACLRule *acl_rule;

    f = fopen(filename, "r");
    if (f == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        char *ptr = line;
        char *cmd, *arg, *argend;

        while (g_ascii_isspace(*ptr)) {
            ptr++;
        }
        if (*ptr == '#' || *ptr == 0) {
            continue;
        }
        cmd = ptr;
        arg = strchr(cmd, ' ');
        if (arg == NULL) {
            arg = strchr(cmd, '\t');
        }
        if (arg == NULL) {
            fprintf(stderr, "Invalid config line:\n  %s\n", line);
            goto err;
        }
        *arg = 0;
        arg++;
        while (g_ascii_isspace(*arg)) {
            arg++;
        }
        argend = arg + strlen(arg);
        while (arg != argend && g_ascii_isspace(*(argend - 1))) {
            argend--;
        }
        *argend = 0;

        if (!g_str_equal(cmd, "include") && strlen(arg) >= NAME_MAX_LEN) {
            fprintf(stderr, "name `%s' too long: %zu\n", arg, strlen(arg));
            goto err;
        }
        if (strcmp(cmd, "deny") == 0) {
            acl_rule = g_malloc(sizeof(*acl_rule));
            if (strcmp(arg, "all") == 0) {
                acl_rule->type = ACL_DENY_ALL;
            } else {
                acl_rule->type = ACL_DENY;
                snprintf(acl_rule->iface, NAME_MAX_LEN, "%s", arg);
            }
            QSIMPLEQ_INSERT_TAIL(acl_list, acl_rule, entry);
        } else if (strcmp(cmd, "allow") == 0) {
            acl_rule = g_malloc(sizeof(*acl_rule));
            if (strcmp(arg, "all") == 0) {
                acl_rule->type = ACL_ALLOW_ALL;
            } else {
                acl_rule->type = ACL_ALLOW;
                snprintf(acl_rule->iface, NAME_MAX_LEN, "%s", arg);
            }
            QSIMPLEQ_INSERT_TAIL(acl_list, acl_rule, entry);
        } else if (strcmp(cmd, "include") == 0) {
            /* ignore errors */
            parse_acl_file(arg, acl_list);
        } else {
            fprintf(stderr, "Unknown command `%s'\n", cmd);
            goto err;
        }
    }
    fclose(f);
    return 0;

err:
    fclose(f);
    errno = EINVAL;
    return -1;
}

int main(int argc, char **argv)
{
    const char *bridge = NULL;
    unsigned long long sock_arg = 0;
    SOCKET sock;
    g_autofree char *acl_file = NULL;
    g_autofree char *guid = NULL;
    g_autofree char *ifname = NULL;
    Error *err = NULL;
    ACLList acl_list;
    ACLRule *acl_rule;
    int access_allowed = 0, access_denied = 0;
    W32FdState st = { 0 };
    W32FdItem item;
    HANDLE tap;
    bool bridged = false;
    char byte = 0;
    struct iovec iov = { &byte, 1 };
    int index;
    int ret = EXIT_FAILURE;

    qemu_init_exec_dir(argv[0]);
    socket_init();

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--use-vnet") == 0) {
            /* TAP-Windows has no virtio-net header: nothing to do */
        } else if (strncmp(argv[index], "--br=", 5) == 0) {
            bridge = &argv[index][5];
        } else if (strncmp(argv[index], "--fd=", 5) == 0) {
            if (qemu_strtou64(&argv[index][5], NULL, 0, &sock_arg) < 0) {
                usage();
                return EXIT_FAILURE;
            }
        } else {
            usage();
            return EXIT_FAILURE;
        }
    }
    if (bridge == NULL || !sock_arg) {
        usage();
        return EXIT_FAILURE;
    }
    if (strlen(bridge) >= NAME_MAX_LEN) {
        fprintf(stderr, "name `%s' too long: %zu\n", bridge, strlen(bridge));
        return EXIT_FAILURE;
    }
    sock = (SOCKET)sock_arg;
    /*
     * Ours only: the programs we start (netsh) must not inherit it, or
     * their end may end the stream for QEMU
     */
    SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, 0);

    /* the ACL: deny wins over allow, the default is to deny */
    QSIMPLEQ_INIT(&acl_list);
    {
        /*
         * get_relocated_path() takes the program for one of bindir; this
         * one is in libexec, under the prefix
         */
        wchar_t wexe[MAX_PATH];
        DWORD len = GetModuleFileNameW(NULL, wexe, MAX_PATH);
        g_autofree char *exe = len && len < MAX_PATH ?
            g_utf16_to_utf8(wexe, len, NULL, NULL, NULL) : g_strdup("");
        g_autofree char *dir = g_path_get_dirname(exe);
        g_autofree char *base = g_path_get_basename(dir);

        if (!g_ascii_strcasecmp(base, "libexec")) {
            g_autofree char *prefix = g_path_get_dirname(dir);

            acl_file = g_build_filename(prefix, "etc", "bridge.conf", NULL);
        } else {
            acl_file = get_relocated_path(DEFAULT_ACL_FILE);
        }
    }
    if (parse_acl_file(acl_file, &acl_list) == -1) {
        fprintf(stderr, "failed to parse default acl file `%s'\n", acl_file);
        goto cleanup;
    }
    QSIMPLEQ_FOREACH(acl_rule, &acl_list, entry) {
        switch (acl_rule->type) {
        case ACL_ALLOW_ALL:
            access_allowed = 1;
            break;
        case ACL_ALLOW:
            if (strcmp(bridge, acl_rule->iface) == 0) {
                access_allowed = 1;
            }
            break;
        case ACL_DENY_ALL:
            access_denied = 1;
            break;
        case ACL_DENY:
            if (strcmp(bridge, acl_rule->iface) == 0) {
                access_denied = 1;
            }
            break;
        }
    }
    if (access_allowed == 0 || access_denied == 1) {
        fprintf(stderr, "access denied by acl file\n");
        goto cleanup;
    }

    /* a new TAP adapter, in the bridge */
    dbg("start: bridge %s, socket %llu", bridge, sock_arg);
    guid = tap_win32_adapter_create(NULL, &ifname, &err);
    dbg("adapter %s %s", guid ? ifname : "(failed)", guid ? guid : "");
    if (!guid) {
        error_report_err(err);
        goto cleanup;
    }
    if (!tap_win32_bridge_add(bridge, ifname, &err)) {
        dbg("bridge add failed");
        error_report_err(err);
        goto cleanup;
    }
    bridged = true;
    dbg("bridged");
    tap = tap_win32_adapter_open(guid, &err);
    dbg("opened: %p", tap);
    if (!tap) {
        error_report_err(err);
        goto cleanup;
    }

    /* the handle to QEMU */
    item.type = W32FD_HANDLE;
    item.handle = tap;
    {
        char c;
        int peek = recv(sock, &c, 1, MSG_PEEK);

        dbg("socket before send: peek %d, error %d", peek,
            peek < 0 ? WSAGetLastError() : 0);
    }
    if (w32fd_send(sock, &st, &iov, 1, &item, 1) != 1) {
        dbg("send failed: errno %d, wsa %d", errno, WSAGetLastError());
        fprintf(stderr, "failed to write fd to unix socket: %s\n",
                strerror(errno));
        CloseHandle(tap);
        goto cleanup;
    }
    CloseHandle(tap);
    dbg("sent the handle");

    /*
     * Until QEMU is gone: its process ends, or its end of the socket closes
     * (the socket alone is not enough: an end inherited by a process that
     * exits does not always show EOF)
     */
    {
        WSAEVENT ev = WSACreateEvent();
        HANDLE hs[2] = { ev, NULL };
        DWORD n = 1, pid = 0, bytes;
        char c;

        /*
         * QEMU: the peer of the socket, else our parent (QEMU starts us)
         */
        if (WSAIoctl(sock, SIO_AF_UNIX_GETPEERPID, NULL, 0, &pid, sizeof(pid),
                     &bytes, NULL, NULL) != 0 || !pid) {
            dbg("peer pid: wsa error %d", WSAGetLastError());
            pid = parent_pid();
        }
        hs[1] = pid ? OpenProcess(SYNCHRONIZE, FALSE, pid) : NULL;
        dbg("waiting for QEMU %lu (process handle %p, error %lu)", pid,
            hs[1], hs[1] ? 0 : GetLastError());
        if (hs[1]) {
            n = 2;
        }
        WSAEventSelect(sock, ev, FD_READ | FD_CLOSE);
        for (;;) {
            DWORD w = WaitForMultipleObjects(n, hs, FALSE, INFINITE);
            int r;

            if (w != WAIT_OBJECT_0) {
                dbg("woken: %s", w == WAIT_OBJECT_0 + 1 ? "QEMU ended"
                                                          : "wait failed");
                break;
            }
            WSAResetEvent(ev);
            r = recv(sock, &c, 1, 0);
            dbg("woken by the socket: recv %d, wsa %d", r,
                r < 0 ? WSAGetLastError() : 0);
            if (r == 0 || (r < 0 && WSAGetLastError() != WSAEWOULDBLOCK)) {
                break;
            }
        }
        if (hs[1]) {
            CloseHandle(hs[1]);
        }
        WSACloseEvent(ev);
    }
    dbg("QEMU gone");
    ret = EXIT_SUCCESS;

cleanup:
    dbg("cleanup");
    if (bridged && !tap_win32_bridge_remove(bridge, ifname, &err)) {
        error_report_err(err);
        err = NULL;
    }
    dbg("out of the bridge");
    if (guid && !tap_win32_adapter_remove(guid, &err)) {
        error_report_err(err);
    }
    dbg("adapter removed: done");
    w32fd_state_free(&st);
    return ret;
}
