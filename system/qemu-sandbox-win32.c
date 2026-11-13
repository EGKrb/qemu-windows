/*
 * -sandbox on Windows
 *
 * The seccomp filter of Linux forbids system calls QEMU does not need;
 * Windows has no system call filter for user programs, the nearest
 * mechanisms are used instead, each for the set of seccomp it stands for:
 *
 * default (on)             the privileges for what the default set denies
 *                          (shutdown and reboot, drivers as modules, system
 *                          time, firmware variables, mounts) are removed
 *                          from the token; no legacy extension DLLs, no
 *                          DLLs from remote shares or of low integrity
 * elevateprivileges=deny   every privilege is removed but the traversal one
 *                          (SeChangeNotifyPrivilege), as setuid() is denied;
 *                          "children" does the same (no setuid helpers)
 * spawn=deny               a job object of one process: CreateProcess fails
 * resourcecontrol=deny     the job object fixes the priority class and the
 *                          CPU affinity of the process to the current ones
 * obsolete                 no obsolete system calls to deny on Windows
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/config-file.h"
#include "qemu/option.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "system/seccomp.h"

static const wchar_t *const default_denied_privileges[] = {
    L"SeShutdownPrivilege",             /* reboot */
    L"SeRemoteShutdownPrivilege",
    L"SeLoadDriverPrivilege",           /* init_module, delete_module */
    L"SeSystemtimePrivilege",           /* settimeofday, stime, adjtimex */
    L"SeTimeZonePrivilege",
    L"SeSystemEnvironmentPrivilege",    /* firmware variables */
    L"SeManageVolumePrivilege",         /* mount, umount, swapon */
    L"SeCreatePagefilePrivilege",       /* swapon, swapoff */
    L"SeTcbPrivilege",
    L"SeAuditPrivilege",                /* acct */
    NULL
};

/* Remove @names from the token, or all but SeChangeNotifyPrivilege */
static int remove_privileges(const wchar_t *const *names, Error **errp)
{
    HANDLE token;
    g_autofree TOKEN_PRIVILEGES *privs = NULL;
    LUID change_notify;
    DWORD size = 0, i;
    int ret = -1;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
        error_setg_win32(errp, GetLastError(), "sandbox: cannot open token");
        return -1;
    }
    if (names) {
        size_t n = 0;

        while (names[n]) {
            n++;
        }
        privs = g_malloc0(sizeof(TOKEN_PRIVILEGES) +
                          n * sizeof(LUID_AND_ATTRIBUTES));
        for (i = 0; i < n; i++) {
            /* privileges the system does not know are left out */
            if (LookupPrivilegeValueW(NULL, names[i],
                    &privs->Privileges[privs->PrivilegeCount].Luid)) {
                privs->Privileges[privs->PrivilegeCount++].Attributes =
                    SE_PRIVILEGE_REMOVED;
            }
        }
    } else {
        GetTokenInformation(token, TokenPrivileges, NULL, 0, &size);
        privs = g_malloc0(size);
        if (!GetTokenInformation(token, TokenPrivileges, privs, size,
                                 &size)) {
            error_setg_win32(errp, GetLastError(),
                             "sandbox: cannot read the privileges");
            goto out;
        }
        LookupPrivilegeValueW(NULL, L"SeChangeNotifyPrivilege",
                              &change_notify);
        for (i = 0; i < privs->PrivilegeCount; i++) {
            LUID_AND_ATTRIBUTES *p = &privs->Privileges[i];

            if (p->Luid.LowPart == change_notify.LowPart &&
                p->Luid.HighPart == change_notify.HighPart) {
                p->Attributes = 0;      /* left as it is */
            } else {
                p->Attributes = SE_PRIVILEGE_REMOVED;
            }
        }
    }

    /* removing a privilege the token does not have is not an error */
    for (i = 0; i < privs->PrivilegeCount; i++) {
        TOKEN_PRIVILEGES one = {
            .PrivilegeCount = 1,
            .Privileges[0] = privs->Privileges[i],
        };

        if (one.Privileges[0].Attributes != SE_PRIVILEGE_REMOVED) {
            continue;
        }
        AdjustTokenPrivileges(token, FALSE, &one, 0, NULL, NULL);
    }
    ret = 0;
out:
    CloseHandle(token);
    return ret;
}

static int set_mitigations(Error **errp)
{
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ext = {
        .DisableExtensionPoints = 1,
    };
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY img = {
        .NoRemoteImages = 1,
        .NoLowMandatoryLabelImages = 1,
    };

    if (!SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy,
                                    &ext, sizeof(ext)) ||
        !SetProcessMitigationPolicy(ProcessImageLoadPolicy,
                                    &img, sizeof(img))) {
        error_setg_win32(errp, GetLastError(),
                         "sandbox: cannot set the mitigation policies");
        return -1;
    }
    return 0;
}

static int set_job_limits(bool spawn, bool resourcectl, Error **errp)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = { 0 };
    JOBOBJECT_BASIC_LIMIT_INFORMATION *basic = &info.BasicLimitInformation;
    DWORD_PTR process_mask, system_mask;
    HANDLE job;

    if (spawn) {
        basic->LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        basic->ActiveProcessLimit = 1;
    }
    if (resourcectl) {
        basic->LimitFlags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS;
        basic->PriorityClass = GetPriorityClass(GetCurrentProcess());
        if (GetProcessAffinityMask(GetCurrentProcess(), &process_mask,
                                   &system_mask)) {
            basic->LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY;
            basic->Affinity = process_mask;
        }
    }

    job = CreateJobObjectW(NULL, NULL);
    if (!job ||
        !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &info, sizeof(info)) ||
        !AssignProcessToJobObject(job, GetCurrentProcess())) {
        error_setg_win32(errp, GetLastError(),
                         "sandbox: cannot set up the job object");
        if (job) {
            CloseHandle(job);
        }
        return -1;
    }
    /* the job lives as long as the process: its handle is kept */
    return 0;
}

static int sandbox_start(uint32_t opts, Error **errp)
{
    if (remove_privileges(default_denied_privileges, errp) < 0 ||
        set_mitigations(errp) < 0) {
        return -1;
    }
    if ((opts & QEMU_SECCOMP_SET_PRIVILEGED) &&
        remove_privileges(NULL, errp) < 0) {
        return -1;
    }
    if (opts & (QEMU_SECCOMP_SET_SPAWN | QEMU_SECCOMP_SET_RESOURCECTL)) {
        return set_job_limits(opts & QEMU_SECCOMP_SET_SPAWN,
                              opts & QEMU_SECCOMP_SET_RESOURCECTL, errp);
    }
    return 0;
}

int parse_sandbox(void *opaque, QemuOpts *opts, Error **errp)
{
    if (qemu_opt_get_bool(opts, "enable", false)) {
        uint32_t sandbox_opts = QEMU_SECCOMP_SET_DEFAULT
                | QEMU_SECCOMP_SET_OBSOLETE;
        const char *value = NULL;

        value = qemu_opt_get(opts, "obsolete");
        if (value && !g_str_equal(value, "allow") &&
            !g_str_equal(value, "deny")) {
            error_setg(errp, "invalid argument for obsolete");
            return -1;
        }

        value = qemu_opt_get(opts, "elevateprivileges");
        if (value) {
            if (g_str_equal(value, "deny") ||
                g_str_equal(value, "children")) {
                sandbox_opts |= QEMU_SECCOMP_SET_PRIVILEGED;
            } else if (!g_str_equal(value, "allow")) {
                error_setg(errp, "invalid argument for elevateprivileges");
                return -1;
            }
        }

        value = qemu_opt_get(opts, "spawn");
        if (value) {
            if (g_str_equal(value, "deny")) {
                sandbox_opts |= QEMU_SECCOMP_SET_SPAWN;
            } else if (!g_str_equal(value, "allow")) {
                error_setg(errp, "invalid argument for spawn");
                return -1;
            }
        }

        value = qemu_opt_get(opts, "resourcecontrol");
        if (value) {
            if (g_str_equal(value, "deny")) {
                sandbox_opts |= QEMU_SECCOMP_SET_RESOURCECTL;
            } else if (!g_str_equal(value, "allow")) {
                error_setg(errp, "invalid argument for resourcecontrol");
                return -1;
            }
        }

        if (sandbox_start(sandbox_opts, errp) < 0) {
            return -1;
        }
    }

    return 0;
}

static QemuOptsList qemu_sandbox_opts = {
    .name = "sandbox",
    .implied_opt_name = "enable",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_sandbox_opts.head),
    .desc = {
        {
            .name = "enable",
            .type = QEMU_OPT_BOOL,
        },
        {
            .name = "obsolete",
            .type = QEMU_OPT_STRING,
        },
        {
            .name = "elevateprivileges",
            .type = QEMU_OPT_STRING,
        },
        {
            .name = "spawn",
            .type = QEMU_OPT_STRING,
        },
        {
            .name = "resourcecontrol",
            .type = QEMU_OPT_STRING,
        },
        { /* end of list */ }
    },
};

static void sandbox_register(void)
{
    qemu_add_opts(&qemu_sandbox_opts);
}
opts_init(sandbox_register);
