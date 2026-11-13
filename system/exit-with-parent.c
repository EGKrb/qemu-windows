/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Originally derived from nbdkit common/utils/exit-with-parent.c
 * Copyright Red Hat
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of Red Hat nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY RED HAT AND CONTRIBUTORS ''AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL RED HAT OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Implement the --exit-with-parent feature on operating systems which
 * support it.
 */

#include "qemu/osdep.h"
#include "qemu/exit-with-parent.h"

#if defined(__linux__)

#include <sys/prctl.h>

/*
 * Send SIGTERM to self when the parent exits.  This will cause
 * qemu_system_killed() to be called.
 *
 * PR_SET_PDEATHSIG has been defined since Linux 2.1.57.
 */
int
set_exit_with_parent(void)
{
    return prctl(PR_SET_PDEATHSIG, SIGTERM);
}

#elif defined(__FreeBSD__)

#include <sys/procctl.h>

/*
 * Send SIGTERM to self when the parent exits.  This will cause
 * qemu_system_killed() to be called.
 *
 * PROC_PDEATHSIG_CTL has been defined since FreeBSD 11.2.
 */
int
set_exit_with_parent(void)
{
    const int sig = SIGTERM;
    return procctl(P_PID, 0, PROC_PDEATHSIG_CTL, (void *) &sig);
}

#elif defined(__APPLE__)

/* For macOS. */

#include "qemu/thread.h"
#include "qemu/error-report.h"
#include "system/runstate.h"
#include <sys/event.h>

static void *
exit_with_parent_loop(void *vp)
{
    const pid_t ppid = getppid();
    int fd;
    struct kevent kev, res[1];
    int r;

    /* Register the kevent to wait for ppid to exit. */
    fd = kqueue();
    if (fd == -1) {
        error_report("exit_with_parent_loop: kqueue: %m");
        return NULL;
    }
    EV_SET(&kev, ppid, EVFILT_PROC, EV_ADD | EV_ENABLE, NOTE_EXIT, 0, NULL);
    if (kevent(fd, &kev, 1, NULL, 0, NULL) == -1) {
        error_report("exit_with_parent_loop: kevent: %m");
        close(fd);
        return NULL;
    }

    /* Wait for the kevent to happen. */
    r = kevent(fd, 0, 0, res, 1, NULL);
    if (r == 1 && res[0].ident == ppid) {
        /* Behave like Linux and FreeBSD above, as if SIGTERM was sent */
        qemu_system_killed(SIGTERM, ppid);
    }
    close(fd);

    return NULL;
}

int
set_exit_with_parent(void)
{
    QemuThread exit_with_parent_thread;

    /*
     * We have to block waiting for kevent, so that requires that we
     * start a background thread.
     */
    qemu_thread_create(&exit_with_parent_thread,
                       "exit-parent",
                       exit_with_parent_loop, NULL,
                       QEMU_THREAD_DETACHED);
    return 0;
}

#elif defined(_WIN32)

/*
 * For Windows: a thread waits on the handle of the parent process, found
 * by its id in a snapshot of the processes.  The parent must have started
 * before us, or its id was reused by another process: the parent is then
 * already gone.
 */

#include <tlhelp32.h>
#include "qemu/thread.h"
#include "qemu/error-report.h"
#include "system/runstate.h"

static HANDLE parent_process;
static DWORD parent_pid;

static void *
exit_with_parent_loop(void *vp)
{
    WaitForSingleObject(parent_process, INFINITE);
    /* Behave like Linux and FreeBSD above, as if SIGTERM was sent */
    qemu_system_killed(SIGTERM, parent_pid);
    return NULL;
}

static uint64_t
process_start_time(HANDLE process)
{
    FILETIME created, exited, kernel, user;

    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        return 0;
    }
    return ((uint64_t)created.dwHighDateTime << 32) | created.dwLowDateTime;
}

int
set_exit_with_parent(void)
{
    QemuThread exit_with_parent_thread;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD self = GetCurrentProcessId();
    HANDLE snapshot;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return -1;
    }
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == self) {
                parent_pid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);

    parent_process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                 FALSE, parent_pid);
    if (!parent_process ||
        process_start_time(parent_process) >
        process_start_time(GetCurrentProcess())) {
        /* the parent has exited already */
        qemu_system_killed(SIGTERM, parent_pid);
        return 0;
    }

    qemu_thread_create(&exit_with_parent_thread,
                       "exit-parent",
                       exit_with_parent_loop, NULL,
                       QEMU_THREAD_DETACHED);
    return 0;
}

#else /* any platform that doesn't support this function */

int
set_exit_with_parent(void)
{
    g_assert_not_reached();
}

#endif
