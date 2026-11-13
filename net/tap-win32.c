/*
 *  TAP-Win32 -- A kernel driver to provide virtual tap device functionality
 *               on Windows.  Originally derived from the CIPE-Win32
 *               project by Damion K. Wilson, with extensive modifications by
 *               James Yonan.
 *
 *  All source code which derives from the CIPE-Win32 project is
 *  Copyright (C) Damion K. Wilson, 2003, and is released under the
 *  GPL version 2 (see below).
 *
 *  All other source code is Copyright (C) James Yonan, 2003-2004,
 *  and is released under the GPL version 2 (see below).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "tap_int.h"

#include "clients.h"            /* net_init_tap */
#include "net/eth.h"
#include "net/net.h"
#include "net/tap.h"            /* tap_has_ufo, ... */
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/cutils.h"
#include "qemu/sockets.h"
#include "qemu/win32-fdpass.h"
#include "qapi/error.h"
#include "tap-win32-adapter.h"
#include <windows.h>
#include <winioctl.h>

//=============
// TAP IOCTLs
//=============

#define TAP_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)

//=================
// Registry keys
//=================

#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

//======================
// Filesystem prefixes
//======================

#define USERMODEDEVICEDIR "\\\\.\\Global\\"
#define TAPSUFFIX         ".tap"


//======================
// Compile time configuration
//======================

//#define DEBUG_TAP_WIN32

/* FIXME: The asynch write path appears to be broken at
 * present. WriteFile() ignores the lpNumberOfBytesWritten parameter
 * for overlapped writes, with the result we return zero bytes sent,
 * and after handling a single packet, receive is disabled for this
 * interface. */
/* #define TUN_ASYNCHRONOUS_WRITES 1 */

#define TUN_BUFFER_SIZE 1560
#define TUN_MAX_BUFFER_COUNT 32

/*
 * The data member "buffer" must be the first element in the tun_buffer
 * structure. See the function, tap_win32_free_buffer.
 */
typedef struct tun_buffer_s {
    unsigned char buffer [TUN_BUFFER_SIZE];
    unsigned long read_size;
    struct tun_buffer_s* next;
} tun_buffer_t;

typedef struct tap_win32_overlapped {
    HANDLE handle;
    HANDLE read_event;
    HANDLE write_event;
    HANDLE output_queue_semaphore;
    HANDLE free_list_semaphore;
    HANDLE tap_semaphore;
    CRITICAL_SECTION output_queue_cs;
    CRITICAL_SECTION free_list_cs;
    OVERLAPPED read_overlapped;
    OVERLAPPED write_overlapped;
    tun_buffer_t buffers[TUN_MAX_BUFFER_COUNT];
    tun_buffer_t* free_list;
    tun_buffer_t* output_queue_front;
    tun_buffer_t* output_queue_back;
    HANDLE thread;
    volatile bool stopping;
} tap_win32_overlapped_t;

static tun_buffer_t* get_buffer_from_free_list(tap_win32_overlapped_t* const overlapped)
{
    tun_buffer_t* buffer = NULL;
    WaitForSingleObject(overlapped->free_list_semaphore, INFINITE);
    EnterCriticalSection(&overlapped->free_list_cs);
    buffer = overlapped->free_list;
//    assert(buffer != NULL);
    overlapped->free_list = buffer->next;
    LeaveCriticalSection(&overlapped->free_list_cs);
    buffer->next = NULL;
    return buffer;
}

static void put_buffer_on_free_list(tap_win32_overlapped_t* const overlapped, tun_buffer_t* const buffer)
{
    EnterCriticalSection(&overlapped->free_list_cs);
    buffer->next = overlapped->free_list;
    overlapped->free_list = buffer;
    LeaveCriticalSection(&overlapped->free_list_cs);
    ReleaseSemaphore(overlapped->free_list_semaphore, 1, NULL);
}

static tun_buffer_t* get_buffer_from_output_queue(tap_win32_overlapped_t* const overlapped, const int block)
{
    tun_buffer_t* buffer = NULL;
    DWORD result, timeout = block ? INFINITE : 0L;

    // Non-blocking call
    result = WaitForSingleObject(overlapped->output_queue_semaphore, timeout);

    switch (result)
    {
        // The semaphore object was signaled.
        case WAIT_OBJECT_0:
            EnterCriticalSection(&overlapped->output_queue_cs);

            buffer = overlapped->output_queue_front;
            overlapped->output_queue_front = buffer->next;

            if(overlapped->output_queue_front == NULL) {
                overlapped->output_queue_back = NULL;
            }

            LeaveCriticalSection(&overlapped->output_queue_cs);
            break;

        // Semaphore was nonsignaled, so a time-out occurred.
        case WAIT_TIMEOUT:
            // Cannot open another window.
            break;
    }

    return buffer;
}

static tun_buffer_t* get_buffer_from_output_queue_immediate (tap_win32_overlapped_t* const overlapped)
{
    return get_buffer_from_output_queue(overlapped, 0);
}

static void put_buffer_on_output_queue(tap_win32_overlapped_t* const overlapped, tun_buffer_t* const buffer)
{
    EnterCriticalSection(&overlapped->output_queue_cs);

    if(overlapped->output_queue_front == NULL && overlapped->output_queue_back == NULL) {
        overlapped->output_queue_front = overlapped->output_queue_back = buffer;
    } else {
        buffer->next = NULL;
        overlapped->output_queue_back->next = buffer;
        overlapped->output_queue_back = buffer;
    }

    LeaveCriticalSection(&overlapped->output_queue_cs);

    ReleaseSemaphore(overlapped->output_queue_semaphore, 1, NULL);
}


static int is_tap_win32_dev(const char *guid)
{
    HKEY netcard_key;
    LONG status;
    DWORD len;
    int i = 0;

    status = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        ADAPTER_KEY,
        0,
        KEY_READ,
        &netcard_key);

    if (status != ERROR_SUCCESS) {
        return FALSE;
    }

    for (;;) {
        char enum_name[256];
        g_autofree char *unit_string = NULL;
        HKEY unit_key;
        char component_id_string[] = "ComponentId";
        char component_id[256];
        char net_cfg_instance_id_string[] = "NetCfgInstanceId";
        char net_cfg_instance_id[256];
        DWORD data_type;

        len = sizeof (enum_name);
        status = RegEnumKeyEx(
            netcard_key,
            i,
            enum_name,
            &len,
            NULL,
            NULL,
            NULL,
            NULL);

        if (status == ERROR_NO_MORE_ITEMS)
            break;
        else if (status != ERROR_SUCCESS) {
            return FALSE;
        }

        unit_string = g_strdup_printf("%s\\%s", ADAPTER_KEY, enum_name);

        status = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            unit_string,
            0,
            KEY_READ,
            &unit_key);

        if (status != ERROR_SUCCESS) {
            return FALSE;
        } else {
            len = sizeof (component_id);
            status = RegQueryValueEx(
                unit_key,
                component_id_string,
                NULL,
                &data_type,
                (LPBYTE)component_id,
                &len);

            if (!(status != ERROR_SUCCESS || data_type != REG_SZ)) {
                len = sizeof (net_cfg_instance_id);
                status = RegQueryValueEx(
                    unit_key,
                    net_cfg_instance_id_string,
                    NULL,
                    &data_type,
                    (LPBYTE)net_cfg_instance_id,
                    &len);

                if (status == ERROR_SUCCESS && data_type == REG_SZ) {
                    if (/* !strcmp (component_id, TAP_COMPONENT_ID) &&*/
                        !strcmp (net_cfg_instance_id, guid)) {
                        RegCloseKey (unit_key);
                        RegCloseKey (netcard_key);
                        return TRUE;
                    }
                }
            }
            RegCloseKey (unit_key);
        }
        ++i;
    }

    RegCloseKey (netcard_key);
    return FALSE;
}

static int get_device_guid(
    char *name,
    int name_size,
    char *actual_name,
    int actual_name_size)
{
    LONG status;
    HKEY control_net_key;
    DWORD len;
    int i = 0;
    int stop = 0;

    status = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        NETWORK_CONNECTIONS_KEY,
        0,
        KEY_READ,
        &control_net_key);

    if (status != ERROR_SUCCESS) {
        return -1;
    }

    while (!stop)
    {
        char enum_name[256];
        g_autofree char *connection_string = NULL;
        HKEY connection_key;
        char name_data[256];
        DWORD name_type;
        const char name_string[] = "Name";

        len = sizeof (enum_name);
        status = RegEnumKeyEx(
            control_net_key,
            i,
            enum_name,
            &len,
            NULL,
            NULL,
            NULL,
            NULL);

        if (status == ERROR_NO_MORE_ITEMS)
            break;
        else if (status != ERROR_SUCCESS) {
            return -1;
        }

        connection_string = g_strdup_printf("%s\\%s\\Connection",
             NETWORK_CONNECTIONS_KEY, enum_name);

        status = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            connection_string,
            0,
            KEY_READ,
            &connection_key);

        if (status == ERROR_SUCCESS) {
            len = sizeof (name_data);
            status = RegQueryValueEx(
                connection_key,
                name_string,
                NULL,
                &name_type,
                (LPBYTE)name_data,
                &len);

            if (status != ERROR_SUCCESS || name_type != REG_SZ) {
                ++i;
                continue;
            }
            else {
                if (is_tap_win32_dev(enum_name)) {
                    snprintf(name, name_size, "%s", enum_name);
                    if (actual_name) {
                        if (strcmp(actual_name, "") != 0) {
                            if (strcmp(name_data, actual_name) != 0) {
                                RegCloseKey (connection_key);
                                ++i;
                                continue;
                            }
                        }
                        else {
                            snprintf(actual_name, actual_name_size, "%s", name_data);
                        }
                    }
                    stop = 1;
                }
            }

            RegCloseKey (connection_key);
        }
        ++i;
    }

    RegCloseKey (control_net_key);

    if (stop == 0)
        return -1;

    return 0;
}

static int tap_win32_set_status(HANDLE handle, int status)
{
    unsigned long len = 0;

    return DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS,
                &status, sizeof (status),
                &status, sizeof (status), &len, NULL);
}

static void tap_win32_overlapped_init(tap_win32_overlapped_t* const overlapped, const HANDLE handle)
{
    overlapped->handle = handle;

    overlapped->read_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    overlapped->write_event = CreateEvent(NULL, FALSE, FALSE, NULL);

    overlapped->read_overlapped.Offset = 0;
    overlapped->read_overlapped.OffsetHigh = 0;
    overlapped->read_overlapped.hEvent = overlapped->read_event;

    overlapped->write_overlapped.Offset = 0;
    overlapped->write_overlapped.OffsetHigh = 0;
    overlapped->write_overlapped.hEvent = overlapped->write_event;

    InitializeCriticalSection(&overlapped->output_queue_cs);
    InitializeCriticalSection(&overlapped->free_list_cs);

    overlapped->output_queue_semaphore = CreateSemaphore(
        NULL,   // default security attributes
        0,   // initial count
        TUN_MAX_BUFFER_COUNT,   // maximum count
        NULL);  // unnamed semaphore

    if(!overlapped->output_queue_semaphore)  {
        fprintf(stderr, "error creating output queue semaphore!\n");
    }

    overlapped->free_list_semaphore = CreateSemaphore(
        NULL,   // default security attributes
        TUN_MAX_BUFFER_COUNT,   // initial count
        TUN_MAX_BUFFER_COUNT,   // maximum count
        NULL);  // unnamed semaphore

    if(!overlapped->free_list_semaphore)  {
        fprintf(stderr, "error creating free list semaphore!\n");
    }

    overlapped->free_list = overlapped->output_queue_front = overlapped->output_queue_back = NULL;

    {
        unsigned index;
        for(index = 0; index < TUN_MAX_BUFFER_COUNT; index++) {
            tun_buffer_t* element = &overlapped->buffers[index];
            element->next = overlapped->free_list;
            overlapped->free_list = element;
        }
    }
    /* To count buffers, initially no-signal. */
    overlapped->tap_semaphore = CreateSemaphore(NULL, 0, TUN_MAX_BUFFER_COUNT, NULL);
    if(!overlapped->tap_semaphore)
        fprintf(stderr, "error creating tap_semaphore.\n");
}

static int tap_win32_write(tap_win32_overlapped_t *overlapped,
                           const void *buffer, unsigned long size)
{
    unsigned long write_size;
    BOOL result;
    DWORD error;

#ifdef TUN_ASYNCHRONOUS_WRITES
    result = GetOverlappedResult( overlapped->handle, &overlapped->write_overlapped,
                                  &write_size, FALSE);

    if (!result && GetLastError() == ERROR_IO_INCOMPLETE)
        WaitForSingleObject(overlapped->write_event, INFINITE);
#endif

    result = WriteFile(overlapped->handle, buffer, size,
                       &write_size, &overlapped->write_overlapped);

#ifdef TUN_ASYNCHRONOUS_WRITES
    /* FIXME: we can't sensibly set write_size here, without waiting
     * for the IO to complete! Moreover, we can't return zero,
     * because that will disable receive on this interface, and we
     * also can't assume it will succeed and return the full size,
     * because that will result in the buffer being reclaimed while
     * the IO is in progress. */
#error Async writes are broken. Please disable TUN_ASYNCHRONOUS_WRITES.
#else /* !TUN_ASYNCHRONOUS_WRITES */
    if (!result) {
        error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            result = GetOverlappedResult(overlapped->handle,
                                         &overlapped->write_overlapped,
                                         &write_size, TRUE);
        }
    }
#endif

    if (!result) {
#ifdef DEBUG_TAP_WIN32
        LPTSTR msgbuf;
        error = GetLastError();
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
                      NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      &msgbuf, 0, NULL);
        fprintf(stderr, "Tap-Win32: Error WriteFile %d - %s\n", error, msgbuf);
        LocalFree(msgbuf);
#endif
        return 0;
    }

    return write_size;
}

static DWORD WINAPI tap_win32_thread_entry(LPVOID param)
{
    tap_win32_overlapped_t *overlapped = (tap_win32_overlapped_t*)param;
    unsigned long read_size;
    BOOL result;
    DWORD dwError;
    tun_buffer_t* buffer = get_buffer_from_free_list(overlapped);


    while (!overlapped->stopping) {
        result = ReadFile(overlapped->handle,
                          buffer->buffer,
                          sizeof(buffer->buffer),
                          &read_size,
                          &overlapped->read_overlapped);
        if (!result) {
            dwError = GetLastError();
            if (dwError == ERROR_IO_PENDING) {
                WaitForSingleObject(overlapped->read_event, INFINITE);
                result = GetOverlappedResult( overlapped->handle, &overlapped->read_overlapped,
                                              &read_size, FALSE);
                if (!result) {
#ifdef DEBUG_TAP_WIN32
                    LPVOID lpBuffer;
                    dwError = GetLastError();
                    FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                                   NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                   (LPTSTR) & lpBuffer, 0, NULL );
                    fprintf(stderr, "Tap-Win32: Error GetOverlappedResult %d - %s\n", dwError, lpBuffer);
                    LocalFree( lpBuffer );
#endif
                }
            } else {
#ifdef DEBUG_TAP_WIN32
                LPVOID lpBuffer;
                FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                               NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               (LPTSTR) & lpBuffer, 0, NULL );
                fprintf(stderr, "Tap-Win32: Error ReadFile %d - %s\n", dwError, lpBuffer);
                LocalFree( lpBuffer );
#endif
            }
        }

        if (overlapped->stopping) {
            break;
        }
        if(read_size > 0) {
            buffer->read_size = read_size;
            put_buffer_on_output_queue(overlapped, buffer);
            ReleaseSemaphore(overlapped->tap_semaphore, 1, NULL);
            buffer = get_buffer_from_free_list(overlapped);
        }
    }

    return 0;
}

static int tap_win32_read(tap_win32_overlapped_t *overlapped,
                          uint8_t **pbuf, int max_size)
{
    int size = 0;

    tun_buffer_t* buffer = get_buffer_from_output_queue_immediate(overlapped);

    if(buffer != NULL) {
        *pbuf = buffer->buffer;
        size = (int)buffer->read_size;
        if(size > max_size) {
            size = max_size;
        }
    }

    return size;
}

static void tap_win32_free_buffer(tap_win32_overlapped_t *overlapped,
                                  uint8_t *pbuf)
{
    tun_buffer_t* buffer = (tun_buffer_t*)pbuf;
    put_buffer_on_free_list(overlapped, buffer);
}

/*
 * The TAP device: opened by its adapter name (ifname=), given as a handle
 * (fd=, from a parent process or qemu-bridge-helper), or a new adapter
 * (as Linux creates tapN when no ifname is given), removed at the end.
 * Each netdev has its own buffers and reading thread.
 */
static tap_win32_overlapped_t *tap_win32_start(HANDLE handle, Error **errp)
{
    struct {
        unsigned long major;
        unsigned long minor;
        unsigned long debug;
    } version;
    DWORD version_len;
    tap_win32_overlapped_t *ov;

    if (!DeviceIoControl(handle, TAP_IOCTL_GET_VERSION,
                         &version, sizeof(version),
                         &version, sizeof(version), &version_len, NULL)) {
        error_setg(errp, "not a TAP-Windows device");
        return NULL;
    }
    if (!tap_win32_set_status(handle, TRUE)) {
        error_setg_win32(errp, GetLastError(), "cannot bring the TAP up");
        return NULL;
    }
    ov = g_new0(tap_win32_overlapped_t, 1);
    tap_win32_overlapped_init(ov, handle);
    ov->thread = CreateThread(NULL, 0, tap_win32_thread_entry, ov, 0, NULL);
    return ov;
}

static void tap_win32_stop(tap_win32_overlapped_t *ov)
{
    ov->stopping = true;
    CancelIoEx(ov->handle, NULL);
    /* a thread waiting for a free buffer */
    ReleaseSemaphore(ov->free_list_semaphore, 1, NULL);
    if (ov->thread) {
        WaitForSingleObject(ov->thread, 5000);
        CloseHandle(ov->thread);
    }
    tap_win32_set_status(ov->handle, FALSE);
    CloseHandle(ov->handle);
    CloseHandle(ov->read_event);
    CloseHandle(ov->write_event);
    CloseHandle(ov->output_queue_semaphore);
    CloseHandle(ov->free_list_semaphore);
    CloseHandle(ov->tap_semaphore);
    DeleteCriticalSection(&ov->output_queue_cs);
    DeleteCriticalSection(&ov->free_list_cs);
    g_free(ov);
}

/********************************************/

typedef struct TAPState {
    NetClientState nc;
    tap_win32_overlapped_t *handle;
    char ifname[128];
    char down_script[1024];
    char *created_guid;     /* the adapter made for this netdev */
    HANDLE helper;          /* qemu-bridge-helper, while the TAP is used */
} TAPState;

/* Run @script with @ifname, as launch_script() of net/tap.c */
static int tap_win32_run_script(const char *script, const char *ifname,
                                Error **errp)
{
    g_autofree char *cmd = NULL;
    const char *ext = strrchr(script, '.');
    g_autoptr(GError) gerr = NULL;
    int status;

    if (ext && !g_ascii_strcasecmp(ext, ".ps1")) {
        cmd = g_strdup_printf("powershell.exe -NoProfile -ExecutionPolicy "
                              "Bypass -File \"%s\" \"%s\"", script, ifname);
    } else if (ext && (!g_ascii_strcasecmp(ext, ".bat") ||
                       !g_ascii_strcasecmp(ext, ".cmd"))) {
        cmd = g_strdup_printf("cmd.exe /c \"\"%s\" \"%s\"\"", script, ifname);
    } else {
        cmd = g_strdup_printf("\"%s\" \"%s\"", script, ifname);
    }
    if (!g_spawn_command_line_sync(cmd, NULL, NULL, &status, &gerr)) {
        error_setg(errp, "could not launch network script %s: %s", script,
                   gerr->message);
        return -1;
    }
    if (!g_spawn_check_wait_status(status, NULL)) {
        error_setg(errp, "network script %s failed with status %d", script,
                   status);
        return -1;
    }
    return 0;
}

/*
 * The scripts of Windows: the name given, else qemu-ifup / qemu-ifdown of
 * the configuration directory with the extension found (.bat, .cmd, .ps1,
 * .exe), if any; "no" for none
 */
static char *tap_win32_script(const char *given, const char *def)
{
    static const char *const exts[] = { "", ".bat", ".cmd", ".ps1", ".exe" };
    g_autofree char *base = NULL;
    size_t i;

    if (given) {
        return g_str_equal(given, "no") || !*given ? NULL : g_strdup(given);
    }
    base = get_relocated_path(def);
    for (i = 0; i < G_N_ELEMENTS(exts); i++) {
        g_autofree char *p = g_strconcat(base, exts[i], NULL);

        if (g_file_test(p, G_FILE_TEST_IS_REGULAR)) {
            return g_steal_pointer(&p);
        }
    }
    return NULL;
}

static void tap_cleanup(NetClientState *nc)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);
    Error *err = NULL;

    if (!s->handle) {
        return;
    }
    qemu_del_wait_object(s->handle->tap_semaphore, NULL, NULL);
    if (s->down_script[0]) {
        if (tap_win32_run_script(s->down_script, s->ifname, &err) < 0) {
            error_report_err(err);
            err = NULL;
        }
    }
    tap_win32_stop(s->handle);
    s->handle = NULL;
    if (s->created_guid) {
        if (!tap_win32_adapter_remove(s->created_guid, &err)) {
            error_report_err(err);
        }
        g_free(s->created_guid);
        s->created_guid = NULL;
    }
    if (s->helper) {
        /* qemu-bridge-helper removes its adapter when we are gone */
        CloseHandle(s->helper);
        s->helper = NULL;
    }
}

static ssize_t tap_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    TAPState *s = DO_UPCAST(TAPState, nc, nc);

    return tap_win32_write(s->handle, buf, size);
}

static void tap_win32_send(void *opaque)
{
    TAPState *s = opaque;
    uint8_t *buf, *orig_buf;
    int max_size = 4096;
    int size;
    uint8_t min_pkt[ETH_ZLEN];
    size_t min_pktsz = sizeof(min_pkt);

    size = tap_win32_read(s->handle, &buf, max_size);
    if (size > 0) {
        orig_buf = buf;

        if (net_peer_needs_padding(&s->nc)) {
            if (eth_pad_short_frame(min_pkt, &min_pktsz, buf, size)) {
                buf = min_pkt;
                size = min_pktsz;
            }
        }

        qemu_send_packet(&s->nc, buf, size);
        tap_win32_free_buffer(s->handle, orig_buf);
    }
}

static NetClientInfo net_tap_win32_info = {
    .type = NET_CLIENT_DRIVER_TAP,
    .size = sizeof(TAPState),
    .receive = tap_receive,
    .cleanup = tap_cleanup,
};

static TAPState *tap_win32_new(NetClientState *peer, const char *model,
                               const char *name, HANDLE handle,
                               const char *ifname, Error **errp)
{
    tap_win32_overlapped_t *ov = tap_win32_start(handle, errp);
    NetClientState *nc;
    TAPState *s;

    if (!ov) {
        CloseHandle(handle);
        return NULL;
    }
    nc = qemu_new_net_client(&net_tap_win32_info, peer, model, name);
    s = DO_UPCAST(TAPState, nc, nc);
    s->handle = ov;
    pstrcpy(s->ifname, sizeof(s->ifname), ifname ? ifname : "");
    qemu_add_wait_object(ov->tap_semaphore, tap_win32_send, s);
    return s;
}

/* A handle given as a number: one this process inherited */
static HANDLE tap_win32_handle_arg(const char *str, Error **errp)
{
    unsigned long long v;

    if (qemu_strtou64(str, NULL, 0, &v) < 0 || !v) {
        error_setg(errp, "invalid handle '%s'", str);
        return NULL;
    }
    return (HANDLE)(uintptr_t)v;
}

/*
 * qemu-bridge-helper: started with one end of a socket pair, it sends the
 * handle of a TAP device added to the bridge, and lives while QEMU does to
 * remove it afterwards.  It takes administrator rights.
 */
static HANDLE tap_win32_run_helper(const char *helper, const char *bridge,
                                   HANDLE *process, Error **errp)
{
    W32FdState st = { 0 };
    W32FdItem items[W32FD_MAX_ITEMS];
    STARTUPINFOEXW si = { 0 };
    PROCESS_INFORMATION pi;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    SIZE_T attrs_size = 0;
    g_autofree char *cmdline = NULL;
    g_autofree gunichar2 *wcmd = NULL;
    HANDLE child_sock, child_err = NULL, ret = NULL;
    HANDLE inherit[2];
    int sv[2], nitems = 0, ninherit = 0, i;
    char byte;
    struct iovec iov = { &byte, 1 };
    ssize_t n;

    if (qemu_socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        error_setg_errno(errp, errno, "socketpair() failed");
        return NULL;
    }
    child_sock = (HANDLE)_get_osfhandle(sv[1]);
    SetHandleInformation(child_sock, HANDLE_FLAG_INHERIT,
                         HANDLE_FLAG_INHERIT);

    if (strstr(helper, " ")) {
        /* a command line, as on Linux where /bin/sh runs it */
        cmdline = g_strdup_printf("%s --use-vnet --fd=%llu%s%s", helper,
                                  (unsigned long long)(uintptr_t)child_sock,
                                  strstr(helper, "--br=") ? "" : " --br=",
                                  strstr(helper, "--br=") ? "" : bridge);
    } else {
        cmdline = g_strdup_printf("\"%s\" --use-vnet --fd=%llu --br=%s",
                                  helper,
                                  (unsigned long long)(uintptr_t)child_sock,
                                  bridge);
    }
    wcmd = g_utf8_to_utf16(cmdline, -1, NULL, NULL, NULL);

    /* its messages go to our stderr, as on Linux */
    inherit[ninherit++] = child_sock;
    if (DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_ERROR_HANDLE),
                        GetCurrentProcess(), &child_err, 0, TRUE,
                        DUPLICATE_SAME_ACCESS)) {
        inherit[ninherit++] = child_err;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdError = child_err;
    }

    InitializeProcThreadAttributeList(NULL, 1, 0, &attrs_size);
    attrs = g_malloc(attrs_size);
    si.StartupInfo.cb = sizeof(si);
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attrs_size) ||
        !UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   inherit, ninherit * sizeof(HANDLE), NULL,
                                   NULL)) {
        error_setg_win32(errp, GetLastError(), "cannot start the helper");
        goto out;
    }
    si.lpAttributeList = attrs;
    if (!CreateProcessW(NULL, (wchar_t *)wcmd, NULL, NULL, TRUE,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                        NULL, NULL, &si.StartupInfo, &pi)) {
        error_setg_win32(errp, GetLastError(), "cannot run %s", cmdline);
        goto out;
    }
    CloseHandle(pi.hThread);
    /* the helper has its copy: no other program we start gets one */
    SetHandleInformation(child_sock, HANDLE_FLAG_INHERIT, 0);
    /*
     * our copy of the end of the helper stays open until its frame came:
     * closing it while the helper starts may cut the connection; the end
     * of the helper is seen on its process handle
     */

    /*
     * Wait for the frame or for the end of the helper: a socket inherited by
     * a process that exits does not always show EOF to its peer.
     */
    {
        SOCKET s0 = (SOCKET)_get_osfhandle(sv[0]);
        WSAEVENT ev = WSACreateEvent();
        HANDLE hs[2] = { ev, pi.hProcess };
        u_long blocking = 0;
        fd_set rfds;
        struct timeval tv = { 0, 0 };

        WSAEventSelect(s0, ev, FD_READ | FD_CLOSE);
        WaitForMultipleObjects(2, hs, FALSE, 120 * 1000);
        WSAEventSelect(s0, NULL, 0);
        WSACloseEvent(ev);
        ioctlsocket(s0, FIONBIO, &blocking);
        FD_ZERO(&rfds);
        FD_SET(s0, &rfds);
        if (select(0, &rfds, NULL, NULL, &tv) != 1) {
            DWORD code = STILL_ACTIVE;

            GetExitCodeProcess(pi.hProcess, &code);
            if (code == STILL_ACTIVE) {
                TerminateProcess(pi.hProcess, 1);
                error_setg(errp, "bridge helper did not answer");
            } else {
                error_setg(errp, "bridge helper failed (exit code %lu)",
                           (unsigned long)code);
            }
            CloseHandle(pi.hProcess);
            goto out;
        }
    }

    /* one byte with the handle of the TAP device */
    n = w32fd_recv((SOCKET)_get_osfhandle(sv[0]), &st, &iov, 1, items,
                   &nitems, W32FD_MAX_ITEMS, false);
    for (i = 0; i < nitems; i++) {
        if (!ret && items[i].type != W32FD_SOCKET) {
            ret = items[i].handle;
        } else if (items[i].type == W32FD_SOCKET) {
            closesocket((SOCKET)items[i].handle);
        } else {
            CloseHandle(items[i].handle);
        }
    }
    if (n <= 0 || !ret) {
        DWORD code = 0;
        int err = errno;

        /*
         * Our ends closed, the helper sees QEMU gone: it takes its adapter
         * out of the bridge and removes it
         */
        close(sv[0]);
        sv[0] = -1;
        close(sv[1]);
        sv[1] = -1;
        WaitForSingleObject(pi.hProcess, 30000);
        GetExitCodeProcess(pi.hProcess, &code);
        if (code == STILL_ACTIVE) {
            TerminateProcess(pi.hProcess, 1);
            error_setg(errp, "bridge helper sent no handle (read %zd, "
                       "%d handles%s%s)", n, nitems, n < 0 ? ": " : "",
                       n < 0 ? strerror(err) : "");
        } else {
            error_setg(errp, "bridge helper failed (exit code %lu)",
                       (unsigned long)code);
        }
        CloseHandle(pi.hProcess);
        ret = NULL;
        goto out;
    }
    /* our end stays open: the helper sees it close when QEMU ends */
    *process = pi.hProcess;
    sv[0] = -1;
    close(sv[1]);
    sv[1] = -1;
out:
    if (attrs) {
        DeleteProcThreadAttributeList(attrs);
        g_free(attrs);
    }
    if (child_err) {
        CloseHandle(child_err);
    }
    if (sv[1] >= 0) {
        close(sv[1]);
    }
    if (sv[0] >= 0) {
        close(sv[0]);
    }
    w32fd_state_free(&st);
    return ret;
}

int net_init_tap(const Netdev *netdev, const char *name,
                 NetClientState *peer, Error **errp)
{
    const NetdevTapOptions *tap;
    g_autofree char *script = NULL;
    g_autofree char *downscript = NULL;
    g_autofree char *guid = NULL;
    g_autofree char *ifname = NULL;
    char *created = NULL;
    HANDLE handle = NULL, helper_process = NULL;
    TAPState *s;

    assert(netdev->type == NET_CLIENT_DRIVER_TAP);
    tap = &netdev->u.tap;

    if (tap->has_vnet_hdr && tap->vnet_hdr) {
        error_setg(errp, "vnet_hdr=on is not supported by TAP-Windows");
        return -1;
    }
    if (tap->has_vhost && tap->vhost) {
        error_setg(errp, "vhost=on needs the vhost-net driver of Windows");
        return -1;
    }
    if (tap->vhostfd || tap->vhostfds) {
        error_setg(errp, "vhostfd= needs the vhost-net driver of Windows");
        return -1;
    }
    if (tap->has_queues && tap->queues > 1) {
        error_setg(errp, "TAP-Windows has one queue: queues must be 1");
        return -1;
    }
    if (tap->fds && strchr(tap->fds, ':')) {
        error_setg(errp, "TAP-Windows has one queue: one handle in fds");
        return -1;
    }

    if (tap->fd || tap->fds) {
        /* a TAP device opened by the parent process, inherited */
        if (tap->ifname || tap->script || tap->downscript || tap->helper) {
            error_setg(errp, "ifname=, script=, downscript= and helper= are "
                       "invalid with fd=");
            return -1;
        }
        handle = tap_win32_handle_arg(tap->fd ? tap->fd : tap->fds, errp);
        if (!handle) {
            return -1;
        }
        s = tap_win32_new(peer, "tap", name, handle, NULL, errp);
        if (!s) {
            return -1;
        }
        qemu_set_info_str(&s->nc, "fd=%s", tap->fd ? tap->fd : tap->fds);
        return 0;
    }

    if (tap->helper) {
        if (tap->ifname || tap->script || tap->downscript) {
            error_setg(errp, "ifname=, script= and downscript= are invalid "
                       "with helper=");
            return -1;
        }
        handle = tap_win32_run_helper(tap->helper, tap->br ?: "br0",
                                      &helper_process, errp);
        if (!handle) {
            return -1;
        }
        s = tap_win32_new(peer, "tap", name, handle, NULL, errp);
        if (!s) {
            CloseHandle(helper_process);
            return -1;
        }
        s->helper = helper_process;
        qemu_set_info_str(&s->nc, "helper=%s", tap->helper);
        return 0;
    }

    if (tap->ifname) {
        guid = tap_win32_adapter_find(tap->ifname);
        if (!guid) {
            error_setg(errp, "no TAP-Windows adapter named '%s'",
                       tap->ifname);
            return -1;
        }
        ifname = g_strdup(tap->ifname);
    } else {
        /* as Linux makes tapN: a new adapter, removed at the end */
        guid = tap_win32_adapter_create(NULL, &ifname, errp);
        if (!guid) {
            return -1;
        }
        created = g_strdup(guid);
    }
    handle = tap_win32_adapter_open(guid, errp);
    if (!handle) {
        goto fail;
    }

    script = tap_win32_script(tap->script, DEFAULT_NETWORK_SCRIPT);
    downscript = tap_win32_script(tap->downscript,
                                  DEFAULT_NETWORK_DOWN_SCRIPT);
    if (script && tap_win32_run_script(script, ifname, errp) < 0) {
        CloseHandle(handle);
        goto fail;
    }

    s = tap_win32_new(peer, "tap", name, handle, ifname, errp);
    if (!s) {
        goto fail;
    }
    s->created_guid = created;
    if (downscript) {
        pstrcpy(s->down_script, sizeof(s->down_script), downscript);
    }
    qemu_set_info_str(&s->nc, "ifname=%s,script=%s,downscript=%s", ifname,
                      script ?: "no", downscript ?: "no");
    return 0;

fail:
    if (created) {
        tap_win32_adapter_remove(created, NULL);
        g_free(created);
    }
    return -1;
}

int net_init_bridge(const Netdev *netdev, const char *name,
                    NetClientState *peer, Error **errp)
{
    const NetdevBridgeOptions *bridge;
    g_autofree char *default_helper = NULL;
    const char *helper, *br;
    HANDLE handle, process = NULL;
    TAPState *s;

    assert(netdev->type == NET_CLIENT_DRIVER_BRIDGE);
    bridge = &netdev->u.bridge;
    helper = bridge->helper;
    if (!helper) {
        helper = default_helper = get_relocated_path(DEFAULT_BRIDGE_HELPER
                                                     ".exe");
    }
    br = bridge->br ?: DEFAULT_BRIDGE_INTERFACE;

    handle = tap_win32_run_helper(helper, br, &process, errp);
    if (!handle) {
        return -1;
    }
    s = tap_win32_new(peer, "bridge", name, handle, NULL, errp);
    if (!s) {
        CloseHandle(process);
        return -1;
    }
    s->helper = process;
    qemu_set_info_str(&s->nc, "helper=%s,br=%s", helper, br);
    return 0;
}

/* the descriptor of a TAP device for vhost-net: see net/tap.c */
int tap_get_fd(NetClientState *nc)
{
    return -1;
}

/* one queue: always enabled */
int tap_enable(NetClientState *nc)
{
    return 0;
}

int tap_disable(NetClientState *nc)
{
    return 0;
}
