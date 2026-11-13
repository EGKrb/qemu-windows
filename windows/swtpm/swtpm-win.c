/*
 * swtpm for Windows: the "socket" interface of swtpm on top of libtpms,
 * as QEMU's tpm-emulator backend and libvirt start it:
 *
 *   swtpm socket --tpm2 --tpmstate dir=DIR --ctrl type=unixio,path=SOCKET
 *                [--log file=FILE,level=N] [--pid file=FILE]
 *                [--flags not-need-init[,startup-clear]] [--terminate]
 *
 * The control channel is an AF_UNIX socket.  QEMU passes the data channel
 * (one end of a socket pair) with CMD_SET_DATAFD; on Windows descriptors
 * travel as handles in frames (qemu/win32-fdpass.h), on the control
 * channel only.  The state of the TPM is kept in DIR as swtpm keeps it:
 * tpm2-00.permall, tpm2-00.volatilestate, tpm2-00.savestate.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <winsock2.h>
#include <afunix.h>
#include <windows.h>
#include <io.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_tis.h>
#include <libtpms/tpm_memory.h>
#include <libtpms/tpm_nvfilename.h>

#include "qemu/win32-fdpass.h"

/* the control protocol: backends/tpm/tpm_ioctl.h of QEMU */
enum {
    CMD_GET_CAPABILITY = 1,
    CMD_INIT,
    CMD_SHUTDOWN,
    CMD_GET_TPMESTABLISHED,
    CMD_SET_LOCALITY,
    CMD_HASH_START,
    CMD_HASH_DATA,
    CMD_HASH_END,
    CMD_CANCEL_TPM_CMD,
    CMD_STORE_VOLATILE,
    CMD_RESET_TPMESTABLISHED,
    CMD_GET_STATEBLOB,
    CMD_SET_STATEBLOB,
    CMD_STOP,
    CMD_GET_CONFIG,
    CMD_SET_DATAFD,
    CMD_SET_BUFFERSIZE,
    CMD_GET_INFO,
    CMD_LOCK_STORAGE,
};

#define PTM_CAP_INIT               (1)
#define PTM_CAP_SHUTDOWN           (1 << 1)
#define PTM_CAP_GET_TPMESTABLISHED (1 << 2)
#define PTM_CAP_SET_LOCALITY       (1 << 3)
#define PTM_CAP_HASHING            (1 << 4)
#define PTM_CAP_CANCEL_TPM_CMD     (1 << 5)
#define PTM_CAP_STORE_VOLATILE     (1 << 6)
#define PTM_CAP_RESET_TPMESTABLISHED (1 << 7)
#define PTM_CAP_GET_STATEBLOB      (1 << 8)
#define PTM_CAP_SET_STATEBLOB      (1 << 9)
#define PTM_CAP_STOP               (1 << 10)
#define PTM_CAP_GET_CONFIG         (1 << 11)
#define PTM_CAP_SET_DATAFD         (1 << 12)
#define PTM_CAP_SET_BUFFERSIZE     (1 << 13)
#define PTM_CAP_GET_INFO           (1 << 14)
#define PTM_CAP_LOCK_STORAGE       (1 << 16)

#define PTM_INIT_FLAG_DELETE_VOLATILE (1 << 0)
#define PTM_BLOB_TYPE_PERMANENT  1
#define PTM_BLOB_TYPE_VOLATILE   2
#define PTM_BLOB_TYPE_SAVESTATE  3
#define PTM_STATE_BLOB_SIZE (3 * 1024)
#define PTM_GETINFO_SIZE (3 * 1024)

static const char *state_dir;
static FILE *log_file;
static unsigned int log_level = 0;
static bool tpm_running;
static bool terminate_on_hangup;
static uint8_t locality;
static SOCKET ctrl_listen = INVALID_SOCKET;
static SOCKET ctrl = INVALID_SOCKET;
static SOCKET data = INVALID_SOCKET;
static W32FdState ctrl_state;

static void logit(unsigned int level, const char *fmt, ...)
{
    va_list ap;

    if (!log_file || level > log_level) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(log_file, fmt, ap);
    va_end(ap);
    fflush(log_file);
}

static void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

/* ------------------------------------------------------------------ */
/* The state of the TPM, in files as swtpm keeps it                    */

static char *state_path(uint32_t tpm_number, const char *name)
{
    size_t len = strlen(state_dir) + strlen(name) + 32;
    char *p = malloc(len);

    snprintf(p, len, "%s\\tpm2-%02x.%s", state_dir, tpm_number, name);
    return p;
}

static TPM_RESULT nv_init(void)
{
    return TPM_SUCCESS;
}

static TPM_RESULT nv_load(unsigned char **out, uint32_t *length,
                          uint32_t tpm_number, const char *name)
{
    char *path = state_path(tpm_number, name);
    FILE *f = fopen(path, "rb");
    long size;
    TPM_RESULT rc;

    free(path);
    *out = NULL;
    *length = 0;
    if (!f) {
        /* no state yet: libtpms makes a new TPM */
        return TPM_RETRY;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    rc = TPM_Malloc(out, size ? size : 1);
    if (rc == TPM_SUCCESS && size &&
        fread(*out, 1, size, f) != (size_t)size) {
        rc = TPM_FAIL;
    }
    fclose(f);
    if (rc == TPM_SUCCESS) {
        *length = size;
    }
    return rc;
}

/* written to a new file, then renamed over the old one */
static TPM_RESULT write_state_file(const char *path, const unsigned char *d,
                                   uint32_t length)
{
    size_t tlen = strlen(path) + 8;
    char *tmp = malloc(tlen);
    FILE *f;
    bool ok;

    snprintf(tmp, tlen, "%s.tmp", path);
    f = fopen(tmp, "wb");
    if (!f) {
        free(tmp);
        return TPM_FAIL;
    }
    ok = fwrite(d, 1, length, f) == length;
    ok = (fflush(f) == 0) && ok;
    _commit(_fileno(f));
    fclose(f);
    if (ok) {
        ok = MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING |
                         MOVEFILE_WRITE_THROUGH);
    }
    if (!ok) {
        DeleteFileA(tmp);
    }
    free(tmp);
    return ok ? TPM_SUCCESS : TPM_FAIL;
}

static TPM_RESULT nv_store(const unsigned char *d, uint32_t length,
                           uint32_t tpm_number, const char *name)
{
    char *path = state_path(tpm_number, name);
    TPM_RESULT rc = write_state_file(path, d, length);

    free(path);
    return rc;
}

static TPM_RESULT nv_delete(uint32_t tpm_number, const char *name,
                            TPM_BOOL must_exist)
{
    char *path = state_path(tpm_number, name);
    BOOL ok = DeleteFileA(path);

    free(path);
    if (!ok && must_exist) {
        return TPM_FAIL;
    }
    return TPM_SUCCESS;
}

static TPM_RESULT io_init(void)
{
    return TPM_SUCCESS;
}

static TPM_RESULT io_getlocality(TPM_MODIFIER_INDICATOR *loc,
                                 uint32_t tpm_number)
{
    *loc = locality;
    return TPM_SUCCESS;
}

static TPM_RESULT io_getpp(TPM_BOOL *pp, uint32_t tpm_number)
{
    *pp = FALSE;
    return TPM_SUCCESS;
}

static struct libtpms_callbacks callbacks = {
    .sizeOfStruct = sizeof(struct libtpms_callbacks),
    .tpm_nvram_init = nv_init,
    .tpm_nvram_loaddata = nv_load,
    .tpm_nvram_storedata = nv_store,
    .tpm_nvram_deletename = nv_delete,
    .tpm_io_init = io_init,
    .tpm_io_getlocality = io_getlocality,
    .tpm_io_getphysicalpresence = io_getpp,
};

static const char *blob_name(uint32_t type)
{
    switch (type) {
    case PTM_BLOB_TYPE_PERMANENT:
        return TPM_PERMANENT_ALL_NAME;
    case PTM_BLOB_TYPE_VOLATILE:
        return TPM_VOLATILESTATE_NAME;
    case PTM_BLOB_TYPE_SAVESTATE:
        return TPM_SAVESTATE_NAME;
    default:
        return NULL;
    }
}

static enum TPMLIB_StateType blob_libtpms_type(uint32_t type)
{
    switch (type) {
    case PTM_BLOB_TYPE_PERMANENT:
        return TPMLIB_STATE_PERMANENT;
    case PTM_BLOB_TYPE_VOLATILE:
        return TPMLIB_STATE_VOLATILE;
    default:
        return TPMLIB_STATE_SAVE_STATE;
    }
}

static TPM_RESULT tpm_start(uint32_t flags)
{
    TPM_RESULT rc;

    if (tpm_running) {
        TPMLIB_Terminate();
        tpm_running = false;
    }
    rc = TPMLIB_MainInit();
    if (rc == TPM_SUCCESS) {
        tpm_running = true;
        if (flags & PTM_INIT_FLAG_DELETE_VOLATILE) {
            nv_delete(0, TPM_VOLATILESTATE_NAME, FALSE);
        }
    }
    logit(1, "TPM init: 0x%x\n", rc);
    return rc;
}

static void tpm_stop(void)
{
    if (tpm_running) {
        TPMLIB_Terminate();
        tpm_running = false;
    }
}

/* ------------------------------------------------------------------ */
/* The control channel                                                 */

static W32FdItem pending_items[W32FD_MAX_ITEMS];
static int pending_nitems;

/* Read exactly @len bytes; the handles of the frames go to pending_items */
static bool ctrl_read(void *buf, size_t len)
{
    char *p = buf;

    while (len) {
        struct iovec { void *iov_base; size_t iov_len; } iov = { p, len };
        W32FdItem items[W32FD_MAX_ITEMS];
        int nitems = 0, i;
        ssize_t n = w32fd_recv(ctrl, &ctrl_state, (const void *)&iov, 1,
                               items, &nitems, W32FD_MAX_ITEMS, false);

        for (i = 0; i < nitems; i++) {
            if (pending_nitems < W32FD_MAX_ITEMS) {
                pending_items[pending_nitems++] = items[i];
            } else if (items[i].type == W32FD_SOCKET) {
                closesocket((SOCKET)items[i].handle);
            } else {
                CloseHandle(items[i].handle);
            }
        }
        if (n <= 0) {
            return false;
        }
        p += n;
        len -= n;
    }
    return true;
}

static bool ctrl_write(const void *buf, size_t len)
{
    struct iovec { const void *iov_base; size_t iov_len; } iov = { buf, len };

    return w32fd_send(ctrl, &ctrl_state, (const void *)&iov, 1, NULL, 0) ==
           (ssize_t)len;
}

static bool reply_result(uint32_t res)
{
    uint32_t r = htonl(res);

    return ctrl_write(&r, sizeof(r));
}

/* the size of the request that follows each command */
static int request_size(uint32_t cmd)
{
    switch (cmd) {
    case CMD_INIT:
    case CMD_SET_LOCALITY:
    case CMD_RESET_TPMESTABLISHED:
    case CMD_SET_BUFFERSIZE:
    case CMD_LOCK_STORAGE:
        return 4;
    case CMD_HASH_DATA:
        return 4 + 4096;
    case CMD_GET_STATEBLOB:
    case CMD_SET_STATEBLOB:
        return 12;
    case CMD_GET_INFO:
        return 16;
    default:
        return 0;
    }
}

/* false: the connection is over (or the process must end) */
static bool ctrl_handle(void)
{
    uint8_t req[4 + 4096 + 16];
    uint32_t cmd, res = TPM_SUCCESS;
    int rsize;

    if (!ctrl_read(&cmd, sizeof(cmd))) {
        return false;
    }
    cmd = ntohl(cmd);
    rsize = request_size(cmd);
    if (rsize && !ctrl_read(req, rsize)) {
        return false;
    }
    logit(2, "control command %u\n", cmd);

    switch (cmd) {
    case CMD_GET_CAPABILITY: {
        uint32_t resp[2] = {
            htonl(TPM_SUCCESS),
            htonl(PTM_CAP_INIT | PTM_CAP_SHUTDOWN |
                  PTM_CAP_GET_TPMESTABLISHED | PTM_CAP_SET_LOCALITY |
                  PTM_CAP_HASHING | PTM_CAP_CANCEL_TPM_CMD |
                  PTM_CAP_STORE_VOLATILE | PTM_CAP_RESET_TPMESTABLISHED |
                  PTM_CAP_GET_STATEBLOB | PTM_CAP_SET_STATEBLOB |
                  PTM_CAP_STOP | PTM_CAP_GET_CONFIG | PTM_CAP_SET_DATAFD |
                  PTM_CAP_SET_BUFFERSIZE | PTM_CAP_GET_INFO |
                  PTM_CAP_LOCK_STORAGE),
        };
        return ctrl_write(resp, sizeof(resp));
    }
    case CMD_INIT: {
        uint32_t flags;

        memcpy(&flags, req, 4);
        return reply_result(tpm_start(ntohl(flags)));
    }
    case CMD_SHUTDOWN:
        tpm_stop();
        reply_result(TPM_SUCCESS);
        logit(1, "shutdown\n");
        exit(0);
    case CMD_STOP:
        tpm_stop();
        return reply_result(TPM_SUCCESS);
    case CMD_GET_TPMESTABLISHED: {
        uint8_t resp[8] = { 0 };
        TPM_BOOL est = FALSE;

        res = tpm_running ? TPM_IO_TpmEstablished_Get(&est) : TPM_FAIL;
        res = htonl(res);
        memcpy(resp, &res, 4);
        resp[4] = est;
        return ctrl_write(resp, sizeof(resp));
    }
    case CMD_SET_LOCALITY:
        if (req[0] > 4) {
            res = TPM_BAD_LOCALITY;
        } else {
            locality = req[0];
        }
        return reply_result(res);
    case CMD_RESET_TPMESTABLISHED: {
        uint8_t saved = locality;

        if (req[0] > 4) {
            return reply_result(TPM_BAD_LOCALITY);
        }
        locality = req[0];
        res = tpm_running ? TPM_IO_TpmEstablished_Reset() : TPM_FAIL;
        locality = saved;
        return reply_result(res);
    }
    case CMD_HASH_START:
        return reply_result(tpm_running ? TPM_IO_Hash_Start() : TPM_FAIL);
    case CMD_HASH_DATA: {
        uint32_t len;

        memcpy(&len, req, 4);
        len = ntohl(len);
        if (len > 4096) {
            return reply_result(TPM_BAD_PARAMETER);
        }
        return reply_result(tpm_running ?
                            TPM_IO_Hash_Data(req + 4, len) : TPM_FAIL);
    }
    case CMD_HASH_END:
        return reply_result(tpm_running ? TPM_IO_Hash_End() : TPM_FAIL);
    case CMD_CANCEL_TPM_CMD:
        return reply_result(TPMLIB_CancelCommand());
    case CMD_STORE_VOLATILE: {
        unsigned char *buf = NULL;
        uint32_t len = 0;

        res = tpm_running ? TPMLIB_VolatileAll_Store(&buf, &len) : TPM_FAIL;
        if (res == TPM_SUCCESS) {
            res = nv_store(buf, len, 0, TPM_VOLATILESTATE_NAME);
        }
        TPM_Free(buf);
        return reply_result(res);
    }
    case CMD_GET_STATEBLOB: {
        uint32_t type, flags;
        unsigned char *buf = NULL;
        uint32_t len = 0;
        uint32_t hdr[4];
        bool ok;

        memcpy(&flags, req, 4);
        memcpy(&type, req + 4, 4);
        type = ntohl(type);
        if (!blob_name(type)) {
            res = TPM_BAD_PARAMETER;
        } else if (tpm_running) {
            res = TPMLIB_GetState(blob_libtpms_type(type), &buf, &len);
        } else {
            res = nv_load(&buf, &len, 0, blob_name(type));
            if (res == TPM_RETRY) {
                /* no such state: an empty blob */
                res = TPM_SUCCESS;
                len = 0;
            }
        }
        if (res != TPM_SUCCESS) {
            len = 0;
        }
        hdr[0] = htonl(res);
        hdr[1] = htonl(0);          /* not encrypted */
        hdr[2] = htonl(len);
        hdr[3] = htonl(len);
        ok = ctrl_write(hdr, sizeof(hdr)) && (!len || ctrl_write(buf, len));
        TPM_Free(buf);
        return ok;
    }
    case CMD_SET_STATEBLOB: {
        uint32_t type, len;
        unsigned char *buf;

        memcpy(&type, req + 4, 4);
        memcpy(&len, req + 8, 4);
        type = ntohl(type);
        len = ntohl(len);
        buf = malloc(len ? len : 1);
        if (len && !ctrl_read(buf, len)) {
            free(buf);
            return false;
        }
        if (!blob_name(type)) {
            res = TPM_BAD_PARAMETER;
        } else if (tpm_running) {
            /* swtpm takes state blobs while the TPM is stopped */
            res = TPM_BAD_ORDINAL;
        } else {
            res = nv_store(buf, len, 0, blob_name(type));
        }
        free(buf);
        return reply_result(res);
    }
    case CMD_GET_CONFIG: {
        uint32_t resp[2] = { htonl(TPM_SUCCESS), 0 };

        return ctrl_write(resp, sizeof(resp));
    }
    case CMD_SET_DATAFD: {
        int i;

        res = TPM_FAIL;
        for (i = 0; i < pending_nitems; i++) {
            if (pending_items[i].type == W32FD_SOCKET &&
                res == TPM_FAIL) {
                if (data != INVALID_SOCKET) {
                    closesocket(data);
                }
                data = (SOCKET)pending_items[i].handle;
                res = TPM_SUCCESS;
            } else if (pending_items[i].type == W32FD_SOCKET) {
                closesocket((SOCKET)pending_items[i].handle);
            } else {
                CloseHandle(pending_items[i].handle);
            }
        }
        pending_nitems = 0;
        logit(1, "data channel: %s\n", res ? "none" : "set");
        return reply_result(res);
    }
    case CMD_SET_BUFFERSIZE: {
        uint32_t wanted, min_size = 0, max_size = 0, actual;
        uint32_t resp[4];

        memcpy(&wanted, req, 4);
        wanted = ntohl(wanted);
        if (wanted && tpm_running) {
            return reply_result(TPM_BAD_ORDINAL);
        }
        actual = TPMLIB_SetBufferSize(wanted, &min_size, &max_size);
        resp[0] = htonl(TPM_SUCCESS);
        resp[1] = htonl(actual);
        resp[2] = htonl(min_size);
        resp[3] = htonl(max_size);
        return ctrl_write(resp, sizeof(resp));
    }
    case CMD_GET_INFO: {
        uint64_t flags;
        uint32_t offset, hdr[3];
        char *info;
        size_t total, len;
        bool ok;

        memcpy(&flags, req, 8);
        memcpy(&offset, req + 8, 4);
        flags = ((uint64_t)ntohl((uint32_t)flags) << 32) |
                ntohl((uint32_t)(flags >> 32));
        offset = ntohl(offset);
        info = TPMLIB_GetInfo((enum TPMLIB_InfoFlags)flags);
        total = info ? strlen(info) + 1 : 0;
        len = offset < total ? total - offset : 0;
        if (len > PTM_GETINFO_SIZE) {
            len = PTM_GETINFO_SIZE;
        }
        hdr[0] = htonl(TPM_SUCCESS);
        hdr[1] = htonl(total);
        hdr[2] = htonl(len);
        ok = ctrl_write(hdr, sizeof(hdr)) &&
             (!len || ctrl_write(info + offset, len));
        free(info);
        return ok;
    }
    case CMD_LOCK_STORAGE:
        /* the state directory is used by this process only */
        return reply_result(TPM_SUCCESS);
    default:
        logit(1, "unknown control command %u\n", cmd);
        return reply_result(TPM_BAD_ORDINAL);
    }
}

/* ------------------------------------------------------------------ */
/* The data channel: TPM commands                                      */

static bool recv_all(SOCKET s, void *buf, size_t len)
{
    char *p = buf;

    while (len) {
        int n = recv(s, p, (int)len, 0);

        if (n <= 0) {
            if (n < 0 && WSAGetLastError() == WSAEWOULDBLOCK) {
                WSAPOLLFD pfd = { .fd = s, .events = POLLRDNORM };

                WSAPoll(&pfd, 1, -1);
                continue;
            }
            return false;
        }
        p += n;
        len -= n;
    }
    return true;
}

static bool send_all(SOCKET s, const void *buf, size_t len)
{
    const char *p = buf;

    while (len) {
        int n = send(s, p, (int)len, 0);

        if (n <= 0) {
            if (n < 0 && WSAGetLastError() == WSAEWOULDBLOCK) {
                WSAPOLLFD pfd = { .fd = s, .events = POLLWRNORM };

                WSAPoll(&pfd, 1, -1);
                continue;
            }
            return false;
        }
        p += n;
        len -= n;
    }
    return true;
}

static bool data_handle(void)
{
    static unsigned char *resp;
    static uint32_t resp_size;
    unsigned char hdr[10], *cmd;
    uint32_t len, resp_len = 0;
    TPM_RESULT rc;
    bool ok;

    if (!recv_all(data, hdr, sizeof(hdr))) {
        return false;
    }
    len = ((uint32_t)hdr[2] << 24) | (hdr[3] << 16) | (hdr[4] << 8) | hdr[5];
    if (len < sizeof(hdr) || len > 64 * 1024) {
        return false;
    }
    cmd = malloc(len);
    memcpy(cmd, hdr, sizeof(hdr));
    if (!recv_all(data, cmd + sizeof(hdr), len - sizeof(hdr))) {
        free(cmd);
        return false;
    }
    if (!tpm_running) {
        /* TPM_RC_FAILURE */
        static const unsigned char fail[10] = {
            0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01,
        };
        free(cmd);
        return send_all(data, fail, sizeof(fail));
    }
    rc = TPMLIB_Process(&resp, &resp_len, &resp_size, cmd, len);
    free(cmd);
    logit(3, "TPM command: %u bytes, result 0x%x, %u bytes\n", len, rc,
          resp_len);
    if (rc != TPM_SUCCESS || !resp_len) {
        return false;
    }
    ok = send_all(data, resp, resp_len);
    return ok;
}

/* ------------------------------------------------------------------ */

static const char *opt_value(const char *opts, const char *key)
{
    static char buf[1024];
    size_t klen = strlen(key);
    const char *p = opts;

    while (p && *p) {
        if (!strncmp(p, key, klen) && p[klen] == '=') {
            const char *v = p + klen + 1, *end = strchr(v, ',');
            size_t len = end ? (size_t)(end - v) : strlen(v);

            if (len >= sizeof(buf)) {
                len = sizeof(buf) - 1;
            }
            memcpy(buf, v, len);
            buf[len] = 0;
            return buf;
        }
        p = strchr(p, ',');
        if (p) {
            p++;
        }
    }
    return NULL;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: swtpm socket --tpm2 --tpmstate dir=DIR "
            "--ctrl type=unixio,path=SOCKET\n"
            "        [--log file=FILE,level=N] [--pid file=FILE] "
            "[--flags not-need-init[,startup-clear]] [--terminate]\n");
    exit(2);
}

int main(int argc, char **argv)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    const char *ctrl_path = NULL, *v;
    bool not_need_init = false;
    WSADATA wsa;
    int i;

    if (argc < 2 || strcmp(argv[1], "socket") != 0) {
        if (argc >= 2 && !strcmp(argv[1], "--version")) {
            printf("TPM emulator version 0.10.1 (swtpm for Windows)\n");
            return 0;
        }
        usage();
    }
    for (i = 2; i < argc; i++) {
        const char *a = argv[i];
        const char *o = i + 1 < argc ? argv[i + 1] : NULL;

        if (!strcmp(a, "--tpm2")) {
            continue;
        } else if (!strcmp(a, "--terminate")) {
            terminate_on_hangup = true;
        } else if (!strcmp(a, "--tpmstate") && o) {
            v = opt_value(o, "dir");
            state_dir = v ? strdup(v) : NULL;
            i++;
        } else if (!strcmp(a, "--ctrl") && o) {
            v = opt_value(o, "path");
            ctrl_path = v ? strdup(v) : NULL;
            i++;
        } else if (!strcmp(a, "--log") && o) {
            if ((v = opt_value(o, "file"))) {
                log_file = fopen(v, "a");
            } else if ((v = opt_value(o, "fd"))) {
                log_file = _fdopen(atoi(v), "a");
            }
            if ((v = opt_value(o, "level"))) {
                log_level = atoi(v);
            }
            i++;
        } else if (!strcmp(a, "--pid") && o) {
            if ((v = opt_value(o, "file"))) {
                FILE *f = fopen(v, "w");

                if (f) {
                    fprintf(f, "%lu\n", GetCurrentProcessId());
                    fclose(f);
                }
            }
            i++;
        } else if (!strcmp(a, "--flags") && o) {
            not_need_init = strstr(o, "not-need-init") != NULL;
            i++;
        } else if (!strcmp(a, "--daemon")) {
            FreeConsole();
        } else {
            usage();
        }
    }
    if (!state_dir || !ctrl_path) {
        usage();
    }
    if (strlen(ctrl_path) >= sizeof(addr.sun_path)) {
        die("swtpm: socket path too long: %s\n", ctrl_path);
    }

    if (TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2) != TPM_SUCCESS ||
        TPMLIB_RegisterCallbacks(&callbacks) != TPM_SUCCESS) {
        die("swtpm: cannot set up libtpms\n");
    }
    if (not_need_init && tpm_start(0) != TPM_SUCCESS) {
        die("swtpm: cannot start the TPM\n");
    }

    WSAStartup(MAKEWORD(2, 2), &wsa);
    ctrl_listen = socket(AF_UNIX, SOCK_STREAM, 0);
    strcpy(addr.sun_path, ctrl_path);
    DeleteFileA(ctrl_path);
    if (ctrl_listen == INVALID_SOCKET ||
        bind(ctrl_listen, (struct sockaddr *)&addr, sizeof(addr)) ||
        listen(ctrl_listen, 1)) {
        die("swtpm: cannot listen on %s (error %d)\n", ctrl_path,
            WSAGetLastError());
    }
    logit(1, "listening on %s\n", ctrl_path);

    for (;;) {
        WSAPOLLFD fds[2];
        int n = 0;

        if (ctrl == INVALID_SOCKET) {
            fds[n].fd = ctrl_listen;
        } else {
            fds[n].fd = ctrl;
        }
        fds[n++].events = POLLRDNORM;
        if (data != INVALID_SOCKET) {
            fds[n].fd = data;
            fds[n++].events = POLLRDNORM;
        }
        if (WSAPoll(fds, n, -1) < 0) {
            die("swtpm: poll failed (error %d)\n", WSAGetLastError());
        }
        if (fds[0].revents) {
            if (ctrl == INVALID_SOCKET) {
                ctrl = accept(ctrl_listen, NULL, NULL);
                memset(&ctrl_state, 0, sizeof(ctrl_state));
                logit(1, "control connection\n");
            } else if (!ctrl_handle()) {
                logit(1, "control connection closed\n");
                closesocket(ctrl);
                ctrl = INVALID_SOCKET;
                w32fd_state_free(&ctrl_state);
                if (terminate_on_hangup) {
                    break;
                }
            }
        }
        if (n > 1 && fds[1].revents && !data_handle()) {
            logit(1, "data connection closed\n");
            closesocket(data);
            data = INVALID_SOCKET;
            if (terminate_on_hangup) {
                break;
            }
        }
    }
    tpm_stop();
    DeleteFileA(ctrl_path);
    return 0;
}
