/*
 * The FUSE export on Windows, with WinFsp
 *
 * On Linux the export mounts FUSE over a regular file, which then reads and
 * writes the block node.  Windows file systems (WinFsp's too) are mounted
 * on a drive letter or on a directory that does not exist yet: the export
 * mounts a WinFsp file system there whose root holds one file, named after
 * the export, which is the image.  WinFsp's DLL is loaded when an export is
 * made (FspLoad()), so that QEMU starts without it.
 *
 * WinFsp calls the operations in its own threads: block I/O goes to the
 * export's AioContext in a coroutine, the thread waits for it.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/coroutine.h"
#include "qemu/thread.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-block.h"
#include "block/block.h"
#include "block/block_int-common.h"
#include "block/export.h"
#include "system/block-backend.h"
#include <sddl.h>

#define FSP_API         /* the functions come from GetProcAddress() */
/* WinFsp's headers declare MSVC's intrinsic, a macro of MinGW */
#pragma push_macro("_ReadWriteBarrier")
#undef _ReadWriteBarrier
#include <winfsp/winfsp.h>
#pragma pop_macro("_ReadWriteBarrier")

#define FUSE_WIN32_FILE_CONTEXT ((PVOID)2)
#define FUSE_WIN32_ROOT_CONTEXT ((PVOID)1)

typedef struct FuseExport {
    BlockExport common;

    FSP_FILE_SYSTEM *fs;
    char *mountpoint;
    gunichar2 *name;            /* the file in the root */
    PSECURITY_DESCRIPTOR sd;
    ULONG sd_size;
    bool writable;
    bool growable;
    UINT64 created;
} FuseExport;

/* WinFsp, loaded at run time */
static struct {
    HMODULE dll;
    typeof(FspFileSystemCreate) *Create;
    typeof(FspFileSystemDelete) *Delete;
    typeof(FspFileSystemSetMountPoint) *SetMountPoint;
    typeof(FspFileSystemRemoveMountPoint) *RemoveMountPoint;
    typeof(FspFileSystemStartDispatcher) *StartDispatcher;
    typeof(FspFileSystemStopDispatcher) *StopDispatcher;
    typeof(FspFileSystemAddDirInfo) *AddDirInfo;
} wfsp;

static bool winfsp_load(Error **errp)
{
    if (wfsp.dll) {
        return true;
    }
    if (!NT_SUCCESS(FspLoad((PVOID *)&wfsp.dll))) {
        error_setg(errp, "FUSE export: WinFsp is not installed "
                   "(https://winfsp.dev)");
        return false;
    }
#define LOAD(field, name) \
    wfsp.field = (typeof(wfsp.field))GetProcAddress(wfsp.dll, name)
    LOAD(Create, "FspFileSystemCreate");
    LOAD(Delete, "FspFileSystemDelete");
    LOAD(SetMountPoint, "FspFileSystemSetMountPoint");
    LOAD(RemoveMountPoint, "FspFileSystemRemoveMountPoint");
    LOAD(StartDispatcher, "FspFileSystemStartDispatcher");
    LOAD(StopDispatcher, "FspFileSystemStopDispatcher");
    LOAD(AddDirInfo, "FspFileSystemAddDirInfo");
#undef LOAD
    if (!wfsp.Create || !wfsp.Delete || !wfsp.SetMountPoint ||
        !wfsp.RemoveMountPoint || !wfsp.StartDispatcher ||
        !wfsp.StopDispatcher || !wfsp.AddDirInfo) {
        error_setg(errp, "FUSE export: unknown version of WinFsp");
        wfsp.dll = NULL;
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Block I/O, in the export's AioContext                               */

typedef enum {
    WF_READ,
    WF_WRITE,
    WF_FLUSH,
    WF_LENGTH,
    WF_TRUNCATE,
} WinFuseOp;

typedef struct {
    FuseExport *exp;
    WinFuseOp op;
    void *buf;
    uint64_t offset;
    uint64_t len;
    int64_t ret;
    QemuEvent done;
} WinFuseReq;

static void coroutine_fn wf_co(void *opaque)
{
    WinFuseReq *req = opaque;
    BlockBackend *blk = req->exp->common.blk;
    int64_t len;

    switch (req->op) {
    case WF_READ:
        req->ret = blk_co_pread(blk, req->offset, req->len, req->buf, 0);
        break;
    case WF_WRITE:
        len = blk_co_getlength(blk);
        if (len < 0) {
            req->ret = len;
            break;
        }
        if (req->offset + req->len > len) {
            if (!req->exp->growable) {
                /* as the Linux export: writes stop at the end */
                if (req->offset >= len) {
                    req->ret = 0;
                    req->len = 0;
                    break;
                }
                req->len = len - req->offset;
            } else {
                req->ret = blk_co_truncate(blk, req->offset + req->len,
                                           true, PREALLOC_MODE_OFF, 0, NULL);
                if (req->ret < 0) {
                    break;
                }
            }
        }
        req->ret = blk_co_pwrite(blk, req->offset, req->len, req->buf, 0);
        break;
    case WF_FLUSH:
        req->ret = blk_co_flush(blk);
        break;
    case WF_LENGTH:
        req->ret = blk_co_getlength(blk);
        break;
    case WF_TRUNCATE:
        req->ret = blk_co_truncate(blk, req->offset, true, PREALLOC_MODE_OFF,
                                   0, NULL);
        break;
    }
    blk_exp_unref(&req->exp->common);
    qemu_event_set(&req->done);
}

static void wf_bh(void *opaque)
{
    WinFuseReq *req = opaque;

    qemu_coroutine_enter(qemu_coroutine_create(wf_co, req));
}

/* From a thread of WinFsp: run @op and wait for it */
static int64_t wf_run(FuseExport *exp, WinFuseOp op, void *buf,
                      uint64_t offset, uint64_t *len)
{
    WinFuseReq req = {
        .exp = exp,
        .op = op,
        .buf = buf,
        .offset = offset,
        .len = len ? *len : 0,
    };

    qemu_event_init(&req.done, false);
    blk_exp_ref(&exp->common);
    aio_bh_schedule_oneshot(exp->common.ctx, wf_bh, &req);
    qemu_event_wait(&req.done);
    qemu_event_destroy(&req.done);
    if (len) {
        *len = req.len;
    }
    return req.ret;
}

static NTSTATUS errno_status(int64_t ret)
{
    switch (-ret) {
    case ENOSPC:
        return STATUS_DISK_FULL;
    case EACCES:
    case EPERM:
        return STATUS_ACCESS_DENIED;
    case EROFS:
        return STATUS_MEDIA_WRITE_PROTECTED;
    case ENOTSUP:
        return STATUS_NOT_SUPPORTED;
    default:
        return STATUS_IO_DEVICE_ERROR;
    }
}

/* ------------------------------------------------------------------ */
/* The file system: a root directory holding the image                 */

static FuseExport *fs_export(FSP_FILE_SYSTEM *fs)
{
    return fs->UserContext;
}

static bool is_root(PWSTR name)
{
    return !wcscmp(name, L"\\") || !*name;
}

static bool is_image(FuseExport *exp, PWSTR name)
{
    return name[0] == L'\\' && !wcscmp(name + 1, (wchar_t *)exp->name);
}

static void fill_info(FuseExport *exp, bool root, FSP_FSCTL_FILE_INFO *fi)
{
    memset(fi, 0, sizeof(*fi));
    fi->CreationTime = fi->LastAccessTime = fi->LastWriteTime =
        fi->ChangeTime = exp->created;
    if (root) {
        fi->FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        fi->IndexNumber = 1;
    } else {
        int64_t len = wf_run(exp, WF_LENGTH, NULL, 0, NULL);

        fi->FileAttributes = exp->writable ? FILE_ATTRIBUTE_NORMAL :
                             FILE_ATTRIBUTE_READONLY;
        fi->FileSize = len > 0 ? len : 0;
        fi->AllocationSize = QEMU_ALIGN_UP(fi->FileSize, 512);
        fi->IndexNumber = 2;
    }
}

static NTSTATUS op_get_volume_info(FSP_FILE_SYSTEM *fs,
                                   FSP_FSCTL_VOLUME_INFO *vi)
{
    FuseExport *exp = fs_export(fs);
    int64_t len = wf_run(exp, WF_LENGTH, NULL, 0, NULL);

    memset(vi, 0, sizeof(*vi));
    vi->TotalSize = len > 0 ? len : 0;
    vi->FreeSize = 0;
    vi->VolumeLabelLength = 4 * sizeof(WCHAR);
    memcpy(vi->VolumeLabel, L"QEMU", 4 * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

static NTSTATUS op_get_security_by_name(FSP_FILE_SYSTEM *fs, PWSTR name,
                                        PUINT32 attributes,
                                        PSECURITY_DESCRIPTOR sd,
                                        SIZE_T *sd_size)
{
    FuseExport *exp = fs_export(fs);

    if (!is_root(name) && !is_image(exp, name)) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (attributes) {
        *attributes = is_root(name) ? FILE_ATTRIBUTE_DIRECTORY :
                      exp->writable ? FILE_ATTRIBUTE_NORMAL :
                      FILE_ATTRIBUTE_READONLY;
    }
    if (sd_size) {
        if (*sd_size < exp->sd_size) {
            *sd_size = exp->sd_size;
            return STATUS_BUFFER_OVERFLOW;
        }
        *sd_size = exp->sd_size;
        if (sd) {
            memcpy(sd, exp->sd, exp->sd_size);
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS op_create(FSP_FILE_SYSTEM *fs, PWSTR name,
                          UINT32 create_options, UINT32 access,
                          UINT32 attributes, PSECURITY_DESCRIPTOR sd,
                          UINT64 allocation, PVOID *ctx,
                          FSP_FSCTL_FILE_INFO *fi)
{
    /* the export holds its image only */
    return STATUS_ACCESS_DENIED;
}

static NTSTATUS op_open(FSP_FILE_SYSTEM *fs, PWSTR name,
                        UINT32 create_options, UINT32 access, PVOID *ctx,
                        FSP_FSCTL_FILE_INFO *fi)
{
    FuseExport *exp = fs_export(fs);

    if (is_root(name)) {
        *ctx = FUSE_WIN32_ROOT_CONTEXT;
        fill_info(exp, true, fi);
        return STATUS_SUCCESS;
    }
    if (!is_image(exp, name)) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (create_options & FILE_DIRECTORY_FILE) {
        return STATUS_NOT_A_DIRECTORY;
    }
    *ctx = FUSE_WIN32_FILE_CONTEXT;
    fill_info(exp, false, fi);
    return STATUS_SUCCESS;
}

static NTSTATUS op_overwrite(FSP_FILE_SYSTEM *fs, PVOID ctx, UINT32 attributes,
                             BOOLEAN replace, UINT64 allocation,
                             FSP_FSCTL_FILE_INFO *fi)
{
    FuseExport *exp = fs_export(fs);
    int64_t ret;

    /* O_TRUNC: the node shrinks to nothing only if it may change size */
    if (!exp->writable || !exp->growable) {
        return STATUS_ACCESS_DENIED;
    }
    ret = wf_run(exp, WF_TRUNCATE, NULL, 0, NULL);
    if (ret < 0) {
        return errno_status(ret);
    }
    fill_info(exp, false, fi);
    return STATUS_SUCCESS;
}

static VOID op_cleanup(FSP_FILE_SYSTEM *fs, PVOID ctx, PWSTR name,
                       ULONG flags)
{
}

static VOID op_close(FSP_FILE_SYSTEM *fs, PVOID ctx)
{
}

static NTSTATUS op_read(FSP_FILE_SYSTEM *fs, PVOID ctx, PVOID buf,
                        UINT64 offset, ULONG length, PULONG done)
{
    FuseExport *exp = fs_export(fs);
    int64_t len, ret;
    uint64_t n;

    if (ctx != FUSE_WIN32_FILE_CONTEXT) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    len = wf_run(exp, WF_LENGTH, NULL, 0, NULL);
    if (len < 0) {
        return errno_status(len);
    }
    if (offset >= len) {
        return STATUS_END_OF_FILE;
    }
    n = MIN((uint64_t)length, len - offset);
    ret = wf_run(exp, WF_READ, buf, offset, &n);
    if (ret < 0) {
        return errno_status(ret);
    }
    *done = n;
    return STATUS_SUCCESS;
}

static NTSTATUS op_write(FSP_FILE_SYSTEM *fs, PVOID ctx, PVOID buf,
                         UINT64 offset, ULONG length, BOOLEAN to_end,
                         BOOLEAN constrained, PULONG done,
                         FSP_FSCTL_FILE_INFO *fi)
{
    FuseExport *exp = fs_export(fs);
    uint64_t n = length;
    int64_t ret, len;

    if (ctx != FUSE_WIN32_FILE_CONTEXT) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!exp->writable) {
        return STATUS_MEDIA_WRITE_PROTECTED;
    }
    len = wf_run(exp, WF_LENGTH, NULL, 0, NULL);
    if (len < 0) {
        return errno_status(len);
    }
    if (to_end) {
        offset = len;
    }
    if (constrained) {
        /* paging I/O: within the file only */
        if (offset >= len) {
            *done = 0;
            fill_info(exp, false, fi);
            return STATUS_SUCCESS;
        }
        n = MIN(n, len - offset);
    }
    ret = wf_run(exp, WF_WRITE, buf, offset, &n);
    if (ret < 0) {
        return errno_status(ret);
    }
    *done = n;
    fill_info(exp, false, fi);
    return STATUS_SUCCESS;
}

static NTSTATUS op_flush(FSP_FILE_SYSTEM *fs, PVOID ctx,
                         FSP_FSCTL_FILE_INFO *fi)
{
    FuseExport *exp = fs_export(fs);
    int64_t ret = wf_run(exp, WF_FLUSH, NULL, 0, NULL);

    if (ret < 0) {
        return errno_status(ret);
    }
    if (ctx) {
        fill_info(exp, ctx == FUSE_WIN32_ROOT_CONTEXT, fi);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS op_get_file_info(FSP_FILE_SYSTEM *fs, PVOID ctx,
                                 FSP_FSCTL_FILE_INFO *fi)
{
    fill_info(fs_export(fs), ctx == FUSE_WIN32_ROOT_CONTEXT, fi);
    return STATUS_SUCCESS;
}

static NTSTATUS op_set_file_size(FSP_FILE_SYSTEM *fs, PVOID ctx,
                                 UINT64 size, BOOLEAN allocation,
                                 FSP_FSCTL_FILE_INFO *fi)
{
    FuseExport *exp = fs_export(fs);
    int64_t ret;

    if (ctx != FUSE_WIN32_FILE_CONTEXT) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!allocation) {
        /* as setattr(size) on Linux: growable exports change size */
        if (!exp->writable || !exp->growable) {
            return STATUS_ACCESS_DENIED;
        }
        ret = wf_run(exp, WF_TRUNCATE, NULL, size, NULL);
        if (ret < 0) {
            return errno_status(ret);
        }
    }
    fill_info(exp, false, fi);
    return STATUS_SUCCESS;
}

static NTSTATUS op_read_directory(FSP_FILE_SYSTEM *fs, PVOID ctx,
                                  PWSTR pattern, PWSTR marker, PVOID buf,
                                  ULONG length, PULONG done)
{
    FuseExport *exp = fs_export(fs);
    union {
        UINT8 bytes[sizeof(FSP_FSCTL_DIR_INFO) + 512 * sizeof(WCHAR)];
        FSP_FSCTL_DIR_INFO d;
    } entry;
    size_t name_len = wcslen((wchar_t *)exp->name);

    if (ctx != FUSE_WIN32_ROOT_CONTEXT) {
        return STATUS_NOT_A_DIRECTORY;
    }
    *done = 0;
    /* the image, unless the listing resumes after it */
    if (!marker || wcscmp(marker, (wchar_t *)exp->name) < 0) {
        memset(&entry, 0, sizeof(entry));
        entry.d.Size = (UINT16)(offsetof(FSP_FSCTL_DIR_INFO, FileNameBuf) +
                                name_len * sizeof(WCHAR));
        fill_info(exp, false, &entry.d.FileInfo);
        memcpy(entry.d.FileNameBuf, exp->name, name_len * sizeof(WCHAR));
        if (!wfsp.AddDirInfo(&entry.d, buf, length, done)) {
            return STATUS_SUCCESS;
        }
    }
    wfsp.AddDirInfo(NULL, buf, length, done);
    return STATUS_SUCCESS;
}

static FSP_FILE_SYSTEM_INTERFACE fuse_win32_interface = {
    .GetVolumeInfo = op_get_volume_info,
    .GetSecurityByName = op_get_security_by_name,
    .Create = op_create,
    .Open = op_open,
    .Overwrite = op_overwrite,
    .Cleanup = op_cleanup,
    .Close = op_close,
    .Read = op_read,
    .Write = op_write,
    .Flush = op_flush,
    .GetFileInfo = op_get_file_info,
    .SetFileSize = op_set_file_size,
    .ReadDirectory = op_read_directory,
};

/* Access for QEMU's user (allow-other: everyone), SYSTEM and Administrators */
static bool make_security(FuseExport *exp, bool allow_other, Error **errp)
{
    g_autofree char *sddl = NULL;
    g_autofree gunichar2 *wsddl = NULL;
    HANDLE token;
    union {
        TOKEN_USER tu;
        UINT8 bytes[256];
    } user;
    DWORD size;
    LPWSTR sid = NULL;
    g_autofree char *usid = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        error_setg_win32(errp, GetLastError(), "FUSE export: no token");
        return false;
    }
    if (!GetTokenInformation(token, TokenUser, &user, sizeof(user), &size) ||
        !ConvertSidToStringSidW(user.tu.User.Sid, &sid)) {
        CloseHandle(token);
        error_setg_win32(errp, GetLastError(), "FUSE export: no user SID");
        return false;
    }
    CloseHandle(token);
    usid = g_utf16_to_utf8((gunichar2 *)sid, -1, NULL, NULL, NULL);
    LocalFree(sid);
    sddl = g_strdup_printf("O:%sG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)%s",
                           usid, usid, allow_other ? "(A;;FA;;;WD)" : "");
    wsddl = g_utf8_to_utf16(sddl, -1, NULL, NULL, NULL);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            (LPCWSTR)wsddl, SDDL_REVISION_1, &exp->sd, &exp->sd_size)) {
        error_setg_win32(errp, GetLastError(),
                         "FUSE export: cannot make the security descriptor");
        return false;
    }
    return true;
}

static int fuse_export_create(BlockExport *blk_exp,
                              BlockExportOptions *blk_exp_args,
                              AioContext *const *multithread,
                              size_t mt_count,
                              Error **errp)
{
    FuseExport *exp = container_of(blk_exp, FuseExport, common);
    BlockExportOptionsFuse *args = &blk_exp_args->u.fuse;
    FSP_FSCTL_VOLUME_PARAMS params = { 0 };
    g_autofree gunichar2 *wmount = NULL;
    FILETIME now;
    NTSTATUS st;
    int ret;

    assert(blk_exp_args->type == BLOCK_EXPORT_TYPE_FUSE);
    if (multithread) {
        error_setg(errp, "FUSE export on Windows: multithreading is not "
                   "supported");
        return -EINVAL;
    }
    if (!winfsp_load(errp)) {
        return -ENOTSUP;
    }

    if (args->growable || blk_exp_args->writable) {
        uint64_t perm, shared;

        blk_get_perm(exp->common.blk, &perm, &shared);
        ret = blk_set_perm(exp->common.blk, perm | BLK_PERM_RESIZE, shared,
                           errp);
        if (ret < 0) {
            return ret;
        }
    }

    exp->mountpoint = g_strdup(args->mountpoint);
    exp->writable = blk_exp_args->writable;
    exp->growable = args->growable;
    exp->name = g_utf8_to_utf16(blk_exp_args->id, -1, NULL, NULL, NULL);
    GetSystemTimeAsFileTime(&now);
    exp->created = ((UINT64)now.dwHighDateTime << 32) | now.dwLowDateTime;
    if (!make_security(exp, args->has_allow_other &&
                       args->allow_other == FUSE_EXPORT_ALLOW_OTHER_ON,
                       errp)) {
        return -EINVAL;
    }

    params.Version = sizeof(params);
    params.SectorSize = 512;
    params.SectorsPerAllocationUnit = 1;
    params.MaxComponentLength = 255;
    params.VolumeCreationTime = exp->created;
    params.VolumeSerialNumber = (UINT32)exp->created;
    params.FileInfoTimeout = 0;     /* the node may change size */
    params.CaseSensitiveSearch = 1;
    params.CasePreservedNames = 1;
    params.UnicodeOnDisk = 1;
    params.ReadOnlyVolume = !exp->writable;
    params.PostCleanupWhenModifiedOnly = 1;
    wcscpy(params.FileSystemName, L"QEMU");

    st = wfsp.Create(L"" FSP_FSCTL_DISK_DEVICE_NAME, &params,
                     &fuse_win32_interface, &exp->fs);
    if (!NT_SUCCESS(st)) {
        error_setg(errp, "FUSE export: cannot create the file system "
                   "(status 0x%lx)", (unsigned long)st);
        return -EIO;
    }
    exp->fs->UserContext = exp;

    wmount = g_utf8_to_utf16(args->mountpoint, -1, NULL, NULL, NULL);
    st = wfsp.SetMountPoint(exp->fs, (PWSTR)wmount);
    if (!NT_SUCCESS(st)) {
        error_setg(errp, "FUSE export: cannot mount on '%s' (status 0x%lx): "
                   "a drive letter or a directory that does not exist",
                   args->mountpoint, (unsigned long)st);
        wfsp.Delete(exp->fs);
        exp->fs = NULL;
        return -EIO;
    }
    st = wfsp.StartDispatcher(exp->fs, 0);
    if (!NT_SUCCESS(st)) {
        error_setg(errp, "FUSE export: cannot start (status 0x%lx)",
                   (unsigned long)st);
        wfsp.RemoveMountPoint(exp->fs);
        wfsp.Delete(exp->fs);
        exp->fs = NULL;
        return -EIO;
    }
    return 0;
}

/*
 * Stop the dispatcher outside the main loop's lock: its threads may be
 * waiting for block I/O that needs the main loop
 */
static void *fuse_win32_stop_thread(void *opaque)
{
    FSP_FILE_SYSTEM *fs = opaque;

    wfsp.StopDispatcher(fs);
    wfsp.RemoveMountPoint(fs);
    wfsp.Delete(fs);
    return NULL;
}

static void fuse_export_shutdown(BlockExport *blk_exp)
{
    FuseExport *exp = container_of(blk_exp, FuseExport, common);
    QemuThread thread;

    if (exp->fs) {
        FSP_FILE_SYSTEM *fs = exp->fs;

        exp->fs = NULL;
        qemu_thread_create(&thread, "fuse-win32-stop",
                           fuse_win32_stop_thread, fs, QEMU_THREAD_JOINABLE);
        /* the main loop runs the I/O of requests still in WinFsp */
        while (!qemu_thread_is_self(&thread)) {
            if (WaitForSingleObject(qemu_thread_get_handle(&thread), 0) ==
                WAIT_OBJECT_0) {
                break;
            }
            aio_poll(qemu_get_aio_context(), false);
            Sleep(1);
        }
        qemu_thread_join(&thread);
    }
}

static void fuse_export_delete(BlockExport *blk_exp)
{
    FuseExport *exp = container_of(blk_exp, FuseExport, common);

    fuse_export_shutdown(blk_exp);
    if (exp->sd) {
        LocalFree(exp->sd);
    }
    g_free(exp->name);
    g_free(exp->mountpoint);
}

const BlockExportDriver blk_exp_fuse = {
    .type               = BLOCK_EXPORT_TYPE_FUSE,
    .instance_size      = sizeof(FuseExport),
    .create             = fuse_export_create,
    .delete             = fuse_export_delete,
    .request_shutdown   = fuse_export_shutdown,
};
