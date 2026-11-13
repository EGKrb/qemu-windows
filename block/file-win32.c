/*
 * Block driver for RAW files (win32)
 *
 * Copyright (c) 2006 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "block/block-io.h"
#include "block/block_int.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "block/raw-aio.h"
#include "trace.h"
#include "block/thread-pool.h"
#include "qemu/iov.h"
#include "qobject/qdict.h"
#include "qobject/qstring.h"
#include "qemu/win32-fdpass.h"
#include <windows.h>
#include <winioctl.h>
#include "scsi/pr-manager.h"
#include "scsi/constants.h"
#include "scsi/utils.h"

#define FTYPE_FILE 0
#define FTYPE_CD     1
#define FTYPE_HARDDISK 2
#define FTYPE_SG       3    /* a SCSI device that is not a disk: tape... */

typedef struct RawWin32AIOData {
    BlockDriverState *bs;
    HANDLE hfile;
    struct iovec *aio_iov;
    int aio_niov;
    size_t aio_nbytes;
    off64_t aio_offset;
    int aio_type;
} RawWin32AIOData;

typedef struct BDRVRawState {
    HANDLE hfile;
    int type;
    char drive_path[16]; /* format: "d:\" */
    QEMUWin32AIOState *aio;

    /* image locking, as file-posix.c does it */
    bool use_lock;
    uint64_t perm;
    uint64_t shared_perm;
    uint64_t locked_perm;
    uint64_t locked_shared_perm;

    /* SCSI pass-through (SG_IO, see include/scsi/sg-win32.h) */
    PRManager *pr_mgr;
} BDRVRawState;

typedef struct BDRVRawReopenState {
    HANDLE hfile;
} BDRVRawReopenState;

/*
 * Read/writes the data to/from a given linear buffer.
 *
 * Returns the number of bytes handles or -errno in case of an error. Short
 * reads are only returned if the end of the file is reached.
 */
static size_t handle_aiocb_rw(RawWin32AIOData *aiocb)
{
    size_t offset = 0;
    int i;

    for (i = 0; i < aiocb->aio_niov; i++) {
        OVERLAPPED ov;
        DWORD ret, ret_count, len;

        memset(&ov, 0, sizeof(ov));
        ov.Offset = (aiocb->aio_offset + offset);
        ov.OffsetHigh = (aiocb->aio_offset + offset) >> 32;
        len = aiocb->aio_iov[i].iov_len;
        if (aiocb->aio_type & QEMU_AIO_WRITE) {
            ret = WriteFile(aiocb->hfile, aiocb->aio_iov[i].iov_base,
                            len, &ret_count, &ov);
        } else {
            ret = ReadFile(aiocb->hfile, aiocb->aio_iov[i].iov_base,
                           len, &ret_count, &ov);
        }
        if (!ret) {
            ret_count = 0;
        }
        if (ret_count != len) {
            offset += ret_count;
            break;
        }
        offset += len;
    }

    return offset;
}

static int aio_worker(void *arg)
{
    RawWin32AIOData *aiocb = arg;
    ssize_t ret = 0;
    size_t count;

    switch (aiocb->aio_type & QEMU_AIO_TYPE_MASK) {
    case QEMU_AIO_READ:
        count = handle_aiocb_rw(aiocb);
        if (count < aiocb->aio_nbytes) {
            /* A short read means that we have reached EOF. Pad the buffer
             * with zeros for bytes after EOF. */
            iov_memset(aiocb->aio_iov, aiocb->aio_niov, count,
                      0, aiocb->aio_nbytes - count);

            count = aiocb->aio_nbytes;
        }
        if (count == aiocb->aio_nbytes) {
            ret = 0;
        } else {
            ret = -EINVAL;
        }
        break;
    case QEMU_AIO_WRITE:
        count = handle_aiocb_rw(aiocb);
        if (count == aiocb->aio_nbytes) {
            ret = 0;
        } else {
            ret = -EINVAL;
        }
        break;
    case QEMU_AIO_FLUSH:
        if (!FlushFileBuffers(aiocb->hfile)) {
            return -EIO;
        }
        break;
    default:
        fprintf(stderr, "invalid aio request (0x%x)\n", aiocb->aio_type);
        ret = -EINVAL;
        break;
    }

    g_free(aiocb);
    return ret;
}

static BlockAIOCB *paio_submit(BlockDriverState *bs, HANDLE hfile,
        int64_t offset, QEMUIOVector *qiov, int count,
        BlockCompletionFunc *cb, void *opaque, int type)
{
    RawWin32AIOData *acb = g_new(RawWin32AIOData, 1);

    acb->bs = bs;
    acb->hfile = hfile;
    acb->aio_type = type;

    if (qiov) {
        acb->aio_iov = qiov->iov;
        acb->aio_niov = qiov->niov;
        assert(qiov->size == count);
    }
    acb->aio_nbytes = count;
    acb->aio_offset = offset;

    trace_file_paio_submit(acb, opaque, offset, count, type);
    return thread_pool_submit_aio(aio_worker, acb, cb, opaque);
}

static int set_sparse(int fd)
{
    DWORD returned;
    return (int) DeviceIoControl((HANDLE)_get_osfhandle(fd), FSCTL_SET_SPARSE,
                                 NULL, 0, NULL, 0, &returned, NULL);
}

static void raw_detach_aio_context(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;

    if (s->aio) {
        win32_aio_detach_aio_context(s->aio, bdrv_get_aio_context(bs));
    }
}

static void raw_attach_aio_context(BlockDriverState *bs,
                                   AioContext *new_context)
{
    BDRVRawState *s = bs->opaque;

    if (s->aio) {
        win32_aio_attach_aio_context(s->aio, new_context);
    }
}

static void raw_probe_alignment(BlockDriverState *bs, Error **errp)
{
    BDRVRawState *s = bs->opaque;
    DWORD sectorsPerCluster, freeClusters, totalClusters, count;
    DISK_GEOMETRY_EX dg;
    BOOL status;

    if (s->type == FTYPE_CD) {
        bs->bl.request_alignment = 2048;
        return;
    }
    if (s->type == FTYPE_HARDDISK) {
        status = DeviceIoControl(s->hfile, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                 NULL, 0, &dg, sizeof(dg), &count, NULL);
        if (status != 0) {
            bs->bl.request_alignment = dg.Geometry.BytesPerSector;
            return;
        }
        /* try GetDiskFreeSpace too */
    }

    if (s->drive_path[0]) {
        GetDiskFreeSpace(s->drive_path, &sectorsPerCluster,
                         &dg.Geometry.BytesPerSector,
                         &freeClusters, &totalClusters);
        bs->bl.request_alignment = dg.Geometry.BytesPerSector;
        return;
    }

    /* XXX Does Windows support AIO on less than 512-byte alignment? */
    bs->bl.request_alignment = 512;
}

static void raw_parse_flags(int flags, bool use_aio, int *access_flags,
                            DWORD *overlapped)
{
    assert(access_flags != NULL);
    assert(overlapped != NULL);

    if (flags & BDRV_O_RDWR) {
        *access_flags = GENERIC_READ | GENERIC_WRITE;
    } else {
        *access_flags = GENERIC_READ;
    }

    *overlapped = FILE_ATTRIBUTE_NORMAL;
    if (use_aio) {
        *overlapped |= FILE_FLAG_OVERLAPPED;
    }
    if (flags & BDRV_O_NOCACHE) {
        *overlapped |= FILE_FLAG_NO_BUFFERING;
    }
}

static void raw_parse_filename(const char *filename, QDict *options,
                               Error **errp)
{
    bdrv_parse_filename_strip_prefix(filename, "file:", options);
}

static QemuOptsList raw_runtime_opts = {
    .name = "raw",
    .head = QTAILQ_HEAD_INITIALIZER(raw_runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "File name of the image",
        },
        {
            .name = "aio",
            .type = QEMU_OPT_STRING,
            .help = "host AIO implementation (threads, native)",
        },
        {
            .name = "locking",
            .type = QEMU_OPT_STRING,
            .help = "file locking mode (on/off/auto, default: auto)",
        },
        {
            .name = "pr-manager",
            .type = QEMU_OPT_STRING,
            .help = "id of persistent reservation manager object (default: none)",
        },
        { /* end of list */ }
    },
};

static bool get_aio_option(QemuOpts *opts, int flags, Error **errp)
{
    BlockdevAioOptions aio, aio_default;

    aio_default = (flags & BDRV_O_NATIVE_AIO) ? BLOCKDEV_AIO_OPTIONS_NATIVE
                                              : BLOCKDEV_AIO_OPTIONS_THREADS;
    aio = qapi_enum_parse(&BlockdevAioOptions_lookup, qemu_opt_get(opts, "aio"),
                          aio_default, errp);

    switch (aio) {
    case BLOCKDEV_AIO_OPTIONS_NATIVE:
        return true;
    case BLOCKDEV_AIO_OPTIONS_THREADS:
        return false;
    default:
        error_setg(errp, "Invalid AIO option");
    }
    return false;
}

/*
 * Image locking
 *
 * The bytes and their meaning are those of file-posix.c: a shared lock
 * on RAW_LOCK_PERM_BASE + i while permission i is held, on
 * RAW_LOCK_SHARED_BASE + i while it is not shared with others.  The
 * locks of LockFileEx() are mandatory, they would forbid I/O to the
 * header of the image: the bytes are moved past 2^62, where no data is
 * (libvirt-windows moves its own locks the same way).  An exclusive
 * LockFileEx() stands for the F_OFD_GETLK test; Windows does not
 * upgrade a lock of the same handle, so the test releases ours first.
 */
#define RAW_LOCK_SHADOW_OFFSET  (1ULL << 62)
#define RAW_LOCK_PERM_BASE      100
#define RAW_LOCK_SHARED_BASE    200

#define PERM_FOREACH(i) \
    for ((i) = 0; (1ULL << (i)) <= BLK_PERM_ALL; i++)

typedef enum {
    RAW_PL_PREPARE,
    RAW_PL_COMMIT,
    RAW_PL_ABORT,
} RawPermLockOp;

static int raw_lock_byte(HANDLE h, int off, bool exclusive)
{
    uint64_t offset = RAW_LOCK_SHADOW_OFFSET + off;
    OVERLAPPED ov = {
        .Offset = (DWORD)offset,
        .OffsetHigh = (DWORD)(offset >> 32),
    };
    DWORD flags = LOCKFILE_FAIL_IMMEDIATELY;
    DWORD size;
    int ret = 0;

    if (exclusive) {
        flags |= LOCKFILE_EXCLUSIVE_LOCK;
    }
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!LockFileEx(h, flags, 0, 1, 0, &ov)) {
        DWORD err = GetLastError();

        if (err == ERROR_IO_PENDING) {
            /* overlapped handles: the result comes at once anyway */
            if (!GetOverlappedResult(h, &ov, &size, TRUE)) {
                err = GetLastError();
            } else {
                err = 0;
            }
        }
        if (err == ERROR_LOCK_VIOLATION) {
            ret = -EAGAIN;
        } else if (err) {
            ret = -EIO;
        }
    }
    CloseHandle(ov.hEvent);
    return ret;
}

static int raw_unlock_byte(HANDLE h, int off)
{
    uint64_t offset = RAW_LOCK_SHADOW_OFFSET + off;
    OVERLAPPED ov = {
        .Offset = (DWORD)offset,
        .OffsetHigh = (DWORD)(offset >> 32),
    };

    return UnlockFileEx(h, 0, 1, 0, &ov) ? 0 : -EIO;
}

/* Does another handle hold a lock on the byte?  @held: we hold one */
static int raw_test_byte(HANDLE h, int off, bool held)
{
    int ret;

    if (held) {
        raw_unlock_byte(h, off);
    }
    ret = raw_lock_byte(h, off, true);
    if (!ret) {
        raw_unlock_byte(h, off);
    }
    if (held) {
        raw_lock_byte(h, off, false);
    }
    return ret;
}

#define raw_lock_error_setg_errno(errp, err, fmt, ...)                  \
    do {                                                                \
        if ((err) == EAGAIN || (err) == EACCES) {                       \
            error_setg((errp), (fmt), ## __VA_ARGS__);                  \
        } else {                                                        \
            error_setg_errno((errp), (err), (fmt), ## __VA_ARGS__);     \
        }                                                               \
    } while (0)

/*
 * Lock bytes indicated by @perm_lock_bits and @shared_perm_lock_bits in the
 * file; if @unlock == true, also unlock the unneeded bytes.
 * @shared_perm_lock_bits is the mask of all permissions that are NOT shared.
 */
static int raw_apply_lock_bytes(BDRVRawState *s, HANDLE h,
                                uint64_t perm_lock_bits,
                                uint64_t shared_perm_lock_bits,
                                bool unlock, Error **errp)
{
    int ret;
    int i;

    PERM_FOREACH(i) {
        int off = RAW_LOCK_PERM_BASE + i;
        uint64_t bit = (1ULL << i);
        if ((perm_lock_bits & bit) && !(s->locked_perm & bit)) {
            ret = raw_lock_byte(h, off, false);
            if (ret) {
                raw_lock_error_setg_errno(errp, -ret, "Failed to lock byte %d",
                                          off);
                return ret;
            }
            s->locked_perm |= bit;
        } else if (unlock && (s->locked_perm & bit) &&
                   !(perm_lock_bits & bit)) {
            ret = raw_unlock_byte(h, off);
            if (ret) {
                error_setg_errno(errp, -ret, "Failed to unlock byte %d", off);
                return ret;
            }
            s->locked_perm &= ~bit;
        }
    }
    PERM_FOREACH(i) {
        int off = RAW_LOCK_SHARED_BASE + i;
        uint64_t bit = (1ULL << i);
        if ((shared_perm_lock_bits & bit) && !(s->locked_shared_perm & bit)) {
            ret = raw_lock_byte(h, off, false);
            if (ret) {
                raw_lock_error_setg_errno(errp, -ret, "Failed to lock byte %d",
                                          off);
                return ret;
            }
            s->locked_shared_perm |= bit;
        } else if (unlock && (s->locked_shared_perm & bit) &&
                   !(shared_perm_lock_bits & bit)) {
            ret = raw_unlock_byte(h, off);
            if (ret) {
                error_setg_errno(errp, -ret, "Failed to unlock byte %d", off);
                return ret;
            }
            s->locked_shared_perm &= ~bit;
        }
    }
    return 0;
}

/* Check "unshared" bytes implied by @perm and ~@shared_perm in the file. */
static int raw_check_lock_bytes(BDRVRawState *s, HANDLE h, uint64_t perm,
                                uint64_t shared_perm, Error **errp)
{
    int ret;
    int i;

    PERM_FOREACH(i) {
        int off = RAW_LOCK_SHARED_BASE + i;
        uint64_t p = 1ULL << i;
        if (perm & p) {
            ret = raw_test_byte(h, off, s->locked_shared_perm & p);
            if (ret) {
                char *perm_name = bdrv_perm_names(p);

                raw_lock_error_setg_errno(errp, -ret,
                                          "Failed to get \"%s\" lock",
                                          perm_name);
                g_free(perm_name);
                return ret;
            }
        }
    }
    PERM_FOREACH(i) {
        int off = RAW_LOCK_PERM_BASE + i;
        uint64_t p = 1ULL << i;
        if (!(shared_perm & p)) {
            ret = raw_test_byte(h, off, s->locked_perm & p);
            if (ret) {
                char *perm_name = bdrv_perm_names(p);

                raw_lock_error_setg_errno(errp, -ret,
                                          "Failed to get shared \"%s\" lock",
                                          perm_name);
                g_free(perm_name);
                return ret;
            }
        }
    }
    return 0;
}

static int raw_handle_perm_lock(BlockDriverState *bs,
                                RawPermLockOp op,
                                uint64_t new_perm, uint64_t new_shared,
                                Error **errp)
{
    BDRVRawState *s = bs->opaque;
    int ret = 0;
    Error *local_err = NULL;

    if (!s->use_lock) {
        return 0;
    }

    if (bdrv_get_flags(bs) & BDRV_O_INACTIVE) {
        return 0;
    }

    switch (op) {
    case RAW_PL_PREPARE:
        if ((s->perm | new_perm) == s->perm &&
            (s->shared_perm & new_shared) == s->shared_perm) {
            return 0;
        }
        ret = raw_apply_lock_bytes(s, s->hfile, s->perm | new_perm,
                                   ~s->shared_perm | ~new_shared,
                                   false, errp);
        if (!ret) {
            ret = raw_check_lock_bytes(s, s->hfile, new_perm, new_shared,
                                       errp);
            if (!ret) {
                return 0;
            }
            error_append_hint(errp,
                              "Is another process using the image [%s]?\n",
                              bs->filename);
        }
        /* fall through to unlock bytes. */
    case RAW_PL_ABORT:
        raw_apply_lock_bytes(s, s->hfile, s->perm, ~s->shared_perm,
                             true, &local_err);
        if (local_err) {
            warn_report_err(local_err);
        }
        break;
    case RAW_PL_COMMIT:
        raw_apply_lock_bytes(s, s->hfile, new_perm, ~new_shared,
                             true, &local_err);
        if (local_err) {
            warn_report_err(local_err);
        }
        break;
    }
    return ret;
}

static int raw_check_perm(BlockDriverState *bs, uint64_t perm,
                          uint64_t shared, Error **errp)
{
    return raw_handle_perm_lock(bs, RAW_PL_PREPARE, perm, shared, errp);
}

static void raw_set_perm(BlockDriverState *bs, uint64_t perm, uint64_t shared)
{
    BDRVRawState *s = bs->opaque;

    raw_handle_perm_lock(bs, RAW_PL_COMMIT, perm, shared, NULL);
    s->perm = perm;
    s->shared_perm = shared;
}

static void raw_abort_perm_update(BlockDriverState *bs)
{
    raw_handle_perm_lock(bs, RAW_PL_ABORT, 0, 0, NULL);
}

static int raw_open(BlockDriverState *bs, QDict *options, int flags,
                    Error **errp)
{
    BDRVRawState *s = bs->opaque;
    int access_flags;
    DWORD overlapped;
    QemuOpts *opts;
    Error *local_err = NULL;
    const char *filename;
    bool use_aio;
    OnOffAuto locking;
    int ret;

    s->type = FTYPE_FILE;

    opts = qemu_opts_create(&raw_runtime_opts, NULL, 0, &error_abort);
    if (!qemu_opts_absorb_qdict(opts, options, errp)) {
        ret = -EINVAL;
        goto fail;
    }

    locking = qapi_enum_parse(&OnOffAuto_lookup,
                              qemu_opt_get(opts, "locking"),
                              ON_OFF_AUTO_AUTO, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto fail;
    }
    switch (locking) {
    case ON_OFF_AUTO_ON:
    case ON_OFF_AUTO_AUTO:
        s->use_lock = true;
        break;
    case ON_OFF_AUTO_OFF:
        s->use_lock = false;
        break;
    default:
        g_assert_not_reached();
    }

    filename = qemu_opt_get(opts, "filename");

    use_aio = get_aio_option(opts, flags, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto fail;
    }

    raw_parse_flags(flags, use_aio, &access_flags, &overlapped);

    if (filename[0] && filename[1] == ':') {
        snprintf(s->drive_path, sizeof(s->drive_path), "%c:\\", filename[0]);
    } else if (filename[0] == '\\' && filename[1] == '\\') {
        s->drive_path[0] = 0;
    } else {
        /* Relative path.  */
        char buf[MAX_PATH];
        GetCurrentDirectory(MAX_PATH, buf);
        snprintf(s->drive_path, sizeof(s->drive_path), "%c:\\", buf[0]);
    }

    s->hfile = CreateFile(filename, access_flags,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          OPEN_EXISTING, overlapped, NULL);
    if (s->hfile == INVALID_HANDLE_VALUE) {
        int err = GetLastError();

        error_setg_win32(errp, err, "Could not open '%s'", filename);
        if (err == ERROR_ACCESS_DENIED) {
            ret = -EACCES;
        } else {
            ret = -EINVAL;
        }
        goto fail;
    }

    if (use_aio) {
        s->aio = win32_aio_init();
        if (s->aio == NULL) {
            CloseHandle(s->hfile);
            error_setg(errp, "Could not initialize AIO");
            ret = -EINVAL;
            goto fail;
        }

        ret = win32_aio_attach(s->aio, s->hfile);
        if (ret < 0) {
            win32_aio_cleanup(s->aio);
            CloseHandle(s->hfile);
            error_setg_errno(errp, -ret, "Could not enable AIO");
            goto fail;
        }

        win32_aio_attach_aio_context(s->aio, bdrv_get_aio_context(bs));
    }

    /* When extending regular files, we get zeros from the OS */
    bs->supported_truncate_flags = BDRV_REQ_ZERO_WRITE;

    ret = 0;
fail:
    qemu_opts_del(opts);
    return ret;
}

static BlockAIOCB *raw_aio_preadv(BlockDriverState *bs,
                                  int64_t offset, int64_t bytes,
                                  QEMUIOVector *qiov, BdrvRequestFlags flags,
                                  BlockCompletionFunc *cb, void *opaque)
{
    BDRVRawState *s = bs->opaque;
    if (s->aio) {
        return win32_aio_submit(bs, s->aio, s->hfile, offset, bytes, qiov,
                                cb, opaque, QEMU_AIO_READ);
    } else {
        return paio_submit(bs, s->hfile, offset, qiov, bytes,
                           cb, opaque, QEMU_AIO_READ);
    }
}

static BlockAIOCB *raw_aio_pwritev(BlockDriverState *bs,
                                   int64_t offset, int64_t bytes,
                                   QEMUIOVector *qiov, BdrvRequestFlags flags,
                                   BlockCompletionFunc *cb, void *opaque)
{
    BDRVRawState *s = bs->opaque;
    if (s->aio) {
        return win32_aio_submit(bs, s->aio, s->hfile, offset, bytes, qiov,
                                cb, opaque, QEMU_AIO_WRITE);
    } else {
        return paio_submit(bs, s->hfile, offset, qiov, bytes,
                           cb, opaque, QEMU_AIO_WRITE);
    }
}

static BlockAIOCB *raw_aio_flush(BlockDriverState *bs,
                         BlockCompletionFunc *cb, void *opaque)
{
    BDRVRawState *s = bs->opaque;
    return paio_submit(bs, s->hfile, 0, NULL, 0, cb, opaque, QEMU_AIO_FLUSH);
}

static void raw_close(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;

    if (s->aio) {
        win32_aio_detach_aio_context(s->aio, bdrv_get_aio_context(bs));
        win32_aio_cleanup(s->aio);
        s->aio = NULL;
    }

    CloseHandle(s->hfile);
    if (bs->open_flags & BDRV_O_TEMPORARY) {
        unlink(bs->filename);
    }
}

static int coroutine_fn raw_co_truncate(BlockDriverState *bs, int64_t offset,
                                        bool exact, PreallocMode prealloc,
                                        BdrvRequestFlags flags, Error **errp)
{
    BDRVRawState *s = bs->opaque;
    LONG low, high;
    DWORD dwPtrLow;

    if (prealloc != PREALLOC_MODE_OFF) {
        error_setg(errp, "Unsupported preallocation mode '%s'",
                   PreallocMode_str(prealloc));
        return -ENOTSUP;
    }

    low = offset;
    high = offset >> 32;

    /*
     * An error has occurred if the return value is INVALID_SET_FILE_POINTER
     * and GetLastError doesn't return NO_ERROR.
     */
    dwPtrLow = SetFilePointer(s->hfile, low, &high, FILE_BEGIN);
    if (dwPtrLow == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
        error_setg_win32(errp, GetLastError(), "SetFilePointer error");
        return -EIO;
    }
    if (SetEndOfFile(s->hfile) == 0) {
        error_setg_win32(errp, GetLastError(), "SetEndOfFile error");
        return -EIO;
    }
    return 0;
}

static int64_t coroutine_fn raw_co_getlength(BlockDriverState *bs)
{
    BDRVRawState *s = bs->opaque;
    LARGE_INTEGER l;
    ULARGE_INTEGER available, total, total_free;
    DISK_GEOMETRY_EX dg;
    DWORD count;
    BOOL status;

    switch(s->type) {
    case FTYPE_FILE:
        l.LowPart = GetFileSize(s->hfile, (PDWORD)&l.HighPart);
        if (l.LowPart == 0xffffffffUL && GetLastError() != NO_ERROR)
            return -EIO;
        break;
    case FTYPE_CD:
        if (!GetDiskFreeSpaceEx(s->drive_path, &available, &total, &total_free))
            return -EIO;
        l.QuadPart = total.QuadPart;
        break;
    case FTYPE_HARDDISK:
        status = DeviceIoControl(s->hfile, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                                 NULL, 0, &dg, sizeof(dg), &count, NULL);
        if (status != 0) {
            l = dg.DiskSize;
        } else {
            /* no medium, or a device without geometry */
            l.QuadPart = 0;
        }
        break;
    case FTYPE_SG:
        /* as a /dev/sgN of Linux: no length */
        l.QuadPart = 0;
        break;
    default:
        return -EIO;
    }
    return l.QuadPart;
}

static int64_t coroutine_fn raw_co_get_allocated_file_size(BlockDriverState *bs)
{
    typedef DWORD (WINAPI * get_compressed_t)(const char *filename,
                                              DWORD * high);
    get_compressed_t get_compressed;
    struct _stati64 st;
    const char *filename = bs->filename;
    /* WinNT support GetCompressedFileSize to determine allocate size */
    get_compressed =
        (get_compressed_t) GetProcAddress(GetModuleHandle("kernel32"),
                                            "GetCompressedFileSizeA");
    if (get_compressed) {
        DWORD high, low;
        low = get_compressed(filename, &high);
        if (low != 0xFFFFFFFFlu || GetLastError() == NO_ERROR) {
            return (((int64_t) high) << 32) + low;
        }
    }

    if (_stati64(filename, &st) < 0) {
        return -1;
    }
    return st.st_size;
}

static int raw_co_create(BlockdevCreateOptions *options, Error **errp)
{
    BlockdevCreateOptionsFile *file_opts;
    int fd;

    assert(options->driver == BLOCKDEV_DRIVER_FILE);
    file_opts = &options->u.file;

    if (file_opts->has_preallocation) {
        error_setg(errp, "Preallocation is not supported on Windows");
        return -EINVAL;
    }
    if (file_opts->has_nocow) {
        error_setg(errp, "nocow is not supported on Windows");
        return -EINVAL;
    }

    fd = qemu_create(file_opts->filename, O_WRONLY | O_TRUNC | O_BINARY,
                     0644, errp);
    if (fd < 0) {
        return -EIO;
    }
    set_sparse(fd);
    ftruncate(fd, file_opts->size);
    qemu_close(fd);

    return 0;
}

static int coroutine_fn GRAPH_RDLOCK
raw_co_create_opts(BlockDriver *drv, const char *filename,
                   QemuOpts *opts, Error **errp)
{
    BlockdevCreateOptions options;
    int64_t total_size = 0;

    strstart(filename, "file:", &filename);

    /* Read out options */
    total_size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                          BDRV_SECTOR_SIZE);

    options = (BlockdevCreateOptions) {
        .driver     = BLOCKDEV_DRIVER_FILE,
        .u.file     = {
            .filename           = (char *) filename,
            .size               = total_size,
            .has_preallocation  = false,
            .has_nocow          = false,
        },
    };
    return raw_co_create(&options, errp);
}

static int raw_reopen_prepare(BDRVReopenState *state,
                              BlockReopenQueue *queue, Error **errp)
{
    BDRVRawState *s = state->bs->opaque;
    BDRVRawReopenState *rs;
    int access_flags;
    DWORD overlapped;
    int ret = 0;

    if (s->type != FTYPE_FILE) {
        error_setg(errp, "Can only reopen files");
        return -EINVAL;
    }

    rs = g_new0(BDRVRawReopenState, 1);

    /*
     * We do not support changing any options (only flags). By leaving
     * all options in state->options, we tell the generic reopen code
     * that we do not support changing any of them, so it will verify
     * that their values did not change.
     */

    raw_parse_flags(state->flags, s->aio != NULL, &access_flags, &overlapped);
    rs->hfile = CreateFile(state->bs->filename, access_flags,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, overlapped, NULL);

    if (rs->hfile == INVALID_HANDLE_VALUE) {
        int err = GetLastError();

        error_setg_win32(errp, err, "Could not reopen '%s'",
                         state->bs->filename);
        if (err == ERROR_ACCESS_DENIED) {
            ret = -EACCES;
        } else {
            ret = -EINVAL;
        }
        goto fail;
    }

    if (s->aio) {
        ret = win32_aio_attach(s->aio, rs->hfile);
        if (ret < 0) {
            error_setg_errno(errp, -ret, "Could not enable AIO");
            CloseHandle(rs->hfile);
            goto fail;
        }
    }

    state->opaque = rs;

    return 0;

fail:
    g_free(rs);
    state->opaque = NULL;

    return ret;
}

static void raw_reopen_commit(BDRVReopenState *state)
{
    BDRVRawState *s = state->bs->opaque;
    BDRVRawReopenState *rs = state->opaque;

    assert(rs != NULL);

    CloseHandle(s->hfile);
    s->hfile = rs->hfile;

    /* the locks went with the old handle: take them on the new one */
    if (s->use_lock && (s->locked_perm || s->locked_shared_perm)) {
        uint64_t perm = s->locked_perm, unshared = s->locked_shared_perm;
        Error *local_err = NULL;

        s->locked_perm = 0;
        s->locked_shared_perm = 0;
        if (raw_apply_lock_bytes(s, s->hfile, perm, unshared, false,
                                 &local_err) < 0) {
            warn_report_err(local_err);
        }
    }

    g_free(rs);
    state->opaque = NULL;
}

static void raw_reopen_abort(BDRVReopenState *state)
{
    BDRVRawReopenState *rs = state->opaque;

    if (!rs) {
        return;
    }

    if (rs->hfile != INVALID_HANDLE_VALUE) {
        CloseHandle(rs->hfile);
    }

    g_free(rs);
    state->opaque = NULL;
}

static QemuOptsList raw_create_opts = {
    .name = "raw-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(raw_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        { /* end of list */ }
    }
};

BlockDriver bdrv_file = {
    .format_name            = "file",
    .protocol_name          = "file",
    .instance_size          = sizeof(BDRVRawState),
    .bdrv_needs_filename    = true,
    .bdrv_parse_filename    = raw_parse_filename,
    .bdrv_open              = raw_open,
    .bdrv_refresh_limits    = raw_probe_alignment,
    .bdrv_close             = raw_close,
    .bdrv_co_create_opts    = raw_co_create_opts,
    .bdrv_has_zero_init     = bdrv_has_zero_init_1,

    .bdrv_reopen_prepare = raw_reopen_prepare,
    .bdrv_reopen_commit  = raw_reopen_commit,
    .bdrv_reopen_abort   = raw_reopen_abort,

    .bdrv_check_perm = raw_check_perm,
    .bdrv_set_perm   = raw_set_perm,
    .bdrv_abort_perm_update = raw_abort_perm_update,

    .bdrv_aio_preadv    = raw_aio_preadv,
    .bdrv_aio_pwritev   = raw_aio_pwritev,
    .bdrv_aio_flush     = raw_aio_flush,

    .bdrv_co_truncate   = raw_co_truncate,
    .bdrv_co_getlength  = raw_co_getlength,
    .bdrv_co_get_allocated_file_size
                        = raw_co_get_allocated_file_size,

    .create_opts        = &raw_create_opts,
};

/***********************************************/
/* host device */

static int find_cdrom(char *cdrom_name, int cdrom_name_size)
{
    char drives[256], *pdrv = drives;
    UINT type;

    memset(drives, 0, sizeof(drives));
    GetLogicalDriveStrings(sizeof(drives), drives);
    while(pdrv[0] != '\0') {
        type = GetDriveType(pdrv);
        switch(type) {
        case DRIVE_CDROM:
            snprintf(cdrom_name, cdrom_name_size, "\\\\.\\%c:", pdrv[0]);
            return 0;
            break;
        }
        pdrv += lstrlen(pdrv) + 1;
    }
    return -1;
}

static int find_device_type(BlockDriverState *bs, const char *filename)
{
    BDRVRawState *s = bs->opaque;
    UINT type;
    const char *p;

    if (strstart(filename, "\\\\.\\", &p) ||
        strstart(filename, "//./", &p)) {
        if (stristart(p, "PhysicalDrive", NULL) ||
            stristart(p, "CdRom", NULL)) {
            return FTYPE_HARDDISK;
        }
        if (stristart(p, "Tape", NULL) || stristart(p, "Changer", NULL) ||
            stristart(p, "Scsi", NULL)) {
            return FTYPE_SG;
        }
        snprintf(s->drive_path, sizeof(s->drive_path), "%c:\\", p[0]);
        type = GetDriveType(s->drive_path);
        switch (type) {
        case DRIVE_REMOVABLE:
        case DRIVE_FIXED:
            return FTYPE_HARDDISK;
        case DRIVE_CDROM:
            return FTYPE_CD;
        default:
            return FTYPE_FILE;
        }
    } else {
        return FTYPE_FILE;
    }
}

static int hdev_probe_device(const char *filename)
{
    if (strstart(filename, "/dev/cdrom", NULL))
        return 100;
    if (is_windows_drive(filename))
        return 100;
    return 0;
}

static void hdev_parse_filename(const char *filename, QDict *options,
                                Error **errp)
{
    bdrv_parse_filename_strip_prefix(filename, "host_device:", options);
}

static void hdev_refresh_limits(BlockDriverState *bs, Error **errp)
{
    BDRVRawState *s = bs->opaque;
    size_t max_transfer;
    int max_iov;

    /* XXX Does Windows support AIO on less than 512-byte alignment? */
    bs->bl.request_alignment = 512;
    bs->bl.has_variable_length = true;

    /* what the adapter takes in one command, for SG_IO */
    win32_sg_limits(s->hfile, &max_transfer, &max_iov);
    if (max_transfer) {
        bs->bl.max_hw_transfer = max_transfer;
    }
    if (max_iov) {
        bs->bl.max_hw_iov = max_iov;
    }
}

typedef struct HdevIoctlData {
    HANDLE hfile;
    unsigned long req;
    void *buf;
} HdevIoctlData;

static int hdev_ioctl_worker(void *opaque)
{
    HdevIoctlData *d = opaque;

    return win32_sg_ioctl(d->hfile, d->req, d->buf);
}

static int coroutine_fn
hdev_co_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
    BDRVRawState *s = bs->opaque;
    HdevIoctlData d = { s->hfile, req, buf };

    if (req == SG_IO) {
        struct sg_io_hdr *io_hdr = buf;

        if (s->pr_mgr) {
            if (io_hdr->cmdp[0] == PERSISTENT_RESERVE_OUT ||
                io_hdr->cmdp[0] == PERSISTENT_RESERVE_IN ||
                io_hdr->cmdp[0] == PR_HELPER_CLEANUP) {
                /* the handle goes to qemu-pr-helper as a handle token */
                return pr_manager_execute(s->pr_mgr,
                                          qemu_get_current_aio_context(),
                                          w32fd_handle_token(s->hfile),
                                          io_hdr);
            }
        } else if (io_hdr->cmdp[0] == PR_HELPER_CLEANUP) {
            /* This is a nop without pr-manager */
            io_hdr->status = GOOD;
            return 0;
        }
    }
    return thread_pool_submit_co(hdev_ioctl_worker, &d);
}

static int hdev_open(BlockDriverState *bs, QDict *options, int flags,
                     Error **errp)
{
    BDRVRawState *s = bs->opaque;
    int access_flags, create_flags;
    int ret = 0;
    DWORD overlapped;
    char device_name[64];

    Error *local_err = NULL;
    const char *filename;
    bool use_aio;

    QemuOpts *opts = qemu_opts_create(&raw_runtime_opts, NULL, 0,
                                      &error_abort);
    if (!qemu_opts_absorb_qdict(opts, options, errp)) {
        ret = -EINVAL;
        goto done;
    }

    filename = qemu_opt_get(opts, "filename");

    use_aio = get_aio_option(opts, flags, &local_err);
    if (!local_err && use_aio) {
        error_setg(&local_err, "AIO is not supported on Windows host devices");
    }
    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto done;
    }

    if (strstart(filename, "/dev/cdrom", NULL)) {
        if (find_cdrom(device_name, sizeof(device_name)) < 0) {
            error_setg(errp, "Could not open CD-ROM drive");
            ret = -ENOENT;
            goto done;
        }
        filename = device_name;
    } else {
        /* transform drive letters into device name */
        if (((filename[0] >= 'a' && filename[0] <= 'z') ||
             (filename[0] >= 'A' && filename[0] <= 'Z')) &&
            filename[1] == ':' && filename[2] == '\0') {
            snprintf(device_name, sizeof(device_name), "\\\\.\\%c:", filename[0]);
            filename = device_name;
        }
    }
    s->type = find_device_type(bs, filename);

    raw_parse_flags(flags, use_aio, &access_flags, &overlapped);

    create_flags = OPEN_EXISTING;

    s->hfile = CreateFile(filename, access_flags,
                          FILE_SHARE_READ, NULL,
                          create_flags, overlapped, NULL);
    if (s->hfile == INVALID_HANDLE_VALUE) {
        int err = GetLastError();

        if (err == ERROR_ACCESS_DENIED) {
            ret = -EACCES;
        } else {
            ret = -EINVAL;
        }
        error_setg_win32(errp, err, "Could not open device");
        goto done;
    }

    /* as /dev/sgN: a SCSI device that is not a disk takes only SG_IO */
    bs->sg = s->type == FTYPE_SG && win32_sg_probe(s->hfile);

    {
        const char *pr = qemu_opt_get(opts, "pr-manager");

        if (pr) {
            s->pr_mgr = pr_manager_lookup(pr, errp);
            if (!s->pr_mgr) {
                CloseHandle(s->hfile);
                ret = -EINVAL;
                goto done;
            }
        }
    }

done:
    qemu_opts_del(opts);
    return ret;
}

static BlockDriver bdrv_host_device = {
    .format_name            = "host_device",
    .protocol_name          = "host_device",
    .instance_size          = sizeof(BDRVRawState),
    .bdrv_needs_filename    = true,
    .bdrv_parse_filename    = hdev_parse_filename,
    .bdrv_probe_device      = hdev_probe_device,
    .bdrv_open              = hdev_open,
    .bdrv_close             = raw_close,
    .bdrv_refresh_limits    = hdev_refresh_limits,
    .bdrv_co_ioctl          = hdev_co_ioctl,

    .bdrv_aio_preadv    = raw_aio_preadv,
    .bdrv_aio_pwritev   = raw_aio_pwritev,
    .bdrv_aio_flush     = raw_aio_flush,

    .bdrv_detach_aio_context = raw_detach_aio_context,
    .bdrv_attach_aio_context = raw_attach_aio_context,

    .bdrv_co_getlength                = raw_co_getlength,
    .bdrv_co_get_allocated_file_size  = raw_co_get_allocated_file_size,
};

static void bdrv_file_init(void)
{
    bdrv_register(&bdrv_file);
    bdrv_register(&bdrv_host_device);
}

block_init(bdrv_file_init);
