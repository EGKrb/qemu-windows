/*
 * The SG_IO interface of Linux on Windows: see include/scsi/sg-win32.h
 *
 * A command goes through IOCTL_SCSI_PASS_THROUGH_DIRECT with a bounce
 * buffer aligned for the adapter (the data of SG_IO may be an iovec);
 * the status, sense and residual come back as Linux reports them.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/memalign.h"
#include "scsi/sg-win32.h"
#include <winioctl.h>
#include <ntddscsi.h>
#include <ntddstor.h>

#define SENSE_MAX 64

/* host_status of Linux (SCSI_HOST_* of include/scsi/utils.h) */
#define HOST_TIME_OUT   0x03
#define HOST_ERROR      0x07
#define DRIVER_TIMEOUT  0x06
#define DRIVER_SENSE    0x08

typedef struct {
    SCSI_PASS_THROUGH_DIRECT sptd;
    ULONG filler;
    UCHAR sense[SENSE_MAX];
} SPTDWithSense;

static int errno_of(DWORD err)
{
    switch (err) {
    case ERROR_ACCESS_DENIED:
        return EACCES;
    case ERROR_INVALID_FUNCTION:
    case ERROR_NOT_SUPPORTED:
        return ENOTTY;
    case ERROR_INVALID_PARAMETER:
    case ERROR_INVALID_USER_BUFFER:
        return EINVAL;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_NO_SYSTEM_RESOURCES:
        return ENOMEM;
    case ERROR_NOT_READY:
    case ERROR_NO_MEDIA_IN_DRIVE:
        return ENOMEDIUM;
    case ERROR_DEVICE_NOT_CONNECTED:
    case ERROR_DEV_NOT_EXIST:
        return ENODEV;
    case ERROR_BUSY:
        return EBUSY;
    default:
        return EIO;
    }
}

/* DeviceIoControl that also works on a handle opened for overlapped I/O */
static BOOL ioctl_wait(HANDLE h, DWORD code, void *in, DWORD inlen,
                       void *out, DWORD outlen, DWORD *ret)
{
    OVERLAPPED ov = { 0 };
    BOOL ok;

    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) {
        return FALSE;
    }
    ok = DeviceIoControl(h, code, in, inlen, out, outlen, ret, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        ok = GetOverlappedResult(h, &ov, ret, TRUE);
    }
    CloseHandle(ov.hEvent);
    return ok;
}

void win32_sg_limits(HANDLE h, size_t *max_transfer, int *max_iov)
{
    STORAGE_PROPERTY_QUERY q = { 0 };
    STORAGE_ADAPTER_DESCRIPTOR d = { 0 };
    DWORD ret;

    *max_transfer = 0;
    *max_iov = 0;
    q.PropertyId = StorageAdapterProperty;
    q.QueryType = PropertyStandardQuery;
    if (ioctl_wait(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q),
                   &d, sizeof(d), &ret) &&
        ret >= offsetof(STORAGE_ADAPTER_DESCRIPTOR, AlignmentMask)) {
        *max_transfer = d.MaximumTransferLength;
        /* one page is lost when the buffer does not start a page */
        if (d.MaximumPhysicalPages > 1) {
            *max_iov = MIN(d.MaximumPhysicalPages - 1, 1024);
        }
    }
}

static int sg_get_scsi_id(HANDLE h, sg_scsi_id_t *id)
{
    SCSI_ADDRESS a = { 0 };
    DWORD ret;
    unsigned char cdb[6] = { 0x12, 0, 0, 0, 36, 0 };   /* INQUIRY */
    unsigned char inq[36] = { 0 };
    sg_io_hdr_t hdr = { 0 };
    int r;

    a.Length = sizeof(a);
    if (!ioctl_wait(h, IOCTL_SCSI_GET_ADDRESS, NULL, 0, &a, sizeof(a),
                    &ret)) {
        return -errno_of(GetLastError());
    }
    memset(id, 0, sizeof(*id));
    id->host_no = a.PortNumber;
    id->channel = a.PathId;
    id->scsi_id = a.TargetId;
    id->lun = a.Lun;
    id->h_cmd_per_lun = 1;
    id->d_queue_depth = 1;

    hdr.interface_id = 'S';
    hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    hdr.cmd_len = sizeof(cdb);
    hdr.cmdp = cdb;
    hdr.dxferp = inq;
    hdr.dxfer_len = sizeof(inq);
    hdr.timeout = 10000;
    r = win32_sg_ioctl(h, SG_IO, &hdr);
    if (r < 0) {
        return r;
    }
    id->scsi_type = inq[0] & 0x1f;
    return 0;
}

int win32_sg_probe(HANDLE h)
{
    SCSI_ADDRESS a = { 0 };
    DWORD ret;

    a.Length = sizeof(a);
    return ioctl_wait(h, IOCTL_SCSI_GET_ADDRESS, NULL, 0, &a, sizeof(a),
                      &ret);
}

static void copy_data(sg_io_hdr_t *hdr, uint8_t *buf, size_t len, bool in)
{
    if (hdr->iovec_count) {
        sg_iovec_t *iov = hdr->dxferp;
        size_t done = 0;
        int i;

        for (i = 0; i < hdr->iovec_count && done < len; i++) {
            size_t n = MIN(iov[i].iov_len, len - done);

            if (in) {
                memcpy(iov[i].iov_base, buf + done, n);
            } else {
                memcpy(buf + done, iov[i].iov_base, n);
            }
            done += n;
        }
    } else if (in) {
        memcpy(hdr->dxferp, buf, len);
    } else {
        memcpy(buf, hdr->dxferp, len);
    }
}

/* PERSISTENT_RESERVE_COMMAND of ntddstor.h for PR IN (MSVC layout) */
typedef struct {
    ULONG Version;
    ULONG Size;
    UCHAR ServiceAction;    /* 5 bits */
    UCHAR Reserved;
    USHORT AllocationLength;
} PRInCommand;

/*
 * PERSISTENT RESERVE IN on a handle opened read-only: the pass-through of
 * Windows needs write access, IOCTL_STORAGE_PERSISTENT_RESERVE_IN does not
 */
static int sg_pr_in_readonly(HANDLE h, sg_io_hdr_t *hdr)
{
    PRInCommand cmd = { 0 };
    size_t len = MIN(hdr->dxfer_len, (size_t)(hdr->cmdp[7] << 8 | hdr->cmdp[8]));
    g_autofree uint8_t *buf = g_malloc0(MAX(len, 8));
    DWORD ret = 0;

    cmd.Version = sizeof(cmd);
    cmd.Size = sizeof(cmd);
    cmd.ServiceAction = hdr->cmdp[1] & 0x1f;
    cmd.AllocationLength = len;
    if (!ioctl_wait(h, IOCTL_STORAGE_PERSISTENT_RESERVE_IN, &cmd, sizeof(cmd),
                    buf, len, &ret)) {
        return -errno_of(GetLastError());
    }
    memset(&hdr->status, 0, offsetof(sg_io_hdr_t, info) -
           offsetof(sg_io_hdr_t, status) + sizeof(hdr->info));
    if (hdr->iovec_count) {
        copy_data(hdr, buf, MIN(ret, len), true);
    } else {
        memcpy(hdr->dxferp, buf, MIN(ret, len));
    }
    hdr->resid = hdr->dxfer_len - MIN(ret, len);
    return 0;
}

/* QEMU_SG_DEBUG=1: every command and what Windows answered, on stderr */
static bool sg_debug(void)
{
    static int on = -1;

    if (on < 0) {
        on = getenv("QEMU_SG_DEBUG") != NULL;
    }
    return on;
}

static int sg_io(HANDLE h, sg_io_hdr_t *hdr)
{
    SPTDWithSense s = { 0 };
    uint8_t *buf = NULL;
    size_t len = hdr->dxfer_len;
    DWORD ret, err = 0;
    ULONGLONG start;
    unsigned int sense_len;
    BOOL ok;

    if (hdr->interface_id != 'S') {
        return -ENOSYS;
    }
    if (hdr->cmd_len == 0 || hdr->cmd_len > 16) {
        return -EINVAL;
    }
    if (hdr->dxfer_direction == SG_DXFER_NONE) {
        len = 0;
    }

    if (len) {
        /* the alignment of any adapter: a page */
        buf = qemu_try_memalign(qemu_real_host_page_size(), len);
        if (!buf) {
            return -ENOMEM;
        }
        if (hdr->dxfer_direction == SG_DXFER_TO_DEV ||
            hdr->dxfer_direction == SG_DXFER_TO_FROM_DEV) {
            copy_data(hdr, buf, len, false);
        } else {
            memset(buf, 0, len);
        }
    }

    s.sptd.Length = sizeof(s.sptd);
    s.sptd.CdbLength = hdr->cmd_len;
    s.sptd.SenseInfoLength = SENSE_MAX;
    s.sptd.SenseInfoOffset = offsetof(SPTDWithSense, sense);
    s.sptd.DataTransferLength = len;
    s.sptd.DataBuffer = buf;
    switch (hdr->dxfer_direction) {
    case SG_DXFER_TO_DEV:
        s.sptd.DataIn = SCSI_IOCTL_DATA_OUT;
        break;
    case SG_DXFER_FROM_DEV:
    case SG_DXFER_TO_FROM_DEV:
        s.sptd.DataIn = SCSI_IOCTL_DATA_IN;
        break;
    default:
        s.sptd.DataIn = SCSI_IOCTL_DATA_UNSPECIFIED;
        break;
    }
    /* seconds; 0 (no timeout on Linux) is the longest Windows takes */
    if (hdr->timeout == 0 || hdr->timeout / 1000 >= 108000) {
        s.sptd.TimeOutValue = 108000;
    } else {
        s.sptd.TimeOutValue = MAX(1, (hdr->timeout + 999) / 1000);
    }
    memcpy(s.sptd.Cdb, hdr->cmdp, hdr->cmd_len);

    start = GetTickCount64();
    ok = ioctl_wait(h, IOCTL_SCSI_PASS_THROUGH_DIRECT, &s, sizeof(s),
                    &s, sizeof(s), &ret);
    if (!ok) {
        err = GetLastError();
    }
    hdr->duration = (unsigned int)(GetTickCount64() - start);
    if (sg_debug()) {
        fprintf(stderr, "sg: cdb %02x %02x %02x len %u dir %d: ok %d error %lu "
                "scsi %02x sense %02x/%02x/%02x transferred %lu, %u ms\n",
                hdr->cmdp[0], hdr->cmdp[1], hdr->cmdp[2], hdr->dxfer_len,
                hdr->dxfer_direction, ok, (unsigned long)err,
                s.sptd.ScsiStatus, s.sense[2] & 0xf, s.sense[12],
                s.sense[13], (unsigned long)s.sptd.DataTransferLength,
                hdr->duration);
    }

    hdr->status = 0;
    hdr->masked_status = 0;
    hdr->msg_status = 0;
    hdr->sb_len_wr = 0;
    hdr->host_status = 0;
    hdr->driver_status = 0;
    hdr->resid = 0;
    hdr->info = SG_INFO_OK;

    if (!ok && err == ERROR_ACCESS_DENIED && hdr->cmdp[0] == 0x5e &&
        hdr->dxfer_direction == SG_DXFER_FROM_DEV) {
        qemu_vfree(buf);
        return sg_pr_in_readonly(h, hdr);
    }
    if (!ok) {
        /* errors of the transport: Linux reports them in host_status */
        if (err == ERROR_SEM_TIMEOUT || err == WAIT_TIMEOUT) {
            hdr->host_status = HOST_TIME_OUT;
            hdr->driver_status = DRIVER_TIMEOUT;
        } else if (err == ERROR_IO_DEVICE || err == ERROR_CRC ||
                   err == ERROR_GEN_FAILURE) {
            hdr->host_status = HOST_ERROR;
        } else {
            qemu_vfree(buf);
            return -errno_of(err);
        }
        hdr->resid = hdr->dxfer_len;
        hdr->info = SG_INFO_CHECK;
        qemu_vfree(buf);
        return 0;
    }

    hdr->status = s.sptd.ScsiStatus;
    hdr->masked_status = (s.sptd.ScsiStatus >> 1) & 0x7f;
    if (s.sptd.DataTransferLength <= len) {
        hdr->resid = len - s.sptd.DataTransferLength;
        if (len && s.sptd.DataIn == SCSI_IOCTL_DATA_IN) {
            copy_data(hdr, buf, s.sptd.DataTransferLength, true);
        }
    }
    if (hdr->dxfer_direction == SG_DXFER_NONE) {
        hdr->resid = 0;
    }
    if (s.sptd.ScsiStatus == 0x02 /* CHECK CONDITION */ &&
        (s.sense[0] & 0x70) == 0x70) {
        /* fixed and descriptor formats: the additional length at byte 7 */
        sense_len = MIN(8u + s.sense[7], SENSE_MAX);
        sense_len = MIN(sense_len, hdr->mx_sb_len);
        if (sense_len && hdr->sbp) {
            memcpy(hdr->sbp, s.sense, sense_len);
            hdr->sb_len_wr = sense_len;
            hdr->driver_status = DRIVER_SENSE;
        }
    }
    if (hdr->status || hdr->host_status || hdr->driver_status) {
        hdr->info = SG_INFO_CHECK;
    }
    qemu_vfree(buf);
    return 0;
}

int win32_sg_ioctl(HANDLE h, unsigned long req, void *buf)
{
    size_t max_transfer;
    int max_iov;

    switch (req) {
    case SG_IO:
        return sg_io(h, buf);
    case SG_GET_VERSION_NUM:
        if (!win32_sg_probe(h)) {
            return -ENOTTY;
        }
        *(int *)buf = SG_WIN32_VERSION;
        return 0;
    case SG_GET_SCSI_ID:
        return sg_get_scsi_id(h, buf);
    case SG_GET_RESERVED_SIZE:
        win32_sg_limits(h, &max_transfer, &max_iov);
        *(int *)buf = max_transfer ? MIN(max_transfer, INT_MAX) : 65536;
        return 0;
    case SG_GET_SG_TABLESIZE:
        win32_sg_limits(h, &max_transfer, &max_iov);
        *(int *)buf = max_iov ? max_iov : 16;
        return 0;
    case SG_SET_RESERVED_SIZE:
    case SG_SET_TIMEOUT:
        return 0;
    case SG_GET_TIMEOUT:
        return 60 * 100;    /* in jiffies (USER_HZ), as Linux returns it */
    default:
        return -ENOTTY;
    }
}
