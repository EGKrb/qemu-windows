/*
 * The SG_IO interface of Linux on Windows
 *
 * The SCSI generic interface of Linux (<scsi/sg.h>: the sg_io_hdr of
 * version 3 and the ioctls QEMU uses), done with the SCSI pass-through of
 * Windows (IOCTL_SCSI_PASS_THROUGH_DIRECT) on the handle of a storage
 * device: \\.\PhysicalDriveN, \\.\CdRomN, \\.\TapeN, \\.\ChangerN...
 *
 * Windows has no separate generic node as /dev/sgN: every device that
 * takes pass-through answers SG_GET_SCSI_ID.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef SCSI_SG_WIN32_H
#define SCSI_SG_WIN32_H

#include <windows.h>
#include <stddef.h>

typedef struct sg_iovec {
    void *iov_base;
    size_t iov_len;
} sg_iovec_t;

typedef struct sg_io_hdr {
    int interface_id;           /* 'S' */
    int dxfer_direction;        /* SG_DXFER_* */
    unsigned char cmd_len;
    unsigned char mx_sb_len;
    unsigned short iovec_count; /* 0: dxferp is the buffer */
    unsigned int dxfer_len;
    void *dxferp;               /* buffer, or array of sg_iovec */
    unsigned char *cmdp;
    unsigned char *sbp;
    unsigned int timeout;       /* milliseconds */
    unsigned int flags;
    int pack_id;
    void *usr_ptr;
    unsigned char status;
    unsigned char masked_status;
    unsigned char msg_status;
    unsigned char sb_len_wr;
    unsigned short host_status;
    unsigned short driver_status;
    int resid;
    unsigned int duration;
    unsigned int info;
} sg_io_hdr_t;

typedef struct sg_scsi_id {
    int host_no;
    int channel;
    int scsi_id;
    int lun;
    int scsi_type;
    short h_cmd_per_lun;
    short d_queue_depth;
    int unused[2];
} sg_scsi_id_t;

#define SG_DXFER_NONE           (-1)
#define SG_DXFER_TO_DEV         (-2)
#define SG_DXFER_FROM_DEV       (-3)
#define SG_DXFER_TO_FROM_DEV    (-4)

#define SG_FLAG_DIRECT_IO       1
#define SG_FLAG_LUN_INHIBIT     2

#define SG_INFO_OK_MASK         0x1
#define SG_INFO_OK              0x0
#define SG_INFO_CHECK           0x1

/* the ioctl numbers of Linux */
#define SG_SET_TIMEOUT          0x2201
#define SG_GET_TIMEOUT          0x2202
#define SG_GET_RESERVED_SIZE    0x2272
#define SG_SET_RESERVED_SIZE    0x2275
#define SG_GET_SCSI_ID          0x2276
#define SG_GET_SG_TABLESIZE     0x227F
#define SG_GET_VERSION_NUM      0x2282
#define SG_IO                   0x2285
#define SG_SCSI_RESET           0x2284

#define SG_WIN32_VERSION        30527

/* driver_status of Linux */
#define DRIVER_OK               0x00

/*
 * An ioctl of the list above on @h: 0, or a negative errno (-ENOTTY for
 * one Windows does not take).  SG_IO blocks: call it from a worker thread.
 */
int win32_sg_ioctl(HANDLE h, unsigned long req, void *buf);

/* The limits of the adapter of @h (0 if unknown) */
void win32_sg_limits(HANDLE h, size_t *max_transfer, int *max_iov);

/* Whether @h is a SCSI device that takes pass-through */
int win32_sg_probe(HANDLE h);

#endif
