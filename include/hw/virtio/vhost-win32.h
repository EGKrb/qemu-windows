/*
 * vhost ioctls on Windows: the requests of linux/vhost.h, encoded as on
 * Linux, go to the vhost drivers of Windows (\\.\vhost-net) as
 * DeviceIoControl() codes: VHOST_WIN32_CODE().  Generated from
 * linux-headers/linux/vhost.h.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef HW_VIRTIO_VHOST_WIN32_H
#define HW_VIRTIO_VHOST_WIN32_H

#include "standard-headers/linux/vhost_types.h"

/* the encoding of linux/ioctl.h (asm-generic) */
#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8
#define _IOC_SIZEBITS   14
#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT + _IOC_SIZEBITS)
#define _IOC_NONE       0U
#define _IOC_WRITE      1U
#define _IOC_READ       2U
#define _IOC(dir, type, nr, size) \
    (((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | \
     ((nr) << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT))
#define _IO(type, nr)            _IOC(_IOC_NONE, (type), (nr), 0)
#define _IOR(type, nr, t)        _IOC(_IOC_READ, (type), (nr), sizeof(t))
#define _IOW(type, nr, t)        _IOC(_IOC_WRITE, (type), (nr), sizeof(t))
#define _IOWR(type, nr, t)       _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), \
                                      sizeof(t))
#define _IOC_DIR(nr)    (((nr) >> _IOC_DIRSHIFT) & 3)
#define _IOC_NR(nr)     (((nr) >> _IOC_NRSHIFT) & 0xff)
#define _IOC_SIZE(nr)   (((nr) >> _IOC_SIZESHIFT) & 0x3fff)

/*
 * DeviceIoControl() code of a request: METHOD_BUFFERED, the direction and
 * number of the request in the function (GET and SET of a number differ)
 */
#define VHOST_WIN32_DEVICE_TYPE 0x8b56
#define VHOST_WIN32_CODE(req) \
    ((VHOST_WIN32_DEVICE_TYPE << 16) | \
     ((0x800 | (_IOC_DIR(req) << 8) | _IOC_NR(req)) << 2))
#define VHOST_WIN32_DEVICE_NAME "\\\\.\\vhost-net"

#define VHOST_FILE_UNBIND -1
#define VHOST_VIRTIO 0xAF
#define VHOST_GET_FEATURES _IOR(VHOST_VIRTIO, 0x00, uint64_t)
#define VHOST_SET_FEATURES _IOW(VHOST_VIRTIO, 0x00, uint64_t)
#define VHOST_SET_OWNER _IO(VHOST_VIRTIO, 0x01)
#define VHOST_RESET_OWNER _IO(VHOST_VIRTIO, 0x02)
#define VHOST_SET_MEM_TABLE _IOW(VHOST_VIRTIO, 0x03, struct vhost_memory)
#define VHOST_SET_LOG_BASE _IOW(VHOST_VIRTIO, 0x04, uint64_t)
#define VHOST_SET_LOG_FD _IOW(VHOST_VIRTIO, 0x07, int)
#define VHOST_NEW_WORKER _IOR(VHOST_VIRTIO, 0x8, struct vhost_worker_state)
#define VHOST_FREE_WORKER _IOW(VHOST_VIRTIO, 0x9, struct vhost_worker_state)
#define VHOST_SET_VRING_NUM _IOW(VHOST_VIRTIO, 0x10, struct vhost_vring_state)
#define VHOST_SET_VRING_ADDR _IOW(VHOST_VIRTIO, 0x11, struct vhost_vring_addr)
#define VHOST_SET_VRING_BASE _IOW(VHOST_VIRTIO, 0x12, struct vhost_vring_state)
#define VHOST_GET_VRING_BASE _IOWR(VHOST_VIRTIO, 0x12, struct vhost_vring_state)
#define VHOST_VRING_LITTLE_ENDIAN 0
#define VHOST_VRING_BIG_ENDIAN 1
#define VHOST_SET_VRING_ENDIAN _IOW(VHOST_VIRTIO, 0x13, struct vhost_vring_state)
#define VHOST_GET_VRING_ENDIAN _IOW(VHOST_VIRTIO, 0x14, struct vhost_vring_state)
#define VHOST_ATTACH_VRING_WORKER _IOW(VHOST_VIRTIO, 0x15, struct vhost_vring_worker)
#define VHOST_GET_VRING_WORKER _IOWR(VHOST_VIRTIO, 0x16, struct vhost_vring_worker)
#define VHOST_SET_VRING_KICK _IOW(VHOST_VIRTIO, 0x20, struct vhost_vring_file)
#define VHOST_SET_VRING_CALL _IOW(VHOST_VIRTIO, 0x21, struct vhost_vring_file)
#define VHOST_SET_VRING_ERR _IOW(VHOST_VIRTIO, 0x22, struct vhost_vring_file)
#define VHOST_SET_VRING_BUSYLOOP_TIMEOUT _IOW(VHOST_VIRTIO, 0x23, struct vhost_vring_state)
#define VHOST_GET_VRING_BUSYLOOP_TIMEOUT _IOW(VHOST_VIRTIO, 0x24, struct vhost_vring_state)
#define VHOST_SET_BACKEND_FEATURES _IOW(VHOST_VIRTIO, 0x25, uint64_t)
#define VHOST_GET_BACKEND_FEATURES _IOR(VHOST_VIRTIO, 0x26, uint64_t)
#define VHOST_NET_SET_BACKEND _IOW(VHOST_VIRTIO, 0x30, struct vhost_vring_file)
#define VHOST_SCSI_SET_ENDPOINT _IOW(VHOST_VIRTIO, 0x40, struct vhost_scsi_target)
#define VHOST_SCSI_CLEAR_ENDPOINT _IOW(VHOST_VIRTIO, 0x41, struct vhost_scsi_target)
#define VHOST_SCSI_GET_ABI_VERSION _IOW(VHOST_VIRTIO, 0x42, int)
#define VHOST_SCSI_SET_EVENTS_MISSED _IOW(VHOST_VIRTIO, 0x43, uint32_t)
#define VHOST_SCSI_GET_EVENTS_MISSED _IOW(VHOST_VIRTIO, 0x44, uint32_t)
#define VHOST_VSOCK_SET_GUEST_CID _IOW(VHOST_VIRTIO, 0x60, uint64_t)
#define VHOST_VSOCK_SET_RUNNING _IOW(VHOST_VIRTIO, 0x61, int)
#define VHOST_GET_FEATURES_ARRAY _IOR(VHOST_VIRTIO, 0x83, struct vhost_features_array)
#define VHOST_SET_FEATURES_ARRAY _IOW(VHOST_VIRTIO, 0x83, struct vhost_features_array)
#define VHOST_SET_FORK_FROM_OWNER _IOW(VHOST_VIRTIO, 0x84, uint8_t)
#define VHOST_GET_FORK_FROM_OWNER _IOR(VHOST_VIRTIO, 0x85, uint8_t)

#endif
