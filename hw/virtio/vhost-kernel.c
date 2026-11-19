/*
 * vhost-kernel
 *
 * Copyright (c) 2013 Virtual Open Systems Sarl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-backend.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "standard-headers/linux/vhost_types.h"

#include "hw/virtio/vhost-vdpa.h"
#ifdef CONFIG_VHOST_KERNEL
#ifdef _WIN32
#include "hw/virtio/vhost-win32.h"
#include "qemu/win32-fdpass.h"
#else
#include <linux/vhost.h>
#include <sys/ioctl.h>
#endif

struct vhost_features {
    uint64_t count;
    uint64_t features[VIRTIO_FEATURES_NU64S];
};

#ifdef _WIN32
/* a descriptor or handle token of QEMU -> the handle, for the driver */
static int vhost_win32_handle(int fd)
{
    if (fd == -1) {
        return -1;
    }
    if (w32fd_is_token(fd)) {
        return (int)(intptr_t)w32fd_token_handle(fd);
    }
    return (int)_get_osfhandle(fd);
}

/*
 * Windows: the request goes to the driver (\\.\vhost-net) as a
 * DeviceIoControl() with the same argument; descriptors in it become
 * handles of this process, which the driver references
 */
static int vhost_kernel_call(struct vhost_dev *dev, unsigned long int request,
                             void *arg)
{
    int fd = (uintptr_t) dev->opaque;
    /* the device: a handle token (net/tap-win32.c), or a descriptor */
    HANDLE h = w32fd_is_token(fd) ? w32fd_token_handle(fd)
                                  : (HANDLE)_get_osfhandle(fd);
    DWORD size = _IOC_SIZE(request), got = 0;
    struct vhost_vring_file file;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

    switch (request) {
    case VHOST_SET_MEM_TABLE:
        size = sizeof(struct vhost_memory) +
               ((struct vhost_memory *)arg)->nregions *
               sizeof(struct vhost_memory_region);
        break;
    case VHOST_GET_FEATURES_ARRAY:
    case VHOST_SET_FEATURES_ARRAY:
        size = sizeof(uint64_t) + ((struct vhost_features_array *)arg)->count *
               sizeof(uint64_t);
        break;
    case VHOST_SET_VRING_KICK:
    case VHOST_SET_VRING_CALL:
    case VHOST_SET_VRING_ERR:
    case VHOST_NET_SET_BACKEND:
        file = *(struct vhost_vring_file *)arg;
        file.fd = vhost_win32_handle(file.fd);
        arg = &file;
        break;
    case VHOST_SET_LOG_FD:
        /* the log is the memory given by VHOST_SET_LOG_BASE */
        return 0;
    }
    if (!DeviceIoControl(h, VHOST_WIN32_CODE(request), arg, arg ? size : 0,
                         arg, arg ? size : 0, &got, NULL)) {
        switch (GetLastError()) {
        case ERROR_INVALID_FUNCTION:
        case ERROR_NOT_SUPPORTED:
            return -ENOTTY;
        case ERROR_INVALID_PARAMETER:
            return -EINVAL;
        case ERROR_INVALID_HANDLE:
            return -EBADF;
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_NO_SYSTEM_RESOURCES:
            return -ENOMEM;
        case ERROR_BUSY:
            return -EBUSY;
        case ERROR_ACCESS_DENIED:
            return -EPERM;
        default:
            return -EIO;
        }
    }
    return 0;
}
#else
static int vhost_kernel_call(struct vhost_dev *dev, unsigned long int request,
                             void *arg)
{
    int fd = (uintptr_t) dev->opaque;
    int ret;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

    ret = ioctl(fd, request, arg);
    return ret < 0 ? -errno : ret;
}
#endif

static int vhost_kernel_init(struct vhost_dev *dev, void *opaque, Error **errp)
{
    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

    dev->opaque = opaque;

    return 0;
}

static int vhost_kernel_cleanup(struct vhost_dev *dev)
{
    int fd = (uintptr_t) dev->opaque;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_KERNEL);

#ifdef _WIN32
    if (w32fd_is_token(fd)) {
        return CloseHandle(w32fd_token_handle(fd)) ? 0 : -EBADF;
    }
#endif
    return close(fd) < 0 ? -errno : 0;
}

static int vhost_kernel_memslots_limit(struct vhost_dev *dev)
{
    int limit = 64;
    char *s;

    if (g_file_get_contents("/sys/module/vhost/parameters/max_mem_regions",
                            &s, NULL, NULL)) {
        uint64_t val = g_ascii_strtoull(s, NULL, 10);
        if (val < INT_MAX && val > 0) {
            g_free(s);
            return val;
        }
        error_report("ignoring invalid max_mem_regions value in vhost module:"
                     " %s", s);
    }
    g_free(s);
    return limit;
}

static int vhost_kernel_net_set_backend(struct vhost_dev *dev,
                                        struct vhost_vring_file *file)
{
    return vhost_kernel_call(dev, VHOST_NET_SET_BACKEND, file);
}

static int vhost_kernel_scsi_set_endpoint(struct vhost_dev *dev,
                                          struct vhost_scsi_target *target)
{
    return vhost_kernel_call(dev, VHOST_SCSI_SET_ENDPOINT, target);
}

static int vhost_kernel_scsi_clear_endpoint(struct vhost_dev *dev,
                                            struct vhost_scsi_target *target)
{
    return vhost_kernel_call(dev, VHOST_SCSI_CLEAR_ENDPOINT, target);
}

static int vhost_kernel_scsi_get_abi_version(struct vhost_dev *dev, int *version)
{
    return vhost_kernel_call(dev, VHOST_SCSI_GET_ABI_VERSION, version);
}

static int vhost_kernel_set_log_base(struct vhost_dev *dev, uint64_t base,
                                     struct vhost_log *log)
{
    return vhost_kernel_call(dev, VHOST_SET_LOG_BASE, &base);
}

static int vhost_kernel_set_mem_table(struct vhost_dev *dev,
                                      struct vhost_memory *mem)
{
    return vhost_kernel_call(dev, VHOST_SET_MEM_TABLE, mem);
}

static int vhost_kernel_set_vring_addr(struct vhost_dev *dev,
                                       struct vhost_vring_addr *addr)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_ADDR, addr);
}

static int vhost_kernel_set_vring_endian(struct vhost_dev *dev,
                                         struct vhost_vring_state *ring)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_ENDIAN, ring);
}

static int vhost_kernel_set_vring_num(struct vhost_dev *dev,
                                      struct vhost_vring_state *ring)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_NUM, ring);
}

static int vhost_kernel_set_vring_base(struct vhost_dev *dev,
                                       struct vhost_vring_state *ring)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_BASE, ring);
}

static int vhost_kernel_get_vring_base(struct vhost_dev *dev,
                                       struct vhost_vring_state *ring)
{
    return vhost_kernel_call(dev, VHOST_GET_VRING_BASE, ring);
}

static int vhost_kernel_set_vring_kick(struct vhost_dev *dev,
                                       struct vhost_vring_file *file)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_KICK, file);
}

static int vhost_kernel_set_vring_call(struct vhost_dev *dev,
                                       struct vhost_vring_file *file)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_CALL, file);
}

static int vhost_kernel_set_vring_err(struct vhost_dev *dev,
                                      struct vhost_vring_file *file)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_ERR, file);
}

static int vhost_kernel_set_vring_busyloop_timeout(struct vhost_dev *dev,
                                                   struct vhost_vring_state *s)
{
    return vhost_kernel_call(dev, VHOST_SET_VRING_BUSYLOOP_TIMEOUT, s);
}

static int vhost_kernel_new_worker(struct vhost_dev *dev,
                                   struct vhost_worker_state *worker)
{
    return vhost_kernel_call(dev, VHOST_NEW_WORKER, worker);
}

static int vhost_kernel_free_worker(struct vhost_dev *dev,
                                    struct vhost_worker_state *worker)
{
    return vhost_kernel_call(dev, VHOST_FREE_WORKER, worker);
}

static int vhost_kernel_attach_vring_worker(struct vhost_dev *dev,
                                            struct vhost_vring_worker *worker)
{
    return vhost_kernel_call(dev, VHOST_ATTACH_VRING_WORKER, worker);
}

static int vhost_kernel_get_vring_worker(struct vhost_dev *dev,
                                         struct vhost_vring_worker *worker)
{
    return vhost_kernel_call(dev, VHOST_GET_VRING_WORKER, worker);
}

static int vhost_kernel_set_backend_cap(struct vhost_dev *dev)
{
    uint64_t features;
    uint64_t f = 0x1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2;
    int r;

    if (vhost_kernel_call(dev, VHOST_GET_BACKEND_FEATURES, &features)) {
        return 0;
    }

    features &= f;
    r = vhost_kernel_call(dev, VHOST_SET_BACKEND_FEATURES,
                              &features);
    if (r) {
        return 0;
    }

    dev->backend_cap = features;

    return 0;
}

static int vhost_kernel_set_features(struct vhost_dev *dev,
                                     const uint64_t *features)
{
    struct vhost_features farray;
    bool extended_in_use;
    int r;

    farray.count = VIRTIO_FEATURES_NU64S;
    virtio_features_copy(farray.features, features);
    extended_in_use = virtio_features_use_ex(farray.features);

    /*
     * Can't check for ENOTTY: for unknown ioctls the kernel interprets
     * the argument as a virtio queue id and most likely errors out validating
     * such id, instead of reporting an unknown operation.
     */
    r = vhost_kernel_call(dev, VHOST_SET_FEATURES_ARRAY, &farray);
    if (!r) {
        return 0;
    }

    if (extended_in_use) {
        error_report("Trying to set extended features without kernel support");
        return -EINVAL;
    }
    return vhost_kernel_call(dev, VHOST_SET_FEATURES, &farray.features[0]);
}

static int vhost_kernel_get_features(struct vhost_dev *dev, uint64_t *features)
{
    struct vhost_features farray;
    int r;

    farray.count = VIRTIO_FEATURES_NU64S;
    r = vhost_kernel_call(dev, VHOST_GET_FEATURES_ARRAY, &farray);
    if (r) {
        memset(&farray, 0, sizeof(farray));
        r = vhost_kernel_call(dev, VHOST_GET_FEATURES, &farray.features[0]);
    }
    if (r) {
        return r;
    }

    virtio_features_copy(features, farray.features);
    return 0;
}

static int vhost_kernel_set_owner(struct vhost_dev *dev)
{
    return vhost_kernel_call(dev, VHOST_SET_OWNER, NULL);
}

static int vhost_kernel_reset_owner(struct vhost_dev *dev)
{
    return vhost_kernel_call(dev, VHOST_RESET_OWNER, NULL);
}

static int vhost_kernel_get_vq_index(struct vhost_dev *dev, int idx)
{
    assert(idx >= dev->vq_index && idx < dev->vq_index + dev->nvqs);

    return idx - dev->vq_index;
}

static int vhost_kernel_vsock_set_guest_cid(struct vhost_dev *dev,
                                            uint64_t guest_cid)
{
    return vhost_kernel_call(dev, VHOST_VSOCK_SET_GUEST_CID, &guest_cid);
}

static int vhost_kernel_vsock_set_running(struct vhost_dev *dev, int start)
{
    return vhost_kernel_call(dev, VHOST_VSOCK_SET_RUNNING, &start);
}

static void vhost_kernel_iotlb_read(void *opaque)
{
    struct vhost_dev *dev = opaque;
    ssize_t len;

    if (dev->backend_cap &
        (0x1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2)) {
        struct vhost_msg_v2 msg;

        while ((len = read((uintptr_t)dev->opaque, &msg, sizeof msg)) > 0) {
            if (len < sizeof msg) {
                error_report("Wrong vhost message len: %d", (int)len);
                break;
            }
            if (msg.type != VHOST_IOTLB_MSG_V2) {
                error_report("Unknown vhost iotlb message type");
                break;
            }

            vhost_handle_iotlb_msg(dev, &msg.iotlb);
        }
    } else {
        struct vhost_msg msg;

        while ((len = read((uintptr_t)dev->opaque, &msg, sizeof msg)) > 0) {
            if (len < sizeof msg) {
                error_report("Wrong vhost message len: %d", (int)len);
                break;
            }
            if (msg.type != VHOST_IOTLB_MSG) {
                error_report("Unknown vhost iotlb message type");
                break;
            }

            vhost_handle_iotlb_msg(dev, &msg.iotlb);
        }
    }
}

static int vhost_kernel_send_device_iotlb_msg(struct vhost_dev *dev,
                                              struct vhost_iotlb_msg *imsg)
{
    if (dev->backend_cap & (1ULL << VHOST_BACKEND_F_IOTLB_MSG_V2)) {
        struct vhost_msg_v2 msg = {};

        msg.type = VHOST_IOTLB_MSG_V2;
        msg.iotlb = *imsg;

        if (write((uintptr_t)dev->opaque, &msg, sizeof msg) != sizeof msg) {
            error_report("Fail to update device iotlb");
            return -EFAULT;
        }
    } else {
        struct vhost_msg msg = {};

        msg.type = VHOST_IOTLB_MSG;
        msg.iotlb = *imsg;

        if (write((uintptr_t)dev->opaque, &msg, sizeof msg) != sizeof msg) {
            error_report("Fail to update device iotlb");
            return -EFAULT;
        }
    }

    return 0;
}

static void vhost_kernel_set_iotlb_callback(struct vhost_dev *dev,
                                           int enabled)
{
    if (enabled)
        qemu_set_fd_handler((uintptr_t)dev->opaque,
                            vhost_kernel_iotlb_read, NULL, dev);
    else
        qemu_set_fd_handler((uintptr_t)dev->opaque, NULL, NULL, NULL);
}

const VhostOps kernel_ops = {
        .backend_type = VHOST_BACKEND_TYPE_KERNEL,
        .vhost_init = vhost_kernel_init,
        .vhost_cleanup = vhost_kernel_cleanup,
        .vhost_memslots_limit = vhost_kernel_memslots_limit,
        .vhost_net_set_backend = vhost_kernel_net_set_backend,
        .vhost_scsi_set_endpoint = vhost_kernel_scsi_set_endpoint,
        .vhost_scsi_clear_endpoint = vhost_kernel_scsi_clear_endpoint,
        .vhost_scsi_get_abi_version = vhost_kernel_scsi_get_abi_version,
        .vhost_set_log_base = vhost_kernel_set_log_base,
        .vhost_set_mem_table = vhost_kernel_set_mem_table,
        .vhost_set_vring_addr = vhost_kernel_set_vring_addr,
        .vhost_set_vring_endian = vhost_kernel_set_vring_endian,
        .vhost_set_vring_num = vhost_kernel_set_vring_num,
        .vhost_set_vring_base = vhost_kernel_set_vring_base,
        .vhost_get_vring_base = vhost_kernel_get_vring_base,
        .vhost_set_vring_kick = vhost_kernel_set_vring_kick,
        .vhost_set_vring_call = vhost_kernel_set_vring_call,
        .vhost_set_vring_err = vhost_kernel_set_vring_err,
        .vhost_set_vring_busyloop_timeout =
                                vhost_kernel_set_vring_busyloop_timeout,
        .vhost_get_vring_worker = vhost_kernel_get_vring_worker,
        .vhost_attach_vring_worker = vhost_kernel_attach_vring_worker,
        .vhost_new_worker = vhost_kernel_new_worker,
        .vhost_free_worker = vhost_kernel_free_worker,
        .vhost_set_features_ex = vhost_kernel_set_features,
        .vhost_get_features_ex = vhost_kernel_get_features,
        .vhost_set_backend_cap = vhost_kernel_set_backend_cap,
        .vhost_set_owner = vhost_kernel_set_owner,
        .vhost_reset_owner = vhost_kernel_reset_owner,
        .vhost_get_vq_index = vhost_kernel_get_vq_index,
        .vhost_vsock_set_guest_cid = vhost_kernel_vsock_set_guest_cid,
        .vhost_vsock_set_running = vhost_kernel_vsock_set_running,
        .vhost_set_iotlb_callback = vhost_kernel_set_iotlb_callback,
        .vhost_send_device_iotlb_msg = vhost_kernel_send_device_iotlb_msg,
};
#endif
