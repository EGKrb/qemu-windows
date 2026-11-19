/*
 * vhost-net for Windows: the data path of virtio-net in the kernel, between
 * the virtqueues of a QEMU guest and a TAP-Windows device, as vhost-net
 * does on Linux between the guest and a tap device.
 *
 * The interface is the one of Linux's /dev/vhost-net: the requests of
 * linux/vhost.h, as DeviceIoControl() codes on \\.\vhost-net (see
 * include/hw/virtio/vhost-win32.h), with handles of the calling process
 * where Linux takes descriptors: events for kick and call, the TAP device
 * for VHOST_NET_SET_BACKEND.
 *
 * The guest's memory is QEMU's: MmSecureVirtualMemory() keeps its regions
 * mapped, and a worker thread, attached to QEMU's process, reaches them
 * by their addresses, as the vhost worker of Linux uses QEMU's mm.
 * Frames go to and come from the TAP device with IRPs; the virtio-net
 * header is added and removed here (VHOST_NET_F_VIRTIO_NET_HDR: TAP-Windows
 * has none).  Split virtqueues, indirect descriptors, event index,
 * mergeable receive buffers, dirty page log.
 *
 * Built with MinGW (build.sh), test-signed; loaded as a kernel service.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ntifs.h>
#include <ntddk.h>

#define TAG 'nhvQ'

#ifndef KeMemoryBarrier
#define KeMemoryBarrier() __sync_synchronize()
#endif

/* ---- the interface of linux/vhost.h ------------------------------------ */

#define VHOST_DEVICE_TYPE 0x8b56
#define IOC_WRITE 1
#define IOC_READ  2

struct vhost_vring_state {
    unsigned int index;
    unsigned int num;
};

struct vhost_vring_file {
    unsigned int index;
    int fd;             /* a handle of the caller here, -1 for none */
};

struct vhost_vring_addr {
    unsigned int index;
    unsigned int flags;
    unsigned long long desc_user_addr;
    unsigned long long used_user_addr;
    unsigned long long avail_user_addr;
    unsigned long long log_guest_addr;
};

struct vhost_memory_region {
    unsigned long long guest_phys_addr;
    unsigned long long memory_size;
    unsigned long long userspace_addr;
    unsigned long long flags_padding;
};

struct vhost_memory {
    unsigned int nregions;
    unsigned int padding;
    struct vhost_memory_region regions[];
};

/* request numbers */
#define NR_FEATURES          0x00
#define NR_SET_OWNER         0x01
#define NR_RESET_OWNER       0x02
#define NR_SET_MEM_TABLE     0x03
#define NR_SET_LOG_BASE      0x04
#define NR_SET_VRING_NUM     0x10
#define NR_SET_VRING_ADDR    0x11
#define NR_VRING_BASE        0x12
#define NR_SET_VRING_ENDIAN  0x13
#define NR_SET_VRING_KICK    0x20
#define NR_SET_VRING_CALL    0x21
#define NR_SET_VRING_ERR     0x22
#define NR_SET_BUSYLOOP      0x23
#define NR_SET_BACKEND_FEAT  0x25
#define NR_GET_BACKEND_FEAT  0x26
#define NR_NET_SET_BACKEND   0x30

#define VHOST_VRING_F_LOG          0
#define VIRTIO_F_NOTIFY_ON_EMPTY   24
#define VHOST_F_LOG_ALL            26
#define VHOST_NET_F_VIRTIO_NET_HDR 27
#define VIRTIO_F_ANY_LAYOUT        27
#define VIRTIO_RING_F_INDIRECT     28
#define VIRTIO_RING_F_EVENT_IDX    29
#define VIRTIO_F_VERSION_1         32
#define VIRTIO_NET_F_MRG_RXBUF     15

#define VHOST_FEATURES \
    ((1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) | (1ULL << VHOST_F_LOG_ALL) | \
     (1ULL << VHOST_NET_F_VIRTIO_NET_HDR) | (1ULL << VIRTIO_RING_F_INDIRECT) | \
     (1ULL << VIRTIO_RING_F_EVENT_IDX) | (1ULL << VIRTIO_F_VERSION_1) | \
     (1ULL << VIRTIO_NET_F_MRG_RXBUF))

#define VRING_DESC_F_NEXT        1
#define VRING_DESC_F_WRITE       2
#define VRING_DESC_F_INDIRECT    4
#define VRING_AVAIL_F_NO_INTERRUPT 1
#define VHOST_LOG_PAGE           0x1000

/* ---- state -------------------------------------------------------------- */

#define MAX_REGIONS 64
#define RX_SLOTS    8
#define RX_BUF      16384
#define TX_BUF      (65536 + 64)
#define VQ_RX       0
#define VQ_TX       1
#define BATCH       256

typedef struct Region {
    ULONG64 gpa, size, uva;
    HANDLE secure;
} Region;

typedef struct Vq {
    unsigned int num;
    ULONG64 desc, avail, used;          /* QEMU's addresses */
    ULONG64 log_addr;                   /* guest address of the used ring */
    unsigned int flags;
    USHORT last_avail, last_used, signalled_used;
    BOOLEAN signalled_valid;
    BOOLEAN backend;                    /* VHOST_NET_SET_BACKEND done */
    BOOLEAN started;                    /* used index read */
    PKEVENT kick, call, err;
} Vq;

typedef struct RxSlot {
    PIRP irp;
    PMDL mdl;
    UCHAR *buf;
    KEVENT done;
    BOOLEAN pending;                    /* sent to the TAP device */
} RxSlot;

typedef struct Dev {
    PEPROCESS owner;
    KMUTEX lock;
    ULONG64 features;
    ULONG hdr_len;                      /* virtio-net header of the guest */
    Region regions[MAX_REGIONS];
    ULONG nregions;
    ULONG64 log_base;
    HANDLE log_secure;
    Vq vq[2];
    PFILE_OBJECT tap;
    PDEVICE_OBJECT tapdev;
    RxSlot rx[RX_SLOTS];
    ULONG rx_head;                      /* the oldest frame read */
    PIRP txirp;
    PMDL txmdl;
    UCHAR *txbuf;
    KEVENT txdone;
    /* the worker */
    struct Chain *chain;                /* scratch of the worker */
    PKTHREAD thread;
    KEVENT ctl;
    volatile LONG stop;
    PVOID release[16];                  /* objects it no longer waits for */
    ULONG nrelease;
} Dev;

static PDEVICE_OBJECT vhost_device;
static UNICODE_STRING dev_name = RTL_CONSTANT_STRING(L"\\Device\\VhostNet");
static UNICODE_STRING dos_name = RTL_CONSTANT_STRING(L"\\DosDevices\\vhost-net");

static void dev_lock(Dev *d)
{
    KeWaitForSingleObject(&d->lock, Executive, KernelMode, FALSE, NULL);
}

static void dev_unlock(Dev *d)
{
    KeReleaseMutex(&d->lock, FALSE);
}

/* an object the worker may wait for: released by the worker, later */
static void dev_release(Dev *d, PVOID obj)
{
    if (!obj) {
        return;
    }
    if (!d->thread || d->nrelease == 16) {
        ObDereferenceObject(obj);
        return;
    }
    d->release[d->nrelease++] = obj;
    KeSetEvent(&d->ctl, IO_NO_INCREMENT, FALSE);
}

/* ---- guest memory --------------------------------------------------------- */

/* QEMU's memory for [uva, uva + len): inside a secured region */
static BOOLEAN uva_ok(Dev *d, ULONG64 uva, ULONG64 len)
{
    ULONG i;

    for (i = 0; i < d->nregions; i++) {
        Region *r = &d->regions[i];

        if (uva >= r->uva && uva - r->uva <= r->size &&
            len <= r->size - (uva - r->uva)) {
            return TRUE;
        }
    }
    return FALSE;
}

static Region *gpa_region(Dev *d, ULONG64 gpa)
{
    ULONG i;

    for (i = 0; i < d->nregions; i++) {
        Region *r = &d->regions[i];

        if (gpa >= r->gpa && gpa - r->gpa < r->size) {
            return r;
        }
    }
    return NULL;
}

static void log_gpa(Dev *d, ULONG64 gpa, ULONG64 len)
{
    ULONG64 page;

    if (!(d->features & (1ULL << VHOST_F_LOG_ALL)) || !d->log_secure ||
        !len) {
        return;
    }
    for (page = gpa / VHOST_LOG_PAGE; page <= (gpa + len - 1) / VHOST_LOG_PAGE;
         page++) {
        UCHAR *p = (UCHAR *)(ULONG_PTR)(d->log_base + page / 8);

        __atomic_fetch_or(p, (UCHAR)(1 << (page % 8)), __ATOMIC_SEQ_CST);
    }
}

/* copy between the guest's memory and @buf; FALSE outside of it */
static BOOLEAN guest_copy(Dev *d, ULONG64 gpa, void *buf, ULONG len,
                          BOOLEAN to_guest)
{
    UCHAR *b = buf;

    if (to_guest) {
        log_gpa(d, gpa, len);
    }
    while (len) {
        Region *r = gpa_region(d, gpa);
        ULONG64 off, n;
        UCHAR *p;

        if (!r) {
            return FALSE;
        }
        off = gpa - r->gpa;
        n = r->size - off < len ? r->size - off : len;
        p = (UCHAR *)(ULONG_PTR)(r->uva + off);
        if (to_guest) {
            RtlCopyMemory(p, b, (SIZE_T)n);
        } else {
            RtlCopyMemory(b, p, (SIZE_T)n);
        }
        b += n;
        gpa += n;
        len -= (ULONG)n;
    }
    return TRUE;
}

static USHORT rd16(ULONG64 uva)
{
    return *(volatile USHORT *)(ULONG_PTR)uva;
}

static void wr16(ULONG64 uva, USHORT v)
{
    *(volatile USHORT *)(ULONG_PTR)uva = v;
}

/* ---- virtqueues ----------------------------------------------------------- */

typedef struct Desc {
    ULONG64 addr;
    ULONG len;
    USHORT flags;
    USHORT next;
} Desc;

typedef struct Chain {
    /* the buffers of a descriptor chain: guest addresses */
    ULONG64 addr[64];
    ULONG len[64];
    BOOLEAN write[64];
    ULONG n;
} Chain;

static BOOLEAN vq_ready(Dev *d, Vq *vq)
{
    return vq->num && vq->desc && vq->avail && vq->used && vq->backend &&
           vq->started && d->tap;
}

static BOOLEAN feature(Dev *d, int bit)
{
    return (d->features >> bit) & 1;
}

/* the chain of descriptors at @head, through an indirect table too */
static BOOLEAN vq_chain(Dev *d, Vq *vq, USHORT head, Chain *c)
{
    ULONG64 table = vq->desc;
    BOOLEAN indirect = FALSE, guest_table = FALSE;
    ULONG max = vq->num, i = head, steps = 0;
    Desc desc;

    c->n = 0;
    for (;;) {
        if (i >= max || ++steps > max + 1) {
            return FALSE;
        }
        if (guest_table) {
            if (!guest_copy(d, table + (ULONG64)i * sizeof(Desc), &desc,
                            sizeof(Desc), FALSE)) {
                return FALSE;
            }
        } else {
            RtlCopyMemory(&desc, (void *)(ULONG_PTR)(table + i * sizeof(Desc)),
                          sizeof(Desc));
        }
        if (desc.flags & VRING_DESC_F_INDIRECT) {
            if (indirect || !feature(d, VIRTIO_RING_F_INDIRECT) ||
                desc.len % sizeof(Desc) || !desc.len) {
                return FALSE;
            }
            /* the indirect table is guest memory */
            indirect = guest_table = TRUE;
            table = desc.addr;
            max = desc.len / sizeof(Desc);
            i = 0;
            steps = 0;
            continue;
        }
        if (c->n == 64) {
            return FALSE;
        }
        c->addr[c->n] = desc.addr;
        c->len[c->n] = desc.len;
        c->write[c->n] = (desc.flags & VRING_DESC_F_WRITE) != 0;
        c->n++;
        if (!(desc.flags & VRING_DESC_F_NEXT)) {
            return TRUE;
        }
        i = desc.next;
    }
}

static USHORT avail_idx(Vq *vq)
{
    USHORT v = rd16(vq->avail + 2);

    KeMemoryBarrier();
    return v;
}

static USHORT avail_head(Vq *vq, USHORT idx)
{
    return rd16(vq->avail + 4 + 2 * (idx % vq->num));
}

static void used_add(Dev *d, Vq *vq, USHORT head, ULONG len)
{
    ULONG64 off = 4 + 8ULL * (vq->last_used % vq->num);
    ULONG *e = (ULONG *)(ULONG_PTR)(vq->used + off);

    e[0] = head;
    e[1] = len;
    if (vq->flags & (1 << VHOST_VRING_F_LOG)) {
        log_gpa(d, vq->log_addr + off, 8);
    }
    vq->last_used++;
}

static void used_flush(Dev *d, Vq *vq)
{
    KeMemoryBarrier();
    wr16(vq->used + 2, vq->last_used);
    if (vq->flags & (1 << VHOST_VRING_F_LOG)) {
        log_gpa(d, vq->log_addr + 2, 2);
    }
    KeMemoryBarrier();
}

/* the interrupt of the guest, unless it does not want it */
static void vq_signal(Dev *d, Vq *vq)
{
    if (!vq->call) {
        return;
    }
    KeMemoryBarrier();
    if (feature(d, VIRTIO_RING_F_EVENT_IDX)) {
        USHORT event = rd16(vq->avail + 4 + 2 * vq->num);
        USHORT old = vq->signalled_used, now = vq->last_used;
        BOOLEAN valid = vq->signalled_valid;

        vq->signalled_used = now;
        vq->signalled_valid = TRUE;
        if (valid && (USHORT)(now - event - 1) >= (USHORT)(now - old)) {
            return;
        }
    } else if (rd16(vq->avail) & VRING_AVAIL_F_NO_INTERRUPT) {
        if (!feature(d, VIRTIO_F_NOTIFY_ON_EMPTY) ||
            vq->last_avail != avail_idx(vq)) {
            return;
        }
    }
    KeSetEvent(vq->call, IO_NO_INCREMENT, FALSE);
}

/* before waiting: the guest kicks for the next buffer (event index) */
static BOOLEAN vq_arm(Dev *d, Vq *vq)
{
    USHORT seen;

    if (!vq_ready(d, vq)) {
        return FALSE;
    }
    seen = avail_idx(vq);
    if (feature(d, VIRTIO_RING_F_EVENT_IDX)) {
        /* as vhost_enable_notify(): past what we saw */
        wr16(vq->used + 4 + 8 * vq->num, seen);
        if (vq->flags & (1 << VHOST_VRING_F_LOG)) {
            log_gpa(d, vq->log_addr + 4 + 8 * vq->num, 2);
        }
        KeMemoryBarrier();
    }
    return avail_idx(vq) != seen;
}

/* ---- the TAP device --------------------------------------------------------- */

static NTSTATUS irp_done(PDEVICE_OBJECT dev, PIRP irp, PVOID ctx)
{
    UNREFERENCED_PARAMETER(dev);
    UNREFERENCED_PARAMETER(irp);
    KeSetEvent((PKEVENT)ctx, IO_NO_INCREMENT, FALSE);
    /* our IRP: it stays ours */
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static void irp_send(Dev *d, PIRP irp, PMDL mdl, UCHAR *buf, ULONG len,
                     UCHAR major, PKEVENT done)
{
    PIO_STACK_LOCATION sp;

    IoReuseIrp(irp, STATUS_SUCCESS);
    irp->MdlAddress = mdl;
    irp->AssociatedIrp.SystemBuffer = buf;
    irp->UserBuffer = buf;
    irp->RequestorMode = KernelMode;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = d->tap;
    sp = IoGetNextIrpStackLocation(irp);
    sp->MajorFunction = major;
    sp->FileObject = d->tap;
    if (major == IRP_MJ_READ) {
        sp->Parameters.Read.Length = len;
        sp->Parameters.Read.ByteOffset.QuadPart = 0;
    } else {
        sp->Parameters.Write.Length = len;
        sp->Parameters.Write.ByteOffset.QuadPart = 0;
    }
    KeClearEvent(done);
    IoSetCompletionRoutine(irp, irp_done, done, TRUE, TRUE, TRUE);
    IoCallDriver(d->tapdev, irp);
}

static void rx_post(Dev *d, ULONG i)
{
    RxSlot *r = &d->rx[i];

    r->pending = TRUE;
    irp_send(d, r->irp, r->mdl, r->buf, RX_BUF, IRP_MJ_READ, &r->done);
}

static void tap_write(Dev *d, ULONG len)
{
    if (!len) {
        return;
    }
    irp_send(d, d->txirp, d->txmdl, d->txbuf, len, IRP_MJ_WRITE, &d->txdone);
    KeWaitForSingleObject(&d->txdone, Executive, KernelMode, FALSE, NULL);
}

static void tap_free_slot(PIRP *irp, PMDL *mdl, UCHAR **buf)
{
    if (*irp) {
        IoFreeIrp(*irp);
        *irp = NULL;
    }
    if (*mdl) {
        IoFreeMdl(*mdl);
        *mdl = NULL;
    }
    if (*buf) {
        ExFreePoolWithTag(*buf, TAG);
        *buf = NULL;
    }
}

/* the TAP device goes: the reads in flight are cancelled first */
static void tap_detach(Dev *d)
{
    ULONG i;

    if (!d->tap) {
        return;
    }
    for (i = 0; i < RX_SLOTS; i++) {
        RxSlot *r = &d->rx[i];

        if (r->pending && r->irp) {
            IoCancelIrp(r->irp);
            KeWaitForSingleObject(&r->done, Executive, KernelMode, FALSE,
                                  NULL);
            r->pending = FALSE;
        }
        tap_free_slot(&r->irp, &r->mdl, &r->buf);
    }
    tap_free_slot(&d->txirp, &d->txmdl, &d->txbuf);
    dev_release(d, d->tap);
    d->tap = NULL;
    d->tapdev = NULL;
}

static UCHAR *pool_buf(ULONG len, PMDL *mdl)
{
    UCHAR *b = ExAllocatePoolWithTag(NonPagedPoolNx, len, TAG);

    if (!b) {
        return NULL;
    }
    *mdl = IoAllocateMdl(b, len, FALSE, FALSE, NULL);
    if (!*mdl) {
        ExFreePoolWithTag(b, TAG);
        return NULL;
    }
    MmBuildMdlForNonPagedPool(*mdl);
    return b;
}

static NTSTATUS tap_attach(Dev *d, HANDLE h)
{
    PFILE_OBJECT fo;
    NTSTATUS st;
    ULONG i;

    st = ObReferenceObjectByHandle(h, FILE_READ_DATA | FILE_WRITE_DATA,
                                   *IoFileObjectType, UserMode, (PVOID *)&fo,
                                   NULL);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    d->tap = fo;
    d->tapdev = IoGetRelatedDeviceObject(fo);
    d->txbuf = pool_buf(TX_BUF, &d->txmdl);
    d->txirp = IoAllocateIrp(d->tapdev->StackSize, FALSE);
    KeInitializeEvent(&d->txdone, NotificationEvent, FALSE);
    if (!d->txbuf || !d->txirp) {
        tap_detach(d);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    for (i = 0; i < RX_SLOTS; i++) {
        RxSlot *r = &d->rx[i];

        KeInitializeEvent(&r->done, NotificationEvent, FALSE);
        r->buf = pool_buf(RX_BUF, &r->mdl);
        r->irp = IoAllocateIrp(d->tapdev->StackSize, FALSE);
        if (!r->buf || !r->irp) {
            tap_detach(d);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    d->rx_head = 0;
    return STATUS_SUCCESS;
}

/* ---- transmit: guest -> TAP ---------------------------------------------- */

static BOOLEAN tx_process(Dev *d)
{
    Vq *vq = &d->vq[VQ_TX];
    Chain *c = d->chain;
    ULONG n = 0;

    if (!vq_ready(d, vq)) {
        return FALSE;
    }
    while (n < BATCH) {
        USHORT idx = avail_idx(vq), head;
        ULONG total = 0, skip = d->hdr_len, i;

        if (vq->last_avail == idx) {
            break;
        }
        head = avail_head(vq, vq->last_avail);
        vq->last_avail++;
        n++;
        if (!vq_chain(d, vq, head, c)) {
            used_add(d, vq, head, 0);
            continue;
        }
        /* the frame, without the virtio-net header */
        for (i = 0; i < c->n; i++) {
            ULONG64 a = c->addr[i];
            ULONG l = c->len[i];

            if (c->write[i]) {
                continue;
            }
            if (skip) {
                ULONG s = l < skip ? l : skip;

                a += s;
                l -= s;
                skip -= s;
            }
            if (total + l > TX_BUF) {
                l = TX_BUF - total;
            }
            if (l && !guest_copy(d, a, d->txbuf + total, l, FALSE)) {
                total = 0;
                break;
            }
            total += l;
        }
        tap_write(d, total);
        used_add(d, vq, head, 0);
    }
    if (n) {
        used_flush(d, vq);
        vq_signal(d, vq);
    }
    return n == BATCH;
}

/* ---- receive: TAP -> guest ------------------------------------------------ */

/* the frame of @r to the guest; FALSE when the guest has no buffer */
static BOOLEAN rx_deliver(Dev *d, UCHAR *frame, ULONG len)
{
    Vq *vq = &d->vq[VQ_RX];
    Chain *c = d->chain;
    UCHAR hdr[12] = { 0 };
    ULONG hlen = d->hdr_len, done = 0, nbufs = 0, total = hlen + len;
    BOOLEAN mrg = feature(d, VIRTIO_NET_F_MRG_RXBUF);
    USHORT idx = avail_idx(vq), heads[64];
    ULONG lens[64], i;
    ULONG64 hdr_gpa = 0;

    while (done < total) {
        USHORT head;
        ULONG written = 0;

        if (vq->last_avail == idx || nbufs == 64) {
            vq->last_avail -= (USHORT)nbufs;        /* not now */
            return FALSE;
        }
        head = avail_head(vq, vq->last_avail);
        vq->last_avail++;
        if (!vq_chain(d, vq, head, c)) {
            heads[nbufs] = head;
            lens[nbufs++] = 0;
            continue;
        }
        for (i = 0; i < c->n && done < total; i++) {
            ULONG64 a = c->addr[i];
            ULONG room = c->len[i];

            if (!c->write[i]) {
                continue;
            }
            while (room && done < total) {
                ULONG l;
                BOOLEAN ok;

                if (done < hlen) {
                    l = hlen - done < room ? hlen - done : room;
                    if (!hdr_gpa) {
                        hdr_gpa = a;
                    }
                    ok = guest_copy(d, a, hdr + done, l, TRUE);
                } else {
                    l = total - done < room ? total - done : room;
                    ok = guest_copy(d, a, frame + (done - hlen), l, TRUE);
                }
                if (!ok) {
                    break;
                }
                a += l;
                room -= l;
                done += l;
                written += l;
            }
        }
        heads[nbufs] = head;
        lens[nbufs++] = written;
        if (!mrg) {
            break;          /* one chain: what does not fit is lost */
        }
    }
    /* num_buffers, once known */
    if (mrg && hlen >= 12 && hdr_gpa && nbufs > 1) {
        USHORT nb = (USHORT)nbufs;

        guest_copy(d, hdr_gpa + 10, &nb, 2, TRUE);
    } else if (hlen >= 12 && hdr_gpa) {
        USHORT one = 1;

        guest_copy(d, hdr_gpa + 10, &one, 2, TRUE);
    }
    for (i = 0; i < nbufs; i++) {
        used_add(d, vq, heads[i], lens[i]);
    }
    return TRUE;
}

static BOOLEAN rx_process(Dev *d)
{
    Vq *vq = &d->vq[VQ_RX];
    ULONG n = 0;

    if (!vq_ready(d, vq)) {
        return FALSE;
    }
    /* the frames in the order the reads went to the TAP device */
    while (n < BATCH) {
        RxSlot *r = &d->rx[d->rx_head];

        if (!r->pending || !KeReadStateEvent(&r->done)) {
            break;
        }
        if (NT_SUCCESS(r->irp->IoStatus.Status) &&
            r->irp->IoStatus.Information) {
            if (!rx_deliver(d, r->buf, (ULONG)r->irp->IoStatus.Information)) {
                break;      /* kept until the guest gives buffers */
            }
            n++;
        }
        rx_post(d, d->rx_head);
        d->rx_head = (d->rx_head + 1) % RX_SLOTS;
    }
    if (n) {
        used_flush(d, vq);
        vq_signal(d, vq);
    }
    return n == BATCH;
}

/* the reads of the TAP device, all sent, once the receive queue runs */
static void rx_start(Dev *d)
{
    ULONG i;

    for (i = 0; i < RX_SLOTS; i++) {
        if (!d->rx[i].pending) {
            rx_post(d, i);
        }
    }
}

/* ---- the worker ----------------------------------------------------------- */

static VOID worker(PVOID ctx)
{
    Dev *d = ctx;
    KAPC_STATE apc;
    KWAIT_BLOCK blocks[4 + RX_SLOTS];

    /* QEMU's addresses are those of its process */
    KeStackAttachProcess((PKPROCESS)d->owner, &apc);
    for (;;) {
        PVOID objs[4 + RX_SLOTS];
        ULONG n = 0, i;
        BOOLEAN more = FALSE;

        dev_lock(d);
        for (i = 0; i < d->nrelease; i++) {
            ObDereferenceObject(d->release[i]);
        }
        d->nrelease = 0;
        if (d->stop) {
            dev_unlock(d);
            break;
        }
        for (i = 0; i < 2; i++) {
            if (d->vq[i].kick) {
                KeClearEvent(d->vq[i].kick);
            }
        }
        if (d->tap) {
            if (vq_ready(d, &d->vq[VQ_RX])) {
                rx_start(d);
            }
            more |= tx_process(d);
            more |= rx_process(d);
            more |= vq_arm(d, &d->vq[VQ_TX]);
            /* buffers came while a frame waits for some: try again */
            if (vq_arm(d, &d->vq[VQ_RX]) &&
                d->rx[d->rx_head].pending &&
                KeReadStateEvent(&d->rx[d->rx_head].done)) {
                more = TRUE;
            }
        }
        objs[n++] = &d->ctl;
        for (i = 0; i < 2; i++) {
            if (d->vq[i].kick) {
                objs[n++] = d->vq[i].kick;
            }
        }
        if (d->tap && vq_ready(d, &d->vq[VQ_RX])) {
            RxSlot *r = &d->rx[d->rx_head];

            if (r->pending) {
                objs[n++] = &r->done;
            }
        }
        dev_unlock(d);
        if (more) {
            continue;
        }
        KeWaitForMultipleObjects(n, objs, WaitAny, Executive, KernelMode,
                                 FALSE, NULL, blocks);
    }
    KeUnstackDetachProcess(&apc);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS worker_start(Dev *d)
{
    HANDLE h;
    NTSTATUS st;

    KeInitializeEvent(&d->ctl, SynchronizationEvent, FALSE);
    d->stop = 0;
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                              worker, d);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = ObReferenceObjectByHandle(h, SYNCHRONIZE, *PsThreadType, KernelMode,
                                   (PVOID *)&d->thread, NULL);
    ZwClose(h);
    return st;
}

static void worker_stop(Dev *d)
{
    ULONG i;

    if (!d->thread) {
        return;
    }
    InterlockedExchange(&d->stop, 1);
    KeSetEvent(&d->ctl, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(d->thread, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(d->thread);
    d->thread = NULL;
    for (i = 0; i < d->nrelease; i++) {
        ObDereferenceObject(d->release[i]);
    }
    d->nrelease = 0;
}

/* ---- requests ------------------------------------------------------------ */

static void mem_free(Dev *d)
{
    ULONG i;

    for (i = 0; i < d->nregions; i++) {
        if (d->regions[i].secure) {
            MmUnsecureVirtualMemory(d->regions[i].secure);
        }
    }
    d->nregions = 0;
    if (d->log_secure) {
        MmUnsecureVirtualMemory(d->log_secure);
        d->log_secure = NULL;
    }
}

static NTSTATUS event_ref(int fd, PKEVENT *ev)
{
    *ev = NULL;
    if (fd == -1) {
        return STATUS_SUCCESS;
    }
    return ObReferenceObjectByHandle((HANDLE)(LONG_PTR)fd,
                                     EVENT_MODIFY_STATE | SYNCHRONIZE,
                                     *ExEventObjectType, UserMode,
                                     (PVOID *)ev, NULL);
}

/* everything set up for the owner goes (RESET_OWNER, close) */
static void dev_reset(Dev *d)
{
    ULONG i;

    worker_stop(d);
    dev_lock(d);
    tap_detach(d);
    for (i = 0; i < 2; i++) {
        Vq *vq = &d->vq[i];

        if (vq->kick) {
            ObDereferenceObject(vq->kick);
        }
        if (vq->call) {
            ObDereferenceObject(vq->call);
        }
        if (vq->err) {
            ObDereferenceObject(vq->err);
        }
        RtlZeroMemory(vq, sizeof(*vq));
    }
    for (i = 0; i < d->nrelease; i++) {
        ObDereferenceObject(d->release[i]);
    }
    d->nrelease = 0;
    mem_free(d);
    d->features = 0;
    if (d->owner) {
        ObDereferenceObject(d->owner);
        d->owner = NULL;
    }
    dev_unlock(d);
}

static NTSTATUS set_mem_table(Dev *d, struct vhost_memory *m, ULONG len)
{
    Region regions[MAX_REGIONS];
    ULONG i, j;

    if (len < sizeof(*m) || m->nregions > MAX_REGIONS ||
        len < sizeof(*m) + m->nregions * sizeof(m->regions[0])) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(regions, sizeof(regions));
    for (i = 0; i < m->nregions; i++) {
        struct vhost_memory_region *r = &m->regions[i];

        regions[i].gpa = r->guest_phys_addr;
        regions[i].size = r->memory_size;
        regions[i].uva = r->userspace_addr;
        if (!r->memory_size ||
            r->userspace_addr + r->memory_size < r->userspace_addr ||
            r->userspace_addr + r->memory_size > (ULONG64)MmHighestUserAddress) {
            goto fail;
        }
        /* in this process: QEMU's */
        regions[i].secure = MmSecureVirtualMemory(
            (PVOID)(ULONG_PTR)r->userspace_addr, (SIZE_T)r->memory_size,
            PAGE_READWRITE);
        if (!regions[i].secure) {
            goto fail;
        }
    }
    for (j = 0; j < d->nregions; j++) {
        MmUnsecureVirtualMemory(d->regions[j].secure);
    }
    RtlCopyMemory(d->regions, regions, sizeof(regions));
    d->nregions = m->nregions;
    return STATUS_SUCCESS;

fail:
    for (j = 0; j < i; j++) {
        MmUnsecureVirtualMemory(regions[j].secure);
    }
    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS set_log_base(Dev *d, ULONG64 base)
{
    ULONG64 end = 0, size;
    ULONG i;
    HANDLE sec;

    for (i = 0; i < d->nregions; i++) {
        ULONG64 e = d->regions[i].gpa + d->regions[i].size;

        end = e > end ? e : end;
    }
    size = (end / VHOST_LOG_PAGE + 7) / 8 + 8;
    sec = MmSecureVirtualMemory((PVOID)(ULONG_PTR)base, (SIZE_T)size,
                                PAGE_READWRITE);
    if (!sec) {
        return STATUS_INVALID_PARAMETER;
    }
    if (d->log_secure) {
        MmUnsecureVirtualMemory(d->log_secure);
    }
    d->log_base = base;
    d->log_secure = sec;
    return STATUS_SUCCESS;
}

/* the rings, checked, and where the guest's driver left the used ring */
static void vq_start(Dev *d, Vq *vq)
{
    if (!vq->num || !vq->backend ||
        !uva_ok(d, vq->desc, 16ULL * vq->num) ||
        !uva_ok(d, vq->avail, 6 + 2ULL * vq->num) ||
        !uva_ok(d, vq->used, 6 + 8ULL * vq->num)) {
        vq->started = FALSE;
        return;
    }
    vq->last_used = rd16(vq->used + 2);
    vq->signalled_valid = FALSE;
    vq->started = TRUE;
}

static NTSTATUS ioctl(Dev *d, ULONG dir, ULONG nr, void *buf, ULONG in,
                      ULONG out, ULONG_PTR *info)
{
    Vq *vq = NULL;
    NTSTATUS st = STATUS_SUCCESS;
    unsigned int index;

#define NEED(n) do { if (in < (n)) return STATUS_INVALID_PARAMETER; } while (0)

    *info = 0;
    if (nr != NR_SET_OWNER && nr != NR_FEATURES &&
        nr != NR_GET_BACKEND_FEAT && nr != NR_SET_BACKEND_FEAT && !d->owner) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (d->owner && d->owner != PsGetCurrentProcess()) {
        return STATUS_ACCESS_DENIED;        /* the owner's memory only */
    }
    switch (nr) {
    case NR_SET_VRING_NUM:
    case NR_SET_VRING_ADDR:
    case NR_VRING_BASE:
    case NR_SET_VRING_KICK:
    case NR_SET_VRING_CALL:
    case NR_SET_VRING_ERR:
    case NR_NET_SET_BACKEND:
    case NR_SET_BUSYLOOP:
    case NR_SET_VRING_ENDIAN:
        NEED(sizeof(unsigned int));
        index = *(unsigned int *)buf;
        if (index >= 2) {
            return STATUS_INVALID_PARAMETER;
        }
        vq = &d->vq[index];
        break;
    }

    switch (nr) {
    case NR_FEATURES:
        if (dir == IOC_READ) {
            if (out < 8) {
                return STATUS_INVALID_PARAMETER;
            }
            *(ULONG64 *)buf = VHOST_FEATURES;
            *info = 8;
            return STATUS_SUCCESS;
        }
        NEED(8);
        if (*(ULONG64 *)buf & ~VHOST_FEATURES) {
            return STATUS_NOT_SUPPORTED;
        }
        dev_lock(d);
        d->features = *(ULONG64 *)buf;
        d->hdr_len = d->features & ((1ULL << VIRTIO_NET_F_MRG_RXBUF) |
                                    (1ULL << VIRTIO_F_VERSION_1)) ? 12 : 10;
        dev_unlock(d);
        return STATUS_SUCCESS;

    case NR_SET_OWNER:
        if (d->owner) {
            return STATUS_DEVICE_BUSY;
        }
        d->owner = PsGetCurrentProcess();
        ObReferenceObject(d->owner);
        st = worker_start(d);
        if (!NT_SUCCESS(st)) {
            ObDereferenceObject(d->owner);
            d->owner = NULL;
        }
        return st;

    case NR_RESET_OWNER:
        dev_reset(d);
        return STATUS_SUCCESS;

    case NR_SET_MEM_TABLE:
        dev_lock(d);
        st = set_mem_table(d, buf, in);
        dev_unlock(d);
        return st;

    case NR_SET_LOG_BASE:
        NEED(8);
        dev_lock(d);
        st = set_log_base(d, *(ULONG64 *)buf);
        dev_unlock(d);
        return st;

    case NR_SET_VRING_NUM: {
        struct vhost_vring_state *s = buf;

        NEED(sizeof(*s));
        if (!s->num || s->num > 32768 || (s->num & (s->num - 1))) {
            return STATUS_INVALID_PARAMETER;
        }
        dev_lock(d);
        vq->num = s->num;
        dev_unlock(d);
        return STATUS_SUCCESS;
    }

    case NR_SET_VRING_ADDR: {
        struct vhost_vring_addr *a = buf;

        NEED(sizeof(*a));
        dev_lock(d);
        vq->desc = a->desc_user_addr;
        vq->avail = a->avail_user_addr;
        vq->used = a->used_user_addr;
        vq->log_addr = a->log_guest_addr;
        vq->flags = a->flags;
        if (vq->backend) {
            vq_start(d, vq);
            KeSetEvent(&d->ctl, IO_NO_INCREMENT, FALSE);
        }
        dev_unlock(d);
        return STATUS_SUCCESS;
    }

    case NR_VRING_BASE: {
        struct vhost_vring_state *s = buf;

        NEED(sizeof(*s));
        dev_lock(d);
        if (dir == (IOC_READ | IOC_WRITE)) {
            /* GET_VRING_BASE: the ring stops */
            s->num = vq->last_avail;
            vq->started = FALSE;
            *info = sizeof(*s);
        } else {
            vq->last_avail = (USHORT)s->num;
        }
        dev_unlock(d);
        return STATUS_SUCCESS;
    }

    case NR_SET_VRING_KICK:
    case NR_SET_VRING_CALL:
    case NR_SET_VRING_ERR: {
        struct vhost_vring_file *f = buf;
        PKEVENT ev, *slot;

        NEED(sizeof(*f));
        st = event_ref(f->fd, &ev);
        if (!NT_SUCCESS(st)) {
            return st;
        }
        slot = nr == NR_SET_VRING_KICK ? &vq->kick :
               nr == NR_SET_VRING_CALL ? &vq->call : &vq->err;
        dev_lock(d);
        dev_release(d, *slot);
        *slot = ev;
        KeSetEvent(&d->ctl, IO_NO_INCREMENT, FALSE);
        dev_unlock(d);
        return STATUS_SUCCESS;
    }

    case NR_NET_SET_BACKEND: {
        struct vhost_vring_file *f = buf;

        NEED(sizeof(*f));
        dev_lock(d);
        if (f->fd == -1) {
            vq->backend = FALSE;
            vq->started = FALSE;
            if (!d->vq[0].backend && !d->vq[1].backend) {
                tap_detach(d);
            }
        } else {
            if (!d->tap) {
                st = tap_attach(d, (HANDLE)(LONG_PTR)f->fd);
            }
            if (NT_SUCCESS(st)) {
                vq->backend = TRUE;
                vq_start(d, vq);
                if (!vq->started) {
                    st = STATUS_INVALID_PARAMETER;
                }
            }
        }
        KeSetEvent(&d->ctl, IO_NO_INCREMENT, FALSE);
        dev_unlock(d);
        return st;
    }

    case NR_SET_BUSYLOOP:
        return STATUS_SUCCESS;

    case NR_SET_BACKEND_FEAT:
        NEED(8);
        return *(ULONG64 *)buf ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;

    case NR_GET_BACKEND_FEAT:
        if (out < 8) {
            return STATUS_INVALID_PARAMETER;
        }
        *(ULONG64 *)buf = 0;
        *info = 8;
        return STATUS_SUCCESS;

    case NR_SET_VRING_ENDIAN:
    default:
        return STATUS_NOT_SUPPORTED;
    }
#undef NEED
}

/* ---- the device ------------------------------------------------------------ */

static NTSTATUS complete(PIRP irp, NTSTATUS st, ULONG_PTR info)
{
    irp->IoStatus.Status = st;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

static NTSTATUS dispatch_create(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    Dev *d;

    UNREFERENCED_PARAMETER(dev);
    d = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(Dev), TAG);
    if (!d) {
        return complete(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    RtlZeroMemory(d, sizeof(*d));
    d->chain = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(Chain), TAG);
    if (!d->chain) {
        ExFreePoolWithTag(d, TAG);
        return complete(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    KeInitializeMutex(&d->lock, 0);
    sp->FileObject->FsContext = d;
    return complete(irp, STATUS_SUCCESS, 0);
}

static NTSTATUS dispatch_cleanup(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    Dev *d = sp->FileObject->FsContext;

    UNREFERENCED_PARAMETER(dev);
    if (d) {
        /* in the process that closes it: QEMU's, for its memory */
        dev_reset(d);
    }
    return complete(irp, STATUS_SUCCESS, 0);
}

static NTSTATUS dispatch_close(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    Dev *d = sp->FileObject->FsContext;

    UNREFERENCED_PARAMETER(dev);
    if (d) {
        ExFreePoolWithTag(d->chain, TAG);
        ExFreePoolWithTag(d, TAG);
        sp->FileObject->FsContext = NULL;
    }
    return complete(irp, STATUS_SUCCESS, 0);
}

static NTSTATUS dispatch_ioctl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
    ULONG fn = (code >> 2) & 0xfff;
    Dev *d = sp->FileObject->FsContext;
    ULONG_PTR info = 0;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(dev);
    if ((code >> 16) != VHOST_DEVICE_TYPE || (code & 3) != METHOD_BUFFERED ||
        !(fn & 0x800) || !d) {
        return complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    st = ioctl(d, (fn >> 8) & 3, fn & 0xff, irp->AssociatedIrp.SystemBuffer,
               sp->Parameters.DeviceIoControl.InputBufferLength,
               sp->Parameters.DeviceIoControl.OutputBufferLength, &info);
    return complete(irp, st, info);
}

static VOID driver_unload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);
    IoDeleteSymbolicLink(&dos_name);
    if (vhost_device) {
        IoDeleteDevice(vhost_device);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    NTSTATUS st;

    UNREFERENCED_PARAMETER(reg);
    st = IoCreateDevice(drv, 0, &dev_name, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &vhost_device);
    if (!NT_SUCCESS(st)) {
        return st;
    }
    st = IoCreateSymbolicLink(&dos_name, &dev_name);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(vhost_device);
        return st;
    }
    drv->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
    drv->MajorFunction[IRP_MJ_CLEANUP] = dispatch_cleanup;
    drv->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_ioctl;
    drv->DriverUnload = driver_unload;
    return STATUS_SUCCESS;
}
