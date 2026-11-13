/*
 * QEMU Random Number Generator Backend
 *
 * Copyright IBM, Corp. 2012
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "system/rng-random.h"
#include "system/rng.h"
#include "qapi/error.h"
#include "qapi/qmp/qerror.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#ifdef _WIN32
#include "crypto/random.h"
#endif

struct RngRandom
{
    RngBackend parent;

    int fd;
    char *filename;
#ifdef _WIN32
    /* the system's generator, for /dev/random and /dev/urandom */
    bool system;
    QEMUBH *bh;
#endif
};

/**
 * A simple and incomplete backend to request entropy from /dev/random.
 *
 * This backend exposes an additional "filename" property that can be used to
 * set the filename to use to open the backend.
 */

#ifndef _WIN32
static void entropy_available(void *opaque)
{
    RngRandom *s = RNG_RANDOM(opaque);

    while (!QSIMPLEQ_EMPTY(&s->parent.requests)) {
        RngRequest *req = QSIMPLEQ_FIRST(&s->parent.requests);
        ssize_t len;

        len = read(s->fd, req->data, req->size);
        if (len < 0 && errno == EAGAIN) {
            return;
        }
        g_assert(len != -1);

        req->receive_entropy(req->opaque, req->data, len);

        rng_backend_finalize_request(&s->parent, req);
    }

    /* We've drained all requests, the fd handler can be reset. */
    qemu_set_fd_handler(s->fd, NULL, NULL, NULL);
}
#endif

#ifdef _WIN32
/*
 * Windows cannot poll files: the requests are served from a bottom half,
 * by the system's generator (BCryptGenRandom) for the Linux names of the
 * random devices, or by reading the file (a device or a named pipe).
 */
static void entropy_bh(void *opaque)
{
    RngRandom *s = RNG_RANDOM(opaque);

    while (!QSIMPLEQ_EMPTY(&s->parent.requests)) {
        RngRequest *req = QSIMPLEQ_FIRST(&s->parent.requests);
        ssize_t len;

        if (s->system) {
            if (qcrypto_random_bytes(req->data, req->size, NULL) < 0) {
                return;
            }
            len = req->size;
        } else {
            len = read(s->fd, req->data, req->size);
            if (len < 0) {
                return;
            }
        }

        req->receive_entropy(req->opaque, req->data, len);

        rng_backend_finalize_request(&s->parent, req);
    }
}
#endif

static void rng_random_request_entropy(RngBackend *b, RngRequest *req)
{
    RngRandom *s = RNG_RANDOM(b);

#ifdef _WIN32
    qemu_bh_schedule(s->bh);
#else
    if (QSIMPLEQ_EMPTY(&s->parent.requests)) {
        /* If there are no pending requests yet, we need to
         * install our fd handler. */
        qemu_set_fd_handler(s->fd, entropy_available, NULL, s);
    }
#endif
}

static void rng_random_opened(RngBackend *b, Error **errp)
{
    RngRandom *s = RNG_RANDOM(b);

    if (s->filename == NULL) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "filename", "a valid filename");
    } else {
#ifdef _WIN32
        if (g_str_equal(s->filename, "/dev/random") ||
            g_str_equal(s->filename, "/dev/urandom")) {
            s->system = true;
            return;
        }
        s->system = false;
        s->fd = qemu_open(s->filename, O_RDONLY | O_BINARY, errp);
#else
        s->fd = qemu_open(s->filename, O_RDONLY | O_NONBLOCK, errp);
#endif
    }
}

static char *rng_random_get_filename(Object *obj, Error **errp)
{
    RngRandom *s = RNG_RANDOM(obj);

    return g_strdup(s->filename);
}

static void rng_random_set_filename(Object *obj, const char *filename,
                                 Error **errp)
{
    RngBackend *b = RNG_BACKEND(obj);
    RngRandom *s = RNG_RANDOM(obj);

    if (b->opened) {
        error_setg(errp, "Property 'filename' can no longer be set");
        return;
    }

    g_free(s->filename);
    s->filename = g_strdup(filename);
}

static void rng_random_init(Object *obj)
{
    RngRandom *s = RNG_RANDOM(obj);

    s->filename = g_strdup("/dev/urandom");
    s->fd = -1;
#ifdef _WIN32
    s->bh = qemu_bh_new(entropy_bh, s);
#endif
}

static void rng_random_finalize(Object *obj)
{
    RngRandom *s = RNG_RANDOM(obj);

#ifdef _WIN32
    qemu_bh_delete(s->bh);
    if (s->fd != -1) {
        qemu_close(s->fd);
    }
#else
    if (s->fd != -1) {
        qemu_set_fd_handler(s->fd, NULL, NULL, NULL);
        qemu_close(s->fd);
    }
#endif

    g_free(s->filename);
}

static void rng_random_class_init(ObjectClass *klass, const void *data)
{
    RngBackendClass *rbc = RNG_BACKEND_CLASS(klass);

    rbc->request_entropy = rng_random_request_entropy;
    rbc->opened = rng_random_opened;
    object_class_property_add_str(klass, "filename",
                                  rng_random_get_filename,
                                  rng_random_set_filename);

}

static const TypeInfo rng_random_info = {
    .name = TYPE_RNG_RANDOM,
    .parent = TYPE_RNG_BACKEND,
    .instance_size = sizeof(RngRandom),
    .class_init = rng_random_class_init,
    .instance_init = rng_random_init,
    .instance_finalize = rng_random_finalize,
};

static void register_types(void)
{
    type_register_static(&rng_random_info);
}

type_init(register_types);
