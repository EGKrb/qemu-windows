/*
 * Parallel port character device on Windows (LPT1, \\.\LPT2...)
 *
 * Windows gives no access to the registers of the port (the ppdev ioctls
 * of Linux): the data the guest writes goes to the port, the device
 * models then emulate the registers themselves, as they do when the
 * backend has no ioctl.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "chardev/char.h"
#include "chardev/char-win.h"
#include "chardev/char-parallel.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/option.h"

static bool parallel_chr_open(Chardev *chr,
                              ChardevBackend *backend,
                              Error **errp)
{
    ChardevHostdev *parallel = backend->u.parallel.data;
    g_autofree char *path = NULL;
    g_autofree gunichar2 *wpath = NULL;
    HANDLE h;

    /* "LPT1" names the device, as "COM1" does for the serial port */
    if (g_ascii_strncasecmp(parallel->device, "LPT", 3) == 0 &&
        !strchr(parallel->device, '\\')) {
        path = g_strdup_printf("\\\\.\\%s", parallel->device);
    } else {
        path = g_strdup(parallel->device);
    }
    wpath = g_utf8_to_utf16(path, -1, NULL, NULL, NULL);
    if (!wpath) {
        error_setg(errp, "invalid path %s", parallel->device);
        return false;
    }
    h = CreateFileW(wpath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        error_setg_win32(errp, GetLastError(), "Failed CreateFile (%s)",
                         parallel->device);
        return false;
    }
    win_chr_set_file(chr, h, false);
    qemu_chr_be_event(chr, CHR_EVENT_OPENED);
    return true;
}

static void parallel_chr_parse(QemuOpts *opts, ChardevBackend *backend,
                               Error **errp)
{
    const char *device = qemu_opt_get(opts, "path");
    ChardevHostdev *parallel;

    if (device == NULL) {
        error_setg(errp, "chardev: parallel: no device path given");
        return;
    }
    backend->type = CHARDEV_BACKEND_KIND_PARALLEL;
    parallel = backend->u.parallel.data = g_new0(ChardevHostdev, 1);
    qemu_chr_parse_common(opts, qapi_ChardevHostdev_base(parallel));
    parallel->device = g_strdup(device);
}

static void char_parallel_class_init(ObjectClass *oc, const void *data)
{
    ChardevClass *cc = CHARDEV_CLASS(oc);

    cc->chr_parse = parallel_chr_parse;
    cc->chr_open = parallel_chr_open;
}

static const TypeInfo char_parallel_type_info = {
    .name = TYPE_CHARDEV_PARALLEL,
    .parent = TYPE_CHARDEV_WIN,
    .class_init = char_parallel_class_init,
};

static void register_types(void)
{
    type_register_static(&char_parallel_type_info);
}

type_init(register_types);
