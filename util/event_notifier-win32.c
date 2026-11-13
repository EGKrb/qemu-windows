/*
 * event notifier support
 *
 * Copyright Red Hat, Inc. 2010
 *
 * Authors:
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/event_notifier.h"
#include "qemu/main-loop.h"
#include "qemu/win32-fdpass.h"

int event_notifier_init(EventNotifier *e, int active)
{
    e->event = CreateEvent(NULL, TRUE, FALSE, NULL);
    assert(e->event);
    return 0;
}

void event_notifier_cleanup(EventNotifier *e)
{
    CloseHandle(e->event);
    e->event = NULL;
}

HANDLE event_notifier_get_handle(EventNotifier *e)
{
    return e->event;
}

void event_notifier_init_fd(EventNotifier *e, int fd)
{
    e->event = w32fd_token_handle(fd);
}

int event_notifier_get_fd(const EventNotifier *e)
{
    return w32fd_handle_token(e->event);
}

int event_notifier_get_wfd(const EventNotifier *e)
{
    return w32fd_handle_token(e->event);
}

bool event_notifier_initialized(const EventNotifier *e)
{
    return e->event != NULL;
}

int event_notifier_set(EventNotifier *e)
{
    SetEvent(e->event);
    return 0;
}

int event_notifier_test_and_clear(EventNotifier *e)
{
    int ret = WaitForSingleObject(e->event, 0);
    if (ret == WAIT_OBJECT_0) {
        ResetEvent(e->event);
        return true;
    }
    return false;
}
