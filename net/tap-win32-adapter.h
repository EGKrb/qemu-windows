/*
 * TAP-Windows adapters: create, name, find, remove, bridge
 *
 * The TAP devices of Windows are adapters of the TAP-Windows6 driver of
 * OpenVPN (hardware id root\tap0901).  Creating and removing them, and
 * adding them to a network bridge, take administrator rights (as creating
 * a TAP device and changing a bridge take CAP_NET_ADMIN on Linux).
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef NET_TAP_WIN32_ADAPTER_H
#define NET_TAP_WIN32_ADAPTER_H

/* The GUID of the TAP adapter whose connection is named @name, or NULL */
char *tap_win32_adapter_find(const char *name);

/*
 * A new TAP adapter: its GUID; named @name, or the first free tapN
 * (returned in *@name_out)
 */
char *tap_win32_adapter_create(const char *name, char **name_out,
                               Error **errp);

/* Remove the TAP adapter @guid */
bool tap_win32_adapter_remove(const char *guid, Error **errp);

/* Open the TAP device @guid for I/O (overlapped) */
HANDLE tap_win32_adapter_open(const char *guid, Error **errp);

/* Add the adapter named @ifname to the network bridge named @bridge */
bool tap_win32_bridge_add(const char *bridge, const char *ifname,
                          Error **errp);
bool tap_win32_bridge_remove(const char *bridge, const char *ifname,
                             Error **errp);

#endif
