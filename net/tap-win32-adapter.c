/*
 * TAP-Windows adapters: see tap-win32-adapter.h
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "tap-win32-adapter.h"

#include <winioctl.h>
#include <setupapi.h>
#include <devguid.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <objbase.h>
#include <netcon.h>

#define TAP_CLASS_KEY   L"SYSTEM\\CurrentControlSet\\Control\\Class\\" \
                        L"{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_NETWORK_KEY L"SYSTEM\\CurrentControlSet\\Control\\Network\\" \
                        L"{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_HWID        L"root\\tap0901"
#define TAP_IOCTL_SET_MEDIA_STATUS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

static const GUID tap_net_class = {
    0x4d36e972, 0xe325, 0x11ce, { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
};

static char *reg_string(HKEY key, const wchar_t *subkey, const wchar_t *value)
{
    wchar_t buf[512];
    DWORD size = sizeof(buf) - sizeof(wchar_t);
    DWORD type;
    HKEY k = key;
    LONG rc;

    if (subkey &&
        RegOpenKeyExW(key, subkey, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) {
        return NULL;
    }
    rc = RegQueryValueExW(k, value, NULL, &type, (BYTE *)buf, &size);
    if (subkey) {
        RegCloseKey(k);
    }
    if (rc != ERROR_SUCCESS || type != REG_SZ) {
        return NULL;
    }
    buf[size / sizeof(wchar_t)] = 0;
    return g_utf16_to_utf8((gunichar2 *)buf, -1, NULL, NULL, NULL);
}

static bool is_tap_component(const char *component)
{
    return component && (!g_ascii_strcasecmp(component, "tap0901") ||
                         !g_ascii_strcasecmp(component, "root\\tap0901"));
}

static char *connection_name(const char *guid)
{
    g_autofree char *path = g_strdup_printf("%ls\\%s\\Connection",
                                            TAP_NETWORK_KEY, guid);
    g_autofree gunichar2 *wpath = g_utf8_to_utf16(path, -1, NULL, NULL,
                                                  NULL);

    return wpath ? reg_string(HKEY_LOCAL_MACHINE, (wchar_t *)wpath, L"Name")
                 : NULL;
}

char *tap_win32_adapter_find(const char *name)
{
    HKEY cls;
    DWORD i;
    char *found = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, TAP_CLASS_KEY, 0,
                      KEY_ENUMERATE_SUB_KEYS, &cls) != ERROR_SUCCESS) {
        return NULL;
    }
    for (i = 0; !found; i++) {
        wchar_t sub[64];
        DWORD len = G_N_ELEMENTS(sub);
        g_autofree char *component = NULL;
        g_autofree char *id = NULL;
        g_autofree char *conn = NULL;

        if (RegEnumKeyExW(cls, i, sub, &len, NULL, NULL, NULL, NULL) !=
            ERROR_SUCCESS) {
            break;
        }
        component = reg_string(cls, sub, L"ComponentId");
        if (!is_tap_component(component)) {
            continue;
        }
        id = reg_string(cls, sub, L"NetCfgInstanceId");
        conn = id ? connection_name(id) : NULL;
        if (conn && (!strcmp(conn, name) || !g_ascii_strcasecmp(id, name))) {
            found = g_steal_pointer(&id);
        }
    }
    RegCloseKey(cls);
    return found;
}

/* Rename a connection as Explorer does (GUIDs in no MinGW library) */
static const GUID clsid_connection_manager = {
    0xba126ad1, 0x2166, 0x11d1, { 0xb1, 0xd0, 0x00, 0x80, 0x5f, 0xc1, 0x27, 0x0e }
};
static const GUID iid_connection_manager = {
    0xc08956a2, 0x1cd3, 0x11d1, { 0xb1, 0xc5, 0x00, 0x80, 0x5f, 0xc1, 0x27, 0x0e }
};

static int rename_connection(const GUID *id, const wchar_t *wname)
{
    INetConnectionManager *mgr = NULL;
    IEnumNetConnection *conns = NULL;
    INetConnection *conn = NULL;
    ULONG fetched;
    int ret = 0;

    if (FAILED(CoCreateInstance(&clsid_connection_manager, NULL, CLSCTX_ALL,
                                &iid_connection_manager, (void **)&mgr))) {
        return -1;
    }
    if (FAILED(mgr->lpVtbl->EnumConnections(mgr, NCME_DEFAULT, &conns))) {
        mgr->lpVtbl->Release(mgr);
        return -1;
    }
    while (!ret && conns->lpVtbl->Next(conns, 1, &conn, &fetched) == S_OK &&
           fetched == 1) {
        NETCON_PROPERTIES *props = NULL;

        if (SUCCEEDED(conn->lpVtbl->GetProperties(conn, &props)) && props) {
            if (IsEqualGUID(&props->guidId, id)) {
                ret = SUCCEEDED(conn->lpVtbl->Rename(conn, wname)) ? 1 : -1;
            }
            CoTaskMemFree(props->pszwName);
            CoTaskMemFree(props->pszwDeviceName);
            CoTaskMemFree(props);
        }
        conn->lpVtbl->Release(conn);
    }
    conns->lpVtbl->Release(conns);
    mgr->lpVtbl->Release(mgr);
    return ret;
}

typedef DWORD (WINAPI *NciSetConnectionNameFn)(const GUID *, const wchar_t *);

/* Name the adapter @guid once Windows has made its connection */
static bool set_connection_name(const char *guid, const char *name,
                                Error **errp)
{
    g_autofree gunichar2 *wguid = g_utf8_to_utf16(guid, -1, NULL, NULL, NULL);
    g_autofree gunichar2 *wname = g_utf8_to_utf16(name, -1, NULL, NULL, NULL);
    HMODULE nci = LoadLibraryExW(L"nci.dll", NULL,
                                 LOAD_LIBRARY_SEARCH_SYSTEM32);
    NciSetConnectionNameFn set_name = NULL;
    HRESULT init = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    GUID id;
    int i, rc = 0;

    if (nci) {
        set_name = (NciSetConnectionNameFn)(void (*)(void))
            GetProcAddress(nci, "NciSetConnectionName");
    }
    if (!wguid || !wname || FAILED(CLSIDFromString((LPCOLESTR)wguid, &id))) {
        rc = -1;
    }
    for (i = 0; i < 100 && rc == 0; i++) {
        if (set_name && set_name(&id, (wchar_t *)wname) == ERROR_SUCCESS) {
            rc = 1;
            break;
        }
        rc = rename_connection(&id, (wchar_t *)wname);
        if (rc != 1) {
            rc = 0;
            g_usleep(100 * 1000);
        }
    }
    if (SUCCEEDED(init)) {
        CoUninitialize();
    }
    if (nci) {
        FreeLibrary(nci);
    }
    if (rc != 1) {
        error_setg(errp, "cannot name the TAP adapter %s", name);
        return false;
    }
    return true;
}

static void win32_error(Error **errp, const char *what)
{
    DWORD err = GetLastError();

    error_setg_win32(errp, err, "%s%s", what,
                     err == ERROR_ACCESS_DENIED ?
                     " (TAP devices take administrator rights)" : "");
}

char *tap_win32_adapter_create(const char *name, char **name_out,
                               Error **errp)
{
    static const wchar_t hwid[] = TAP_HWID L"\0";
    HDEVINFO set;
    SP_DEVINFO_DATA dev = { .cbSize = sizeof(dev) };
    SP_DRVINFO_DATA_W drv = { .cbSize = sizeof(drv) };
    SP_DRVINFO_DATA_W best = { .cbSize = sizeof(best) };
    g_autofree char *chosen = NULL;
    char *guid = NULL;
    bool found = false, registered = false, ok = false;
    DWORD i;

    if (name) {
        g_autofree char *exists = tap_win32_adapter_find(name);

        if (exists) {
            error_setg(errp, "a TAP adapter named '%s' exists already", name);
            return NULL;
        }
        chosen = g_strdup(name);
    } else {
        for (i = 0; !chosen; i++) {
            g_autofree char *n = g_strdup_printf("tap%lu", (unsigned long)i);
            g_autofree char *exists = tap_win32_adapter_find(n);

            if (!exists) {
                chosen = g_steal_pointer(&n);
            }
        }
    }

    set = SetupDiCreateDeviceInfoList(&tap_net_class, NULL);
    if (set == INVALID_HANDLE_VALUE) {
        win32_error(errp, "cannot create a TAP device");
        return NULL;
    }
    if (!SetupDiCreateDeviceInfoW(set, L"Net", &tap_net_class, NULL, NULL,
                                  DICD_GENERATE_ID, &dev) ||
        !SetupDiSetDeviceRegistryPropertyW(set, &dev, SPDRP_HARDWAREID,
                                           (const BYTE *)hwid, sizeof(hwid))) {
        win32_error(errp, "cannot create a TAP device");
        goto out;
    }
    /* the newest TAP-Windows driver of the driver store */
    if (SetupDiBuildDriverInfoList(set, &dev, SPDIT_COMPATDRIVER)) {
        for (i = 0; SetupDiEnumDriverInfoW(set, &dev, SPDIT_COMPATDRIVER, i,
                                           &drv); i++) {
            if (!found || drv.DriverVersion > best.DriverVersion) {
                best = drv;
                found = true;
            }
        }
    }
    if (!found) {
        error_setg(errp, "TAP devices need the TAP-Windows6 driver in the "
                   "driver store (pnputil /add-driver OemVista.inf /install)");
        goto out;
    }
    if (!SetupDiSetSelectedDriverW(set, &dev, &best) ||
        !SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, &dev)) {
        win32_error(errp, "cannot create a TAP device");
        goto out;
    }
    registered = true;
    SetupDiCallClassInstaller(DIF_REGISTER_COINSTALLERS, set, &dev);
    SetupDiCallClassInstaller(DIF_INSTALLINTERFACES, set, &dev);
    if (!SetupDiCallClassInstaller(DIF_INSTALLDEVICE, set, &dev)) {
        win32_error(errp, "cannot install the TAP device");
        goto out;
    }
    for (i = 0; i < 50 && !guid; i++) {
        HKEY k = SetupDiOpenDevRegKey(set, &dev, DICS_FLAG_GLOBAL, 0,
                                      DIREG_DRV, KEY_QUERY_VALUE);

        if (k != INVALID_HANDLE_VALUE) {
            guid = reg_string(k, NULL, L"NetCfgInstanceId");
            RegCloseKey(k);
        }
        if (!guid) {
            g_usleep(100 * 1000);
        }
    }
    if (!guid) {
        error_setg(errp, "the TAP device got no network adapter");
        goto out;
    }
    if (!set_connection_name(guid, chosen, errp)) {
        goto out;
    }
    ok = true;
out:
    if (!ok) {
        if (registered) {
            SetupDiCallClassInstaller(DIF_REMOVE, set, &dev);
        }
        g_free(guid);
        guid = NULL;
    } else if (name_out) {
        *name_out = g_steal_pointer(&chosen);
    }
    SetupDiDestroyDeviceInfoList(set);
    return guid;
}

bool tap_win32_adapter_remove(const char *guid, Error **errp)
{
    HDEVINFO set = SetupDiGetClassDevsW(&tap_net_class, NULL, NULL, 0);
    SP_DEVINFO_DATA dev = { .cbSize = sizeof(dev) };
    bool ok = false;
    DWORD i;

    if (set == INVALID_HANDLE_VALUE) {
        win32_error(errp, "cannot delete the TAP device");
        return false;
    }
    for (i = 0; SetupDiEnumDeviceInfo(set, i, &dev); i++) {
        HKEY k = SetupDiOpenDevRegKey(set, &dev, DICS_FLAG_GLOBAL, 0,
                                      DIREG_DRV, KEY_QUERY_VALUE);
        g_autofree char *id = NULL;
        g_autofree char *component = NULL;

        if (k == INVALID_HANDLE_VALUE) {
            continue;
        }
        id = reg_string(k, NULL, L"NetCfgInstanceId");
        component = reg_string(k, NULL, L"ComponentId");
        RegCloseKey(k);
        if (!id || g_ascii_strcasecmp(id, guid) ||
            !is_tap_component(component)) {
            continue;
        }
        if (SetupDiCallClassInstaller(DIF_REMOVE, set, &dev)) {
            ok = true;
        } else {
            win32_error(errp, "cannot delete the TAP device");
        }
        break;
    }
    if (!ok && errp && !*errp) {
        error_setg(errp, "no TAP device for the adapter %s", guid);
    }
    SetupDiDestroyDeviceInfoList(set);
    return ok;
}

HANDLE tap_win32_adapter_open(const char *guid, Error **errp)
{
    g_autofree char *path = g_strdup_printf("\\\\.\\Global\\%s.tap", guid);
    ULONG status = TRUE;
    DWORD len;
    HANDLE h;

    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        error_setg_win32(errp, GetLastError(),
                         "cannot open the TAP device %s", guid);
        return NULL;
    }
    /* the link is up while QEMU uses the device */
    DeviceIoControl(h, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status),
                    &status, sizeof(status), &len, NULL);
    return h;
}

/* netsh names a bridge by the GUID of its adapter */
static char *bridge_guid(const char *bridge, Error **errp)
{
    g_autofree gunichar2 *alias = g_utf8_to_utf16(bridge, -1, NULL, NULL,
                                                  NULL);
    NET_LUID luid;
    GUID id;

    if (!alias ||
        ConvertInterfaceAliasToLuid((wchar_t *)alias, &luid) != NO_ERROR ||
        ConvertInterfaceLuidToGuid(&luid, &id) != NO_ERROR) {
        error_setg(errp, "no network bridge named '%s'", bridge);
        return NULL;
    }
    return g_strdup_printf("{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                           (unsigned long)id.Data1, id.Data2, id.Data3,
                           id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3],
                           id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
}

/* netsh bridge @verb "@ifname" @prep {bridge} */
static bool bridge_port(const char *bridge, const char *ifname,
                        const char *verb, const char *prep, Error **errp)
{
    g_autofree char *guid = bridge_guid(bridge, errp);
    g_autofree char *out = NULL;
    g_autofree char *err = NULL;
    g_autoptr(GError) gerr = NULL;
    const char *argv[] = { "netsh", "bridge", verb, ifname, prep, NULL, NULL };
    int status;

    if (!guid) {
        return false;
    }
    argv[5] = guid;
    if (!g_spawn_sync(NULL, (char **)argv, NULL, G_SPAWN_SEARCH_PATH, NULL,
                      NULL, &out, &err, &status, &gerr)) {
        error_setg(errp, "cannot run netsh: %s", gerr->message);
        return false;
    }
    if (!g_spawn_check_wait_status(status, NULL)) {
        error_setg(errp, "cannot %s %s %s bridge %s: %s", verb, ifname, prep,
                   bridge, g_strstrip(out ? out : (char *)""));
        return false;
    }
    return true;
}

bool tap_win32_bridge_add(const char *bridge, const char *ifname,
                          Error **errp)
{
    return bridge_port(bridge, ifname, "add", "to", errp);
}

bool tap_win32_bridge_remove(const char *bridge, const char *ifname,
                             Error **errp)
{
    return bridge_port(bridge, ifname, "remove", "from", errp);
}
