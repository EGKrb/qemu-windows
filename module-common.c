#include "qemu/osdep.h"
#include "qemu/module.h"

void qemu_module_dummy(void)
{
}

void DSO_STAMP_FUN(void)
{
}

#ifdef _WIN32
/*
 * A module imports the symbols of QEMU from "qemu-host.exe", with delay-load
 * imports the Windows loader leaves alone (see meson.build).  Its entry point
 * binds them to the executable that loads it, through the resolver of
 * util/module.c, before the C runtime starts: the pseudo-relocations of the
 * runtime then see the right addresses, and the constructors the right
 * functions.  A symbol that is nowhere to be found fails the loading, as an
 * undefined symbol fails dlopen() on Linux.
 */
BOOL WINAPI DllMainCRTStartup(HANDLE inst, DWORD reason, LPVOID reserved);
BOOL WINAPI qemu_module_entry(HANDLE inst, DWORD reason, LPVOID reserved);

typedef void *(*QemuModuleResolve)(const char *name);

static bool qemu_module_bind(HANDLE inst)
{
    BYTE *base = (BYTE *)inst;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base +
                               ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    IMAGE_DELAYLOAD_DESCRIPTOR *d;
    QemuModuleResolve resolve;

    if (!dir->VirtualAddress) {
        return true;
    }
    resolve = (QemuModuleResolve)(void *)
        GetProcAddress(GetModuleHandleW(NULL), "qemu_module_resolve");
    if (!resolve) {
        return false;
    }
    for (d = (IMAGE_DELAYLOAD_DESCRIPTOR *)(base + dir->VirtualAddress);
         d->DllNameRVA; d++) {
        IMAGE_THUNK_DATA *names, *iat;

        if (_stricmp((const char *)(base + d->DllNameRVA), "qemu-host.exe")) {
            continue;
        }
        names = (IMAGE_THUNK_DATA *)(base + d->ImportNameTableRVA);
        iat = (IMAGE_THUNK_DATA *)(base + d->ImportAddressTableRVA);
        for (; names->u1.AddressOfData; names++, iat++) {
            IMAGE_IMPORT_BY_NAME *by_name;
            void *p;
            DWORD old;

            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) {
                return false;
            }
            by_name = (IMAGE_IMPORT_BY_NAME *)(base + names->u1.AddressOfData);
            p = resolve((const char *)by_name->Name);
            if (!p ||
                !VirtualProtect(iat, sizeof(*iat), PAGE_READWRITE, &old)) {
                return false;
            }
            iat->u1.Function = (ULONG_PTR)p;
            VirtualProtect(iat, sizeof(*iat), old, &old);
        }
    }
    return true;
}

BOOL WINAPI qemu_module_entry(HANDLE inst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH && !qemu_module_bind(inst)) {
        return FALSE;
    }
    return DllMainCRTStartup(inst, reason, reserved);
}
#endif
