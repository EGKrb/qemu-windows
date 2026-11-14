#!/usr/bin/env python3
#
# Modules on Windows: the import library of the symbols of QEMU the modules
# use, for the DLL "qemu-host.exe" (the executable that loads a module, see
# module-common.c).
#
# Usage: win32-module-imports.py NM OBJDUMP DLLTOOL OUT.def OUT.a INPUT...
# An INPUT ending in .exe is an executable that loads modules, the others
# are the static libraries of the modules.
#
# Imported: the symbols a module leaves undefined that an executable exports
# (not those of the static runtime libraries, libgcc and others, that each
# DLL has its own copy of) or another module defines.  A symbol of data is
# imported as DATA (the module reaches it through its address in the
# import table), a function through a thunk.

import re
import subprocess
import sys


def symbols(nm, files):
    out = subprocess.run([nm, '-P', '-g'] + files, stdout=subprocess.PIPE,
                         check=True).stdout.decode('utf-8', 'replace')
    for line in out.splitlines():
        tokens = line.split()
        # "name type [value [size]]"; an archive member line ends with ':'
        if len(tokens) >= 2 and not tokens[0].endswith(':'):
            yield tokens[0], tokens[1]


def exports(objdump, exe):
    out = subprocess.run([objdump, '-p', exe], stdout=subprocess.PIPE,
                         check=True).stdout.decode('utf-8', 'replace')
    # "[Ordinal/Name Pointer] Table" lines: "[   0] +base[   1]  0000 name"
    names = set()
    for line in out.splitlines():
        m = re.match(r'\s*\[\s*\d+\]\s+\+base\[\s*\d+\]\s+[0-9a-fA-F]+\s+(\S+)',
                     line)
        if m:
            names.add(m.group(1))
    return names


def main(args):
    nm, objdump, dlltool, out_def, out_lib = args[:5]
    inputs = args[5:]
    exes = [f for f in inputs if f.lower().endswith('.exe')]
    libs = [f for f in inputs if not f.lower().endswith('.exe')]

    exported = set()
    for exe in exes:
        exported |= exports(objdump, exe)

    defined = {}
    undefined = set()
    for name, kind in symbols(nm, exes):
        if name in exported and kind in 'TDBRCV':
            defined.setdefault(name, kind != 'T')
    for name, kind in symbols(nm, libs):
        if kind == 'U':
            undefined.add(name)
        elif kind in 'TDBRCV':
            defined.setdefault(name, kind != 'T')

    with open(out_def, 'w') as f:
        f.write('LIBRARY qemu-host.exe\nEXPORTS\n')
        for name in sorted(undefined):
            if name in defined:
                f.write(name + (' DATA\n' if defined[name] else '\n'))

    subprocess.run([dlltool, '--input-def', out_def,
                    '--output-delaylib', out_lib], check=True)


if __name__ == '__main__':
    main(sys.argv[1:])
