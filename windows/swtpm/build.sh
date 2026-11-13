#!/bin/sh
# swtpm for Windows: libtpms 0.10.1 (TPM 2.0 only) and swtpm-win.c.
# From an MSYS2 UCRT64 shell (packages: autotools, openssl, libsystre):
#
#   windows/swtpm/build.sh LIBTPMS_SOURCE_DIR PREFIX OUTPUT_DIR
#
# LIBTPMS_SOURCE_DIR: an extracted libtpms-0.10.1 tarball
# (https://github.com/stefanberger/libtpms), patched here for MinGW.
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -e
here=$(cd "$(dirname "$0")" && pwd)
src=$1
prefix=$2
out=$3
[ -d "$src" ] && [ -n "$prefix" ] && [ -n "$out" ] || {
    echo "usage: $0 LIBTPMS_SOURCE_DIR PREFIX OUTPUT_DIR" >&2
    exit 2
}

cd "$src"
if ! grep -q '__MINGW32__' src/tpm2/simulator_sysheaders.h; then
    patch -p1 < "$here/libtpms-0.10.1-mingw.patch"
fi
[ -f configure ] || NOCONFIGURE=1 ./autogen.sh
CPPFLAGS="-I$here/shim -include $here/shim/w32shim.h -D__USE_MINGW_ANSI_STDIO=1" \
CFLAGS="-O2 -g -Wno-error" LIBS="-lws2_32" \
    ./configure --prefix="$prefix" --with-openssl --with-tpm2 --without-tpm1 \
                --disable-static --enable-shared
make -j"$(nproc)"
make install

mkdir -p "$out"
gcc -O2 -g -Wall -Wno-incompatible-pointer-types \
    -I"$prefix/include" -I"$here/../../include" \
    -o "$out/swtpm.exe" "$here/swtpm-win.c" "$here/../../util/win32-fdpass.c" \
    "$prefix/lib/libtpms.a" -lcrypto -lsystre -lws2_32
echo "$out/swtpm.exe"
