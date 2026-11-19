#!/bin/sh
# Build and test-sign the kernel drivers of qemu-win (MSYS2 UCRT64 shell).
#
#   sh windows/drivers/build.sh OUTDIR
#
# OUTDIR gets vhost-net.sys, vfio.sys and qemu-win-test.cer: the drivers,
# signed with a test certificate made here (Windows loads them in test
# mode: bcdedit /set testsigning on, the certificate in the Root and
# TrustedPublisher stores of the machine).  Test them in a virtual machine.
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?output directory}
mkdir -p "$out"
ddk=$(dirname "$(command -v gcc)")/../include/ddk
signtool=${SIGNTOOL:-"/c/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe"}

cflags="-O2 -Wall -Wno-unknown-pragmas -Wno-multichar -I$ddk
    -D_AMD64_ -DNTDDI_VERSION=0x0A000000 -D_WIN32_WINNT=0x0A00
    -fno-stack-protector -fno-asynchronous-unwind-tables -mno-stack-arg-probe"
ldflags="-shared -nostdlib -Wl,--subsystem,native -Wl,--entry,DriverEntry
    -Wl,--image-base,0x140000000 -Wl,--dynamicbase -Wl,--nxcompat
    -Wl,--high-entropy-va -Wl,--file-alignment,0x200
    -Wl,--section-alignment,0x1000 -Wl,--exclude-all-symbols"

# the PE checksum, which drivers must have
checksum() {
    python3 - "$1" <<'EOF'
import struct, sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
off = struct.unpack_from('<I', b, 0x3c)[0] + 24 + 64
struct.pack_into('<I', b, off, 0)
s = 0
for i in range(0, len(b) - len(b) % 2, 2):
    s += b[i] | (b[i + 1] << 8)
    s = (s & 0xffff) + (s >> 16)
if len(b) % 2:
    s += b[-1]
    s = (s & 0xffff) + (s >> 16)
s = (s & 0xffff) + (s >> 16)
struct.pack_into('<I', b, off, s + len(b))
open(p, 'wb').write(b)
EOF
}

# a test certificate for code signing, once
if [ ! -f "$out/qemu-win-test.pfx" ]; then
    w=$(cygpath -m "$out")
    MSYS2_ARG_CONV_EXCL='*' openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
        -subj "/CN=qemu-win test drivers" \
        -addext "extendedKeyUsage=codeSigning" \
        -addext "keyUsage=digitalSignature" \
        -keyout "$w/qemu-win-test.key" -out "$w/qemu-win-test.pem"
    openssl pkcs12 -export -passout pass:qemu-win -inkey "$out/qemu-win-test.key" \
        -in "$out/qemu-win-test.pem" -out "$out/qemu-win-test.pfx"
    openssl x509 -in "$out/qemu-win-test.pem" -outform der \
        -out "$out/qemu-win-test.cer"
fi

for drv in vhost-net vfio; do
    [ -f "$here/$drv/$drv.c" ] || continue
    gcc $cflags $ldflags -o "$out/$drv.sys" "$here/$drv/$drv.c" \
        -lntoskrnl -lhal -lgcc
    checksum "$out/$drv.sys"
    MSYS2_ARG_CONV_EXCL="*" "$signtool" sign /q /fd sha256 /f "$(cygpath -w "$out/qemu-win-test.pfx")" \
        /p qemu-win "$(cygpath -w "$out/$drv.sys")"
    echo "$out/$drv.sys"
done
