# QEMU for Windows (unofficial port)

[Français](README.fr.md)

QEMU 11.1.90 built natively for Windows x64, with the features QEMU has on
Linux brought to Windows wherever Windows has a counterpart: accelerated
guests (WHPX), TAP networking with vhost-net, vhost-user, passt, virtio-9p,
memfd with seals, TPM passthrough and emulation, SCSI pass-through, modules as
DLLs, and the Linux user-mode emulators (`qemu-x86_64`, `qemu-aarch64`)
running Linux programs natively, without WSL. This is QEMU's own code with its
platform layers ported, not a rewrite.

> [!IMPORTANT]
> **Not an official QEMU release**, and not affiliated with the QEMU project.
> The Windows changes were written with an AI assistant; QEMU does not accept
> contributions that include AI-generated content
> ([docs/devel/code-provenance.rst](docs/devel/code-provenance.rst)), so
> **nothing here is to be submitted upstream**. Experimental software: try it
> on machines you can afford to break, and the kernel driver only in a
> virtual machine.

The history shows the port as a diff: the first commit is QEMU 11.1.90 as
downloaded, the next ones are the Windows port.

## Status

Tested on Windows 11 (build 26300), with Alpine and Ubuntu guests under TCG;
what needs administrator rights or a driver (TAP, bridge helper, SCSI, FUSE
export, vhost-net, TPM passthrough) in a Windows 11 virtual machine.
[windows/STATUS.md](windows/STATUS.md) lists every feature, how it is done on
Windows and what is left.

| Area | Done and tested |
| --- | --- |
| Accelerators | WHPX (`-accel kvm` gives it too), with dirty tracking, live migration, save/restore, snapshots; TCG |
| Memory | `memory-backend-file`, `-memfd` (seals enforced by the kernel, for every process), `-shm`, `share=on` |
| Networking | `-netdev tap` (create/name/remove TAP-Windows adapters, `script=`, `fd=`, `helper=`, `-netdev bridge` with `qemu-bridge-helper`), `vhost=on` with the vhost-net driver below, vhost-user, `-netdev passt` (with `passt.exe` for Windows), user, socket, stream |
| vhost-net | `windows/drivers/vhost-net`: a kernel driver with the interface of Linux's `/dev/vhost-net`; 5.4x the guest to host throughput of `vhost=off` in the tests |
| Storage | image locking, FUSE export (WinFsp), vhost-user-blk export, `scsi-block`/`scsi-generic` (SG_IO), `pr-manager-helper` with `qemu-pr-helper`, curl, NFS and SSH block drivers |
| Devices | virtio-9p (every security model, WSL metadata), TPM: `tpm-passthrough` (TBS) and `tpm-emulator` (swtpm for Windows), chardev `pty` (named pipes), serial and parallel ports |
| Processes | `-daemonize`, `-run-with exit-with-parent`, `-sandbox` |
| Modules | `--enable-modules`: modules as DLLs, loaded by the executables (all 30 modules, `modules-test` passes) |
| linux-user | `qemu-x86_64`, `qemu-aarch64`: static and dynamic Linux programs (`-L` gives the guest's root), threads, `fork`, `exec`, pipes, `poll`, signals; Ubuntu's bash and coreutils run |
| Not done | vfio (needs an IOMMU interface Windows does not give), vhost-vdpa, AF_XDP, bsd-user |

## Build

With [MSYS2](https://www.msys2.org) in its UCRT64 shell:

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-{toolchain,meson,ninja,glib2,pixman,libslirp,curl,libssh,libnfs,SDL2,gtk3,spice,python} git
mkdir build && cd build
../configure --disable-werror --disable-docs
ninja
```

- Modules as DLLs: add `--enable-modules`.
- The Linux user-mode emulators, in a build of their own:
  `../configure --target-list=x86_64-linux-user,aarch64-linux-user --enable-linux-user --disable-system --disable-tools`.
- The vhost-net driver: `sh windows/drivers/build.sh OUTDIR` builds it with
  MinGW and signs it with a test certificate it makes; Windows loads it in
  test mode only (`bcdedit /set testsigning on`, Secure Boot off).

## Use

Most of QEMU's command line is the same as on Linux; Windows paths and names
are taken where Linux has device files:

```sh
# a TAP adapter made for the guest, with vhost-net
qemu-system-x86_64 -accel whpx ... -netdev tap,id=n0,vhost=on -device virtio-net-pci,netdev=n0
# passt: the guest gets the host's address, DNS and LAN
qemu-system-x86_64 ... -netdev passt,id=n0 -device virtio-net-pci,netdev=n0
# the TPM of the host
qemu-system-x86_64 ... -tpmdev passthrough,id=tpm0,path=tbs -device tpm-crb,tpmdev=tpm0
# a Linux program, with the root of a Linux system for its libraries
qemu-x86_64 -L C:/linux-root C:/linux-root/bin/bash -c 'ls | wc -l'
```

## Layout

| Path | What |
| --- | --- |
| `windows/STATUS.md` | every Linux feature and its state on Windows |
| `windows/drivers/` | the vhost-net driver and its build script |
| `windows/swtpm/`, `windows/winfsp/` | swtpm for Windows; WinFsp headers |
| `linux-user/win32/` | the frontend of the Linux user-mode emulators on Windows |
| `contrib/passt-win32/` | passt for Windows |
| `util/*-win32.c`, `*-win32.c` | the Windows counterparts of QEMU's POSIX layers |

## License

QEMU's licenses: GPL version 2 for the whole (see [COPYING](COPYING) and
[LICENSE](LICENSE)); the Windows additions are under GPL-2.0-or-later.
