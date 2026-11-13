# QEMU on Windows: what differs from Linux

Local port of QEMU 11.1.90 (from qemu-master) aiming at the features of QEMU
on Linux. Not an official QEMU build: the changes were written with an AI
assistant and, per QEMU's policy (`docs/devel/code-provenance.rst`), are not
to be submitted upstream.

Legend: **done** (in this tree, tested on Windows 11), **todo** (a Windows
counterpart exists, not done yet), **no** (needs a part of the Linux kernel
Windows does not have; what replaces it, if anything).

## Accelerators

| Linux | Windows |
| --- | --- |
| KVM | `-enable-kvm`, `-accel kvm`, `accel=kvm` and `query-kvm` give WHPX (Windows Hypervisor Platform), x86 only. Done here on top of upstream: dirty page tracking, live migration, save/restore, snapshots, Hyper-V MSRs and reference time migrated, memory balloon returning memory to the host |
| TCG | same |
| Xen, MSHV, Nitro | **no** |

## Memory

| Feature | Windows |
| --- | --- |
| `memory-backend-file`, `-mem-path` (file or directory) | **done**: file mappings (`CreateFileMapping`/`MapViewOfFile`); a directory gets a temporary file deleted on close; offsets in multiples of 64 KiB |
| `memory-backend-shm`, `memory-backend-ram,share=on`, `-machine aux-ram-share=on` | **done**: temporary delete-on-close file kept in cache |
| `memory-backend-memfd`, memfd seals | **done**: a delete-on-close file kept in cache; seals (`seal=on`, F_ADD_SEALS/F_GET_SEALS as `qemu_memfd_add_seals()`/`qemu_memfd_get_seals()`) are an extended attribute of the file, so every process that has it reads them; the kernel of Windows enforces them for every handle, for as long as the memfd exists: WRITE/FUTURE_WRITE = a shared lock of every byte, GROW = a shared lock past the end, SHRINK = a section (no truncation under a section or a view); locks and sections belong to a process, so `qemu-memfd-guard` (libexec), started on the first seal, holds them past the process that sealed and lets the memfd go when only guards have it (handle count against a count of guards kept in the file); a process that receives a sealed memfd enforces it too (a sender cannot unlock what it did not lock). mmap()/ftruncate() refuse what Linux refuses (EPERM, EBUSY). Test: `tests/unit/test-memfd-seals.c` (10, with a sealer that exits). The memfd ends up to 250 ms after its last descriptor (the guard polls). No huge pages |
| hugetlbfs, `guest-memfd`, `memory-backend-epc` (SGX) | **todo** (large pages need SeLockMemoryPrivilege) / **no** |
| `discard-data`, discard of file-backed RAM | **todo** |

## Character devices

| Backend | Windows |
| --- | --- |
| `pty` | **done**: a named pipe `\\.\pipe\qemu-pty-PID-N` (reported by `query-chardev`, like `/dev/pts/N`), no wait for a client, output dropped while none, next client taken; `path=` makes a symbolic link to it |
| `serial` | **done**: COM ports, now with the guest's line settings (speed, parity, bits, break, DTR/RTS, modem status) applied to the host's port as on Linux |
| `parallel` | **done**: `LPT1`... (data only: Windows gives no access to the registers, the device models emulate them) |
| `pipe`, `file`, `socket`, `udp`, `console`, `stdio`, ... | same as upstream |

## Block

| Feature | Windows |
| --- | --- |
| image locking (`locking=on|auto`) | **done**: the bytes of file-posix.c, locked with `LockFileEx` past 2^62 (Windows locks are mandatory); `qemu-img info` refuses an image in use, `-U` forces |
| `aio=native` (linux-aio), `io_uring` | Windows overlapped I/O (`aio=native`) as upstream; IoRing **todo** |
| FUSE export (`qemu-storage-daemon --export fuse`) | **done**, on WinFsp's native API (loaded at run time): `mountpoint` is a drive letter or a directory that does not exist (Windows file systems are not mounted over a file), which holds the image as one file named after the export id; `writable`, `growable`, `allow-other`. Tested in a Windows 11 VM with WinFsp (13 checks: directory and drive letter, read, write, read-only, growable, unmount) |
| vhost-user-blk export | **done** (`qemu-storage-daemon --export type=vhost-user-blk`, with `vhost-user-blk-pci`); VDUSE export **todo** |
| `host_device`, `host_cdrom` | `\\.\PhysicalDriveN`, `\\.\X:` as upstream |

## Process

| Option | Windows |
| --- | --- |
| `-daemonize` | **done**: QEMU starts itself again detached from the console; the first process exits 0 only when the daemon is initialized, as with the double fork |
| `-run-with exit-with-parent=on` | **done**: a thread waits on the parent process |
| `-run-with user=`, `chroot=`, `async-teardown=` | **no** (no setuid/chroot; teardown clone) |
| `-sandbox` | **done**: privileges removed from the token, mitigation policies, job object for `spawn=deny` and `resourcecontrol=deny` (no system call filter on Windows) |
| `rng-random` | **done**: `/dev/random` and `/dev/urandom` are the system generator, other files are read |

## Networking

| Backend | Windows |
| --- | --- |
| user (slirp), socket, stream, dgram, hubport | same |
| scsi-block, scsi-generic | **done** (VM test pending): SG_IO and the sg ioctls QEMU uses are IOCTL_SCSI_PASS_THROUGH_DIRECT and IOCTL_SCSI_GET_ADDRESS on `host_device` (`util/win32-sgio.c`, `include/scsi/sg-win32.h`); `\\.\PhysicalDriveN`, `\\.\CdRomN`, `\\.\TapeN`, `\\.\ChangerN` (tapes/changers are sg devices as /dev/sgN). Differences: no separate generic node on Windows (any pass-through device answers SG_GET_SCSI_ID); pass-through needs write access on Windows (not from root on Linux): a read-only device gets a second, read-write handle for SG_IO only (shared for reading, so nobody else writes), qemu-pr-helper gets the read-only one and refuses PR OUT on it as Linux does, PR IN on it = IOCTL_STORAGE_PERSISTENT_RESERVE_IN; qemu-pr-helper gives commands 30 s (Windows counts timeouts in seconds and resets the unit at expiry: 1 ms of upstream lost replies); administrator rights to open disks |
| tap, bridge | **done** (VM test pending): `ifname=` an adapter by name; no `ifname=` = a new adapter tapN, removed at the end (SetupAPI root\tap0901, `net/tap-win32-adapter.c`); `script=`/`downscript=` (.ps1/.bat/.cmd/.exe, default `etc\qemu-ifup`/`qemu-ifdown` with any of these extensions, `no`); `fd=`/`fds=` = an inherited handle number (overlapped); `helper=` and `-netdev bridge` = qemu-bridge-helper (handle sent over a socket pair). One queue: `queues>1`, `vnet_hdr=on` refused; `vhost=` needs the vhost-net driver (**todo**) |
| vhost-user | **done**: both ends of the AF_UNIX socket frame the stream and duplicate handles into the peer (`util/win32-fdpass.c`, as SCM_RIGHTS would pass descriptors); `contrib/vhost-user-bridge` ported (tested: ping through it) |
| vhost-net, vhost-vdpa, af-xdp, netmap, passt, l2tpv3, vde | **no** (Linux kernel or Linux-only programs) |
| `-netdev user,smb=` | **todo** |

## Devices and backends

| Feature | Windows |
| --- | --- |
| virtio-9p (`-virtfs`, `-fsdev local`) | **done**, every security model: the `*at()` functions on NT's relative opens (`NtCreateFile` with a root directory), POSIX renames and deletions (a file deleted while open, as on Linux), owner/mode/device as WSL keeps them (`$LXUID`, `$LXGID`, `$LXMOD`, `$LXDEV`), symbolic links, FIFOs, sockets and device nodes as WSL's reparse points (no privilege), extended attributes as NTFS EAs, names NTFS refuses mapped to U+F0xx as WSL and Cygwin do, directories made by the guest case sensitive |
| TPM (`tpm-tis`, `tpm-crb`...) | **done**, built. `tpm-passthrough`: the TPM of the host through the TPM Base Services (`path=tbs`), to be tested in a VM. `tpm-emulator`: **done** with swtpm for Windows (`windows/swtpm`: libtpms 0.10.1 built with MinGW, the `swtpm socket` command line and control protocol, state in `--tpmstate dir=`); tested: a Linux guest sees a TPM 2.0, TPM2_GetRandom, PCRs measured by the firmware |
| vfio, iommufd, vfio-user | **no** |
| `input-linux`, `can-host-socketcan`, `pr-manager-helper` | **no** / **no** / **done** (VM test pending): the handle of the device goes to qemu-pr-helper in a frame (`qio_channel_socket_set_handle_passing`) |
| `secret_keyring` | **todo** (Credential Manager) |

## Programs

| Program | Windows |
| --- | --- |
| qemu-system-*, qemu-img, qemu-io, qemu-nbd, qemu-storage-daemon, qemu-ga, elf2dmp | built |
| linux-user (`qemu-ARCH`) | **todo**: a native prototype for aarch64; otherwise through WSL |
| bsd-user | **no** |
| qemu-vnc | **done**: sockets given to QEMU as WSAPROTOCOL_INFOW (the Win32 D-Bus display API), Win32 map scanouts, AddClient; tested over a session bus |
| qemu-bridge-helper, qemu-pr-helper, qemu-vmsr-helper, vhost-user backends of contrib | **done** (`qemu-bridge-helper-win32.c`: bridge.conf ACL, makes a TAP adapter, `netsh bridge add`, sends its handle, removes it when QEMU ends; needs administrator rights) / **done** (VM test pending: `scsi/qemu-pr-helper.c`, SG_IO of Windows on the handle QEMU sends; `--daemon` = os-win32-daemon.c; no multipath: device-mapper is Linux) / **no** / vhost-user-bridge done, others **todo** |
| modules (`--enable-modules`) | **todo** (DLLs) |

## Tests of QEMU on Windows (qtests)

Built and run on Windows: virtio-9p (39), vhost-user-blk (6), TPM with the
emulator of the test and with swtpm (crb, tis, tis-device, tis-i2c, with
migration), `tests/unit/test-memfd-seals`.  To run them by hand from a
shell of MSYS2 or Git: `QTEST_QEMU_BINARY=./qemu-system-x86_64` (without
`.exe`: the architecture is read from the name), and `MSYS_NO_PATHCONV=1`
so that `-p /x86_64/...` reaches the program.  Windows differences handled
for them: single quotes of the command lines (sh) become double quotes;
a socket from accept() is blocking, as on POSIX (Windows inherits the
WSAEventSelect of the listener); a reset of an AF_UNIX peer that ended
reads as the end of the stream, as on Linux.

