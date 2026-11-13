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
| KVM | **no**: WHPX (Windows Hypervisor Platform) instead, x86 only. Done here on top of upstream: dirty page tracking, live migration, save/restore, snapshots, Hyper-V MSRs and reference time migrated, memory balloon returning memory to the host |
| TCG | same |
| Xen, MSHV, Nitro | **no** |

## Memory

| Feature | Windows |
| --- | --- |
| `memory-backend-file`, `-mem-path` (file or directory) | **done**: file mappings (`CreateFileMapping`/`MapViewOfFile`); a directory gets a temporary file deleted on close; offsets in multiples of 64 KiB |
| `memory-backend-shm`, `memory-backend-ram,share=on`, `-machine aux-ram-share=on` | **done**: temporary delete-on-close file kept in cache |
| `memory-backend-memfd`, hugetlbfs, `guest-memfd`, `memory-backend-epc` (SGX) | **no** |
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
| FUSE export (`qemu-storage-daemon --export fuse`) | **todo** (WinFsp) |
| vhost-user-blk export, VDUSE export | **todo** / **no** |
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
| tap | TAP-Windows adapters (upstream); `vhost=`, `script=`, `helper=`, `fds=` **todo** |
| vhost-user | **todo** (needs passing handles over AF_UNIX) |
| vhost-net, vhost-vdpa, af-xdp, netmap, passt, l2tpv3, vde | **no** (Linux kernel or Linux-only programs) |
| `-netdev user,smb=` | **todo** |

## Devices and backends

| Feature | Windows |
| --- | --- |
| virtio-9p (`-virtfs`) | **todo** (NTFS, EAs for the mapped security models) |
| TPM (`tpm-emulator`, `tpm-passthrough`) | **todo** |
| vfio, iommufd, vfio-user | **no** |
| `input-linux`, `can-host-socketcan`, `pr-manager-helper` | **no** / **no** / **todo** (SCSI pass-through) |
| `secret_keyring` | **todo** (Credential Manager) |

## Programs

| Program | Windows |
| --- | --- |
| qemu-system-*, qemu-img, qemu-io, qemu-nbd, qemu-storage-daemon, qemu-ga, elf2dmp | built |
| linux-user (`qemu-ARCH`) | **todo**: a native prototype for aarch64; otherwise through WSL |
| bsd-user | **no** |
| qemu-bridge-helper, qemu-pr-helper, qemu-vmsr-helper, qemu-vnc, vhost-user backends of contrib | **todo** / **todo** / **no** / **todo** / **todo** |
| modules (`--enable-modules`) | **todo** (DLLs) |
