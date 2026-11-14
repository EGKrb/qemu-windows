# Native Win32 linux-user prototype: runs static Linux ELF binaries on
# Windows without WSL, on top of VirtualAlloc/VirtualProtect and a
# vectored exception handler instead of mmap/mprotect and signals.

linux_user_ss.add(files(
  'elf.c',
  'fault.c',
  'main.c',
  'mem.c',
  'stubs.c',
  'syscall.c',
))
linux_user_ss.add(when: 'TARGET_AARCH64', if_true: files('cpu_loop-aarch64.c'))

syscall_nr_generators = {
  'aarch64': generator(sh,
                      arguments: [ meson.current_source_dir() / '../aarch64/syscallhdr.sh',
                                   '@INPUT@', '@OUTPUT@', '@EXTRA_ARGS@' ],
                      output: '@BASENAME@_nr.h')
}

specific_ss.add_all(when: 'CONFIG_LINUX_USER', if_true: linux_user_ss)
