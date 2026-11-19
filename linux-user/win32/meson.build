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
  'thread.c',
))
linux_user_ss.add(when: 'TARGET_AARCH64', if_true: files('cpu_loop-aarch64.c'))
linux_user_ss.add(when: 'TARGET_X86_64', if_true: files('cpu_loop-x86_64.c'))

syscall_nr_generators = {}
foreach arch : ['aarch64', 'x86_64']
  syscall_nr_generators += {
    arch: generator(sh,
                    arguments: [ meson.current_source_dir() / '..' / arch / 'syscallhdr.sh',
                                 '@INPUT@', '@OUTPUT@', '@EXTRA_ARGS@' ],
                    output: '@BASENAME@_nr.h')
  }
endforeach

specific_ss.add_all(when: 'CONFIG_LINUX_USER', if_true: linux_user_ss)
