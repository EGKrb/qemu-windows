block_ss.add(files('utils.c'))
if host_os == 'linux' or host_os == 'windows'
  block_ss.add(files('pr-manager.c', 'pr-manager-helper.c'))
else
  block_ss.add(files('pr-manager-stub.c'))
endif
