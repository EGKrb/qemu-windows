if have_tpm
  system_ss.add(files('tpm_backend.c'))
  system_ss.add(files('tpm_util.c'))
  if host_os == 'windows'
    # the TPM Base Services of Windows, for tpm-passthrough
    system_ss.add(cc.find_library('tbs'))
  endif
  system_ss.add(when: 'CONFIG_TPM_PASSTHROUGH', if_true: files('tpm_passthrough.c'))
  system_ss.add(when: 'CONFIG_TPM_EMULATOR', if_true: files('tpm_emulator.c'))
endif
