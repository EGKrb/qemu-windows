executable('passt', files('passt.c'),
           dependencies: [qemuutil, slirp, vhost_user,
                          cc.find_library('iphlpapi')],
           install: true)
