# QEMU pour Windows (portage non officiel)

[English](README.md)

QEMU 11.1.90 compilé nativement pour Windows x64, avec les fonctions de QEMU
sous Linux portées sur Windows partout où Windows a un équivalent : invités
accélérés (WHPX), réseau TAP avec vhost-net, vhost-user, passt, virtio-9p,
memfd avec scellés, TPM (passthrough et émulation), pass-through SCSI,
modules en DLL, et les émulateurs Linux en mode utilisateur (`qemu-x86_64`,
`qemu-aarch64`) qui lancent des programmes Linux nativement, sans WSL. C'est
le code de QEMU dont les couches système ont été portées, pas une réécriture.

> [!IMPORTANT]
> **Pas une version officielle de QEMU**, et sans lien avec le projet QEMU.
> Les modifications pour Windows ont été écrites avec un assistant IA ; QEMU
> n'accepte pas de contributions contenant du contenu généré par IA
> ([docs/devel/code-provenance.rst](docs/devel/code-provenance.rst)), donc
> **rien ici n'est à proposer en amont**. Logiciel expérimental : à essayer
> sur des machines qu'on peut se permettre de casser, et le pilote noyau
> uniquement dans une machine virtuelle.

L'historique montre le portage comme un diff : le premier commit est QEMU
11.1.90 tel que téléchargé, les suivants sont le portage Windows.

## État

Testé sous Windows 11 (build 26300), avec des invités Alpine et Ubuntu en
TCG ; ce qui demande des droits administrateur ou un pilote (TAP, bridge
helper, SCSI, export FUSE, vhost-net, TPM passthrough) dans une machine
virtuelle Windows 11. [windows/STATUS.md](windows/STATUS.md) (en anglais)
liste chaque fonction, comment elle est faite sous Windows et ce qui reste.

| Domaine | Fait et testé |
| --- | --- |
| Accélérateurs | WHPX (`-accel kvm` le donne aussi), avec suivi des pages modifiées, migration à chaud, save/restore, instantanés ; TCG |
| Mémoire | `memory-backend-file`, `-memfd` (scellés appliqués par le noyau, pour tous les processus), `-shm`, `share=on` |
| Réseau | `-netdev tap` (création/nommage/suppression d'adaptateurs TAP-Windows, `script=`, `fd=`, `helper=`, `-netdev bridge` avec `qemu-bridge-helper`), `vhost=on` avec le pilote vhost-net ci-dessous, vhost-user, `-netdev passt` (avec `passt.exe` pour Windows), user, socket, stream |
| vhost-net | `windows/drivers/vhost-net` : un pilote noyau avec l'interface de `/dev/vhost-net` de Linux ; débit invité → hôte 5,4 fois celui de `vhost=off` dans les tests |
| Stockage | verrouillage des images, export FUSE (WinFsp), export vhost-user-blk, `scsi-block`/`scsi-generic` (SG_IO), `pr-manager-helper` avec `qemu-pr-helper`, pilotes curl, NFS et SSH |
| Périphériques | virtio-9p (tous les modèles de sécurité, métadonnées WSL), TPM : `tpm-passthrough` (TBS) et `tpm-emulator` (swtpm pour Windows), chardev `pty` (tubes nommés), ports série et parallèle |
| Processus | `-daemonize`, `-run-with exit-with-parent`, `-sandbox` |
| Modules | `--enable-modules` : modules en DLL, chargés par les exécutables (les 30 modules, `modules-test` passe) |
| linux-user | `qemu-x86_64`, `qemu-aarch64` : programmes Linux statiques et dynamiques (`-L` donne la racine de l'invité), threads, `fork`, `exec`, tubes, `poll`, signaux ; bash et les coreutils d'Ubuntu fonctionnent |
| Pas fait | vfio (demande une interface IOMMU que Windows ne donne pas), vhost-vdpa, AF_XDP, bsd-user |

## Compilation

Avec [MSYS2](https://www.msys2.org), dans son shell UCRT64 :

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-{toolchain,meson,ninja,glib2,pixman,libslirp,curl,libssh,libnfs,SDL2,gtk3,spice,python} git
mkdir build && cd build
../configure --disable-werror --disable-docs
ninja
```

- Modules en DLL : ajouter `--enable-modules`.
- Les émulateurs Linux en mode utilisateur, dans un build à part :
  `../configure --target-list=x86_64-linux-user,aarch64-linux-user --enable-linux-user --disable-system --disable-tools`.
- Le pilote vhost-net : `sh windows/drivers/build.sh DOSSIER` le compile avec
  MinGW et le signe avec un certificat de test qu'il crée ; Windows ne le
  charge qu'en mode test (`bcdedit /set testsigning on`, Secure Boot
  désactivé).

## Utilisation

La ligne de commande de QEMU est presque la même que sous Linux ; les chemins
et noms de Windows remplacent les fichiers de périphériques de Linux :

```sh
# un adaptateur TAP créé pour l'invité, avec vhost-net
qemu-system-x86_64 -accel whpx ... -netdev tap,id=n0,vhost=on -device virtio-net-pci,netdev=n0
# passt : l'invité a l'adresse, le DNS et le réseau local de l'hôte
qemu-system-x86_64 ... -netdev passt,id=n0 -device virtio-net-pci,netdev=n0
# le TPM de l'hôte
qemu-system-x86_64 ... -tpmdev passthrough,id=tpm0,path=tbs -device tpm-crb,tpmdev=tpm0
# un programme Linux, avec la racine d'un système Linux pour ses bibliothèques
qemu-x86_64 -L C:/racine-linux C:/racine-linux/bin/bash -c 'ls | wc -l'
```

## Organisation

| Chemin | Contenu |
| --- | --- |
| `windows/STATUS.md` | chaque fonction de Linux et son état sous Windows |
| `windows/drivers/` | le pilote vhost-net et son script de compilation |
| `windows/swtpm/`, `windows/winfsp/` | swtpm pour Windows ; en-têtes de WinFsp |
| `linux-user/win32/` | le frontal des émulateurs Linux en mode utilisateur sous Windows |
| `contrib/passt-win32/` | passt pour Windows |
| `util/*-win32.c`, `*-win32.c` | les équivalents Windows des couches POSIX de QEMU |

## Licence

Les licences de QEMU : GPL version 2 pour l'ensemble (voir [COPYING](COPYING)
et [LICENSE](LICENSE)) ; les ajouts pour Windows sont sous
GPL-2.0-or-later.
