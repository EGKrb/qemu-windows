/*
 * The POSIX file API of 9p on Windows
 *
 * 9p-local.c works with the *at() functions of POSIX on directory file
 * descriptors.  On Windows the descriptors of the C runtime wrap handles
 * opened with the native API of NT: NtCreateFile() opens names relative
 * to a directory handle (OBJECT_ATTRIBUTES.RootDirectory), which is what
 * openat() does, and renames and deletions use the POSIX semantics of NT.
 *
 * Linux metadata are kept as WSL keeps them, so that both see the same
 * files: owner, group, mode and device number in the extended attributes
 * $LXUID, $LXGID, $LXMOD and $LXDEV; symbolic links, FIFOs, sockets and
 * device nodes as the reparse points of WSL (no privilege needed).
 * Characters NTFS does not take in names (\ : * ? " < > | and controls)
 * are mapped to U+F000 + character, as WSL and Cygwin do.
 *
 * The types and constants are those of Linux, which the 9p protocol
 * carries: this header is only for the code of 9p and fsdev.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_9P_WIN32_H
#define QEMU_9P_WIN32_H

#include <sys/stat.h>
#include <dirent.h>
#include <sys/utime.h>

/* Linux types: MinGW's mode_t is 16 bits, dev_t 32 bits */
typedef uint32_t p9_uid_t;
typedef uint32_t p9_gid_t;
typedef uint32_t p9_mode_t;
typedef uint64_t p9_dev_t;
typedef uint64_t p9_ino_t;
typedef uint64_t p9_nlink_t;
#define uid_t p9_uid_t
#define gid_t p9_gid_t
#define mode_t p9_mode_t
#define dev_t p9_dev_t
#define ino_t p9_ino_t
#define nlink_t p9_nlink_t

struct p9_stat {
    dev_t st_dev;
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    dev_t st_rdev;
    int64_t st_size;
    int64_t st_blksize;
    int64_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
};
/*
 * The 9p server sees files through struct p9_stat; a 9p client (the
 * qtests) includes the headers for the protocol and keeps the stat() of
 * the C runtime: it defines P9_WIN32_CLIENT
 */
#ifndef P9_WIN32_CLIENT
#undef stat
#undef fstat
#undef lstat
#define stat p9_stat
#define fstat p9_fstat
#define lstat p9_lstat
#define st_atime st_atim.tv_sec
#define st_mtime st_mtim.tv_sec
#define st_ctime st_ctim.tv_sec
#endif

int p9_fstat(int fd, struct p9_stat *st);
int p9_lstat(const char *path, struct p9_stat *st);

/* the file types and modes of Linux */
#undef S_IFMT
#undef S_IFIFO
#undef S_IFCHR
#undef S_IFDIR
#undef S_IFBLK
#undef S_IFREG
#undef S_IFLNK
#undef S_IFSOCK
#undef S_ISFIFO
#undef S_ISCHR
#undef S_ISDIR
#undef S_ISBLK
#undef S_ISREG
#undef S_ISLNK
#undef S_ISSOCK
#define S_IFMT   0170000
#define S_IFIFO  0010000
#define S_IFCHR  0020000
#define S_IFDIR  0040000
#define S_IFBLK  0060000
#define S_IFREG  0100000
#define S_IFLNK  0120000
#define S_IFSOCK 0140000
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#ifndef S_ISUID
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000
#endif
#undef S_IRWXU
#undef S_IRUSR
#undef S_IWUSR
#undef S_IXUSR
#undef S_IRWXG
#undef S_IRGRP
#undef S_IWGRP
#undef S_IXGRP
#undef S_IRWXO
#undef S_IROTH
#undef S_IWOTH
#undef S_IXOTH
#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100
#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010
#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

#define makedev(maj, min)     ((((uint64_t)(maj) & 0x00000fffu) << 8) |      (((uint64_t)(maj) & 0xfffff000u) << 32) |      (((uint64_t)(min) & 0x000000ffu) << 0) |      (((uint64_t)(min) & 0xffffff00u) << 12))
#define major(dev) ((uint32_t)(((dev) >> 8) & 0xfff) | \
                    (uint32_t)(((dev) >> 32) & 0xfffff000))
#define minor(dev) ((uint32_t)((dev) & 0xff) | \
                    (uint32_t)(((dev) >> 12) & 0xffffff00))

/* open() flags MinGW does not have, in bits it does not use */
#define O_DIRECTORY 0x01000000
#define O_NOFOLLOW  0x02000000
#define O_NOCTTY    0
#define O_NONBLOCK  0x04000000
#define O_NOATIME   0x08000000
#define O_DIRECT    0x10000000
#define O_SYNC      0x20000000
#define O_DSYNC     O_SYNC
#define O_ASYNC     0
#define FASYNC      O_ASYNC
#ifndef O_CLOEXEC
#define O_CLOEXEC   0
#endif

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#define F_GETFL 3
#define F_SETFL 4
int p9_fcntl(int fd, int cmd, ...);
#define fcntl p9_fcntl

#define AT_FDCWD            -100
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR        0x200
#define AT_EMPTY_PATH       0x1000

#define UTIME_NOW  ((1l << 30) - 1l)
#define UTIME_OMIT ((1l << 30) - 2l)

#define XATTR_CREATE  0x1
#define XATTR_REPLACE 0x2

/* errno values of Linux that MinGW does not have */
#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

int openat(int dirfd, const char *name, int flags, ...);
int fstatat(int dirfd, const char *name, struct p9_stat *st, int flags);
int mkdirat(int dirfd, const char *name, mode_t mode);
int renameat(int olddirfd, const char *oldname,
             int newdirfd, const char *newname);
int unlinkat(int dirfd, const char *name, int flags);
int linkat(int olddirfd, const char *oldname,
           int newdirfd, const char *newname, int flags);
int symlinkat(const char *target, int dirfd, const char *name);
ssize_t readlinkat(int dirfd, const char *name, char *buf, size_t size);
int fchmodat(int dirfd, const char *name, mode_t mode, int flags);
int fchownat(int dirfd, const char *name, uid_t uid, gid_t gid, int flags);
int fchmod(int fd, mode_t mode);
int fchown(int fd, uid_t uid, gid_t gid);
int utimensat(int dirfd, const char *name, const struct timespec times[2],
              int flags);
int futimens(int fd, const struct timespec times[2]);
int p9_fsync(int fd);
#undef fsync
#define fsync p9_fsync
ssize_t p9_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t p9_pwritev(int fd, const struct iovec *iov, int iovcnt,
                   off_t offset);

struct statfs {
    uint32_t f_type;
    uint64_t f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    struct { int32_t __val[2]; } f_fsid;
    uint64_t f_namelen;
};
int fstatfs(int fd, struct statfs *buf);

ssize_t fgetxattr(int fd, const char *name, void *value, size_t size);
int fsetxattr(int fd, const char *name, const void *value, size_t size,
              int flags);
ssize_t flistxattr(int fd, char *list, size_t size);
int fremovexattr(int fd, const char *name);

/* directories: readdir() of NT, with "." and ".." and stable offsets */
#define DT_UNKNOWN 0
#define DT_FIFO    1
#define DT_CHR     2
#define DT_DIR     4
#define DT_BLK     6
#define DT_REG     8
#define DT_LNK     10
#define DT_SOCK    12

struct p9_dirent {
    ino_t d_ino;
    off_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[256 * 4];
};
#define dirent p9_dirent
#define _DIRENT_HAVE_D_RECLEN

typedef struct P9Dir P9Dir;
#define DIR P9Dir
#undef opendir
#undef readdir
#undef closedir
#undef rewinddir
#undef telldir
#undef seekdir
#define readdir p9_readdir
#define closedir p9_closedir
#define rewinddir p9_rewinddir
#define telldir p9_telldir
#define seekdir p9_seekdir
#define dirfd p9_dirfd
P9Dir *fdopendir(int fd);
struct p9_dirent *p9_readdir(P9Dir *dir);
int p9_closedir(P9Dir *dir);
void p9_rewinddir(P9Dir *dir);
long p9_telldir(P9Dir *dir);
void p9_seekdir(P9Dir *dir, long off);
int p9_dirfd(P9Dir *dir);

#endif
