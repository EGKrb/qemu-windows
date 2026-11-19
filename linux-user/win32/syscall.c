/*
 * Native Win32 linux-user prototype: Linux system calls
 *
 * The subset of the asm-generic syscall ABI that static executables use,
 * on top of the C runtime and the Win32 API: file descriptors, paths,
 * stat, directories, memory, time and process identity.  There is a
 * single guest thread: clone, execve and wait fail, signals only take
 * their default (fatal) action, and futex covers the uncontended cases.
 *
 * Guest paths: "/c/..." and "/mnt/c/..." name drive C:, "/tmp" is the
 * Windows temporary directory, "/proc/self/exe" and "/dev/null" are
 * emulated; other paths are given to Windows as they are.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <io.h>
#include "qemu/bswap.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/guest-random.h"
#include "qemu/log.h"
#include "qemu/timer.h"
#include "exec/page-protection.h"
#include "user/guest-host.h"
#include "user/page-protection.h"
#include "syscall_nr.h"
#include "win32-user.h"

/* Linux asm-generic ABI values (arm64 variant for the O_* flags) */
#define LX_AT_FDCWD             -100
#define LX_AT_SYMLINK_NOFOLLOW  0x100
#define LX_AT_REMOVEDIR         0x200
#define LX_AT_EMPTY_PATH        0x1000

#define LX_O_ACCMODE    03
#define LX_O_RDONLY     00
#define LX_O_WRONLY     01
#define LX_O_RDWR       02
#define LX_O_CREAT      0100
#define LX_O_EXCL       0200
#define LX_O_TRUNC      01000
#define LX_O_APPEND     02000
#define LX_O_NONBLOCK   04000
#define LX_O_DIRECTORY  040000
#define LX_O_CLOEXEC    02000000

#define LX_F_DUPFD          0
#define LX_F_GETFD          1
#define LX_F_SETFD          2
#define LX_F_GETFL          3
#define LX_F_SETFL          4
#define LX_F_GETLK          5
#define LX_F_SETLK          6
#define LX_F_SETLKW         7
#define LX_F_DUPFD_CLOEXEC  1030
#define LX_FD_CLOEXEC       1
#define LX_F_UNLCK          2

#define LX_TCGETS       0x5401
#define LX_TCSETS       0x5402
#define LX_TCSETSW      0x5403
#define LX_TCSETSF      0x5404
#define LX_TIOCGPGRP    0x540f
#define LX_TIOCGWINSZ   0x5413
#define LX_FIONBIO      0x5421

#define LX_S_IFIFO      0010000
#define LX_S_IFCHR      0020000
#define LX_S_IFDIR      0040000
#define LX_S_IFREG      0100000

#define LX_DT_DIR       4
#define LX_DT_REG       8

#define LX_MAP_ANONYMOUS    0x20
#define LX_MADV_DONTNEED    4

#define LX_FUTEX_WAIT           0
#define LX_FUTEX_WAKE           1
#define LX_FUTEX_WAIT_BITSET    9
#define LX_FUTEX_WAKE_BITSET    10
#define LX_FUTEX_CLOCK_REALTIME 256
#define LX_FUTEX_CMD_MASK       0x7f

#define LX_CLOCK_REALTIME           0
#define LX_CLOCK_MONOTONIC          1
#define LX_CLOCK_PROCESS_CPUTIME_ID 2
#define LX_CLOCK_THREAD_CPUTIME_ID  3
#define LX_CLOCK_MONOTONIC_RAW      4
#define LX_CLOCK_REALTIME_COARSE    5
#define LX_CLOCK_MONOTONIC_COARSE   6
#define LX_CLOCK_BOOTTIME           7
#define LX_TIMER_ABSTIME            1

#define LX_RLIMIT_STACK     3
#define LX_RLIMIT_NOFILE    7
#define LX_RLIM_INFINITY    (~0ULL)

#define LX_PR_SET_NAME      15
#define LX_PR_GET_NAME      16

#define LX_UTIME_NOW        ((1L << 30) - 1)
#define LX_UTIME_OMIT       ((1L << 30) - 2)

#define LX_STATX_BASIC_STATS    0x7ff
#define LX_STATX_BTIME          0x800

#define LX_RENAME_NOREPLACE 1

#define LX_SIGKILL  9
#define LX_SIGSTOP  19
#define LX_NSIG     64

/* Largest transfer of a single read/write, as on Linux */
#define LX_MAX_RW_COUNT     0x7ffff000
#define LX_IOV_MAX          1024

#define W32U_MAX_FDS        1024
#define W32U_UID            1000
/* 100 ns intervals between 1601-01-01 and 1970-01-01 */
#define FILETIME_UNIX_EPOCH 116444736000000000ULL

#ifdef TARGET_X86_64
/* the struct stat of x86_64 */
struct lx_stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t pad0;
    uint64_t st_rdev;
    int64_t st_size;
    int64_t st_blksize;
    int64_t st_blocks;
    int64_t st_atime_sec;
    uint64_t st_atime_nsec;
    int64_t st_mtime_sec;
    uint64_t st_mtime_nsec;
    int64_t st_ctime_sec;
    uint64_t st_ctime_nsec;
    int64_t unused[3];
};
QEMU_BUILD_BUG_ON(sizeof(struct lx_stat) != 144);
#else
struct lx_stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint64_t pad1;
    int64_t st_size;
    int32_t st_blksize;
    int32_t pad2;
    int64_t st_blocks;
    int64_t st_atime_sec;
    uint64_t st_atime_nsec;
    int64_t st_mtime_sec;
    uint64_t st_mtime_nsec;
    int64_t st_ctime_sec;
    uint64_t st_ctime_nsec;
    uint32_t unused[2];
};
QEMU_BUILD_BUG_ON(sizeof(struct lx_stat) != 128);
#endif

struct lx_statx_timestamp {
    int64_t tv_sec;
    uint32_t tv_nsec;
    int32_t pad;
};

struct lx_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t pad1;
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct lx_statx_timestamp stx_atime;
    struct lx_statx_timestamp stx_btime;
    struct lx_statx_timestamp stx_ctime;
    struct lx_statx_timestamp stx_mtime;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t spare[14];
};
QEMU_BUILD_BUG_ON(sizeof(struct lx_statx) != 256);

struct lx_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

struct lx_timeval {
    int64_t tv_sec;
    int64_t tv_usec;
};

struct lx_iovec {
    uint64_t iov_base;
    uint64_t iov_len;
};

struct lx_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct lx_rlimit {
    uint64_t rlim_cur;
    uint64_t rlim_max;
};

struct lx_rusage {
    struct lx_timeval ru_utime;
    struct lx_timeval ru_stime;
    int64_t ru_other[14];
};

struct lx_tms {
    int64_t tms_utime;
    int64_t tms_stime;
    int64_t tms_cutime;
    int64_t tms_cstime;
};

struct lx_sysinfo {
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram;
    uint64_t freeram;
    uint64_t sharedram;
    uint64_t bufferram;
    uint64_t totalswap;
    uint64_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint32_t pad2;
    uint64_t totalhigh;
    uint64_t freehigh;
    uint32_t mem_unit;
    uint32_t pad3;
};
QEMU_BUILD_BUG_ON(sizeof(struct lx_sysinfo) != 112);

struct lx_termios {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
};

struct lx_winsize {
    uint16_t ws_row;
    uint16_t ws_col;
    uint16_t ws_xpixel;
    uint16_t ws_ypixel;
};

typedef enum { FD_FREE, FD_HOST, FD_DIR } GuestFDKind;

typedef struct DirEnt {
    char *name;
    uint8_t type;
} DirEnt;

typedef struct GuestFD {
    GuestFDKind kind;
    int host;           /* FD_HOST: C runtime descriptor */
    int flags;          /* Linux O_ACCMODE and status flags */
    bool cloexec;
    char *path;         /* host path; NULL for the inherited stdio */
    GArray *dents;      /* FD_DIR: entries, listed by the first getdents64 */
    guint pos;          /* FD_DIR: index of the next entry */
} GuestFD;

typedef struct HostStat {
    uint32_t mode;
    uint32_t nlink;
    uint64_t dev;
    uint64_t rdev;
    uint64_t ino;
    int64_t size;
    int64_t atime_ns;
    int64_t mtime_ns;
    int64_t ctime_ns;
    int64_t btime_ns;
} HostStat;

static GuestFD fds[W32U_MAX_FDS];
static char *exec_host_path;
static uint32_t guest_umask = 022;
static char task_name[16];
static UINT saved_console_cp;

#define N(x) [TARGET_NR_##x] = #x
static const char *const syscall_names[] = {
    N(getcwd), N(dup), N(dup3), N(fcntl), N(ioctl), N(mkdirat), N(unlinkat),
    N(renameat), N(ftruncate), N(faccessat), N(chdir), N(fchdir), N(fchmod),
    N(fchmodat), N(fchownat), N(fchown), N(openat), N(close), N(pipe2),
    N(getdents64), N(lseek), N(read), N(write), N(readv), N(writev),
    N(pread64), N(pwrite64), N(readlinkat), N(newfstatat), N(fstat),
    N(fsync), N(fdatasync), N(utimensat), N(exit), N(exit_group),
    N(set_tid_address), N(futex), N(set_robust_list), N(nanosleep),
    N(clock_gettime), N(clock_getres), N(clock_nanosleep),
    N(sched_getaffinity), N(sched_yield), N(kill), N(tkill), N(tgkill),
    N(sigaltstack), N(rt_sigaction), N(rt_sigprocmask), N(times),
    N(setpgid), N(getpgid), N(getsid), N(setsid), N(uname), N(getrlimit),
    N(setrlimit), N(getrusage), N(umask), N(prctl), N(getcpu),
    N(gettimeofday), N(getpid), N(getppid), N(getuid), N(geteuid),
    N(getgid), N(getegid), N(gettid), N(sysinfo), N(brk), N(munmap),
    N(mremap), N(clone), N(execve), N(mmap), N(fadvise64), N(mprotect),
    N(msync), N(mlock), N(munlock), N(madvise), N(wait4), N(prlimit64),
    N(renameat2), N(getrandom), N(statx), N(rseq), N(clone3),
    N(faccessat2),
};
#undef N

/* Errors */

static int lx_errno(int e)
{
    /* the C runtime values only match Linux up to ERANGE */
    switch (e) {
    case EDEADLK:
        return LX_EDEADLK;
    case ENAMETOOLONG:
        return LX_ENAMETOOLONG;
    case ENOLCK:
        return LX_ENOLCK;
    case ENOSYS:
        return LX_ENOSYS;
    case ENOTEMPTY:
        return LX_ENOTEMPTY;
    case EILSEQ:
        return LX_EILSEQ;
    default:
        return e > 0 && e <= LX_ERANGE ? e : LX_EIO;
    }
}

static int lx_win_error(DWORD err)
{
    switch (err) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
    case ERROR_INVALID_DRIVE:
    case ERROR_BAD_NETPATH:
    case ERROR_BAD_PATHNAME:
        return LX_ENOENT;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
    case ERROR_WRITE_PROTECT:
        return LX_EACCES;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        return LX_EEXIST;
    case ERROR_DIR_NOT_EMPTY:
        return LX_ENOTEMPTY;
    case ERROR_DIRECTORY:
        return LX_ENOTDIR;
    case ERROR_FILENAME_EXCED_RANGE:
        return LX_ENAMETOOLONG;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
        return LX_ENOSPC;
    case ERROR_NOT_SAME_DEVICE:
        return LX_EXDEV;
    case ERROR_BROKEN_PIPE:
    case ERROR_NO_DATA:
        return LX_EPIPE;
    case ERROR_INVALID_HANDLE:
        return LX_EBADF;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        return LX_ENOMEM;
    case ERROR_NEGATIVE_SEEK:
    case ERROR_INVALID_PARAMETER:
        return LX_EINVAL;
    default:
        return LX_EIO;
    }
}

static abi_long last_win_error(void)
{
    return -lx_win_error(GetLastError());
}

/* Guest memory */

/*
 * Host view of a guest buffer accessible with @prot, or NULL (EFAULT).
 * Checking for PAGE_WRITE also lifts the write protection of pages
 * holding translated code, so that Windows itself may store there.
 */
static void *guest_ptr(abi_ulong addr, abi_ulong len, int prot)
{
    if (len == 0) {
        return g2h_untagged(addr);
    }
    if (!guest_range_valid_untagged(addr, len) ||
        !page_check_range(addr, len, prot)) {
        return NULL;
    }
    return g2h_untagged(addr);
}

static abi_long get_guest_str(abi_ulong addr, char **out)
{
    abi_ulong p = addr;
    size_t len = 0;

    while (len < PATH_MAX) {
        abi_ulong chunk = TARGET_PAGE_SIZE - (p & ~TARGET_PAGE_MASK);
        const char *h, *z;

        if (!guest_addr_valid_untagged(p) || !(page_get_flags(p) & PAGE_READ)) {
            return -LX_EFAULT;
        }
        h = g2h_untagged(p);
        z = memchr(h, 0, chunk);
        if (z) {
            *out = g_strndup(g2h_untagged(addr), len + (z - h));
            return 0;
        }
        len += chunk;
        p += chunk;
    }
    return -LX_ENAMETOOLONG;
}

static abi_long put_guest(abi_ulong addr, const void *data, size_t len)
{
    void *p = guest_ptr(addr, len, PAGE_WRITE);

    if (!p) {
        return -LX_EFAULT;
    }
    memcpy(p, data, len);
    return 0;
}

/* Paths */

static gunichar2 *wide(const char *s)
{
    return g_utf8_to_utf16(s, -1, NULL, NULL, NULL);
}

const char *w32u_sysroot;

/*
 * The file under the sysroot, when there is one there (as path.c of
 * linux-user does): the libraries and the interpreter of the guest
 */
static char *sysroot_path(const char *g)
{
    g_autofree char *p = NULL;

    if (!w32u_sysroot || g[0] != '/' || !strcmp(g, "/") ||
        g_str_has_prefix(g, "/proc/") || g_str_has_prefix(g, "/dev/") ||
        g_str_has_prefix(g, "/tmp/") || !strcmp(g, "/tmp")) {
        return NULL;
    }
    p = g_strconcat(w32u_sysroot, g, NULL);
    if (g_file_test(p, G_FILE_TEST_EXISTS)) {
        return g_steal_pointer(&p);
    }
    return NULL;
}

/* Host path of an absolute or cwd-relative guest path */
static char *host_path(const char *g)
{
    const char *d = g_str_has_prefix(g, "/mnt/") ? g + 4 : g;
    char *s = sysroot_path(g);

    if (s) {
        return s;
    }

    if (!strcmp(g, "/proc/self/exe")) {
        return g_strdup(exec_host_path);
    }
    if (!strcmp(g, "/dev/null")) {
        return g_strdup("NUL");
    }
    if (!strcmp(g, "/tmp") || g_str_has_prefix(g, "/tmp/")) {
        return g_strconcat(g_get_tmp_dir(), g + 4, NULL);
    }
    if (d[0] == '/' && g_ascii_isalpha(d[1]) && (d[2] == '/' || !d[2])) {
        return g_strdup_printf("%c:/%s", d[1], d[2] ? d + 3 : "");
    }
    return g_strdup(g);
}

char *w32u_host_path(const char *guest)
{
    return host_path(guest);
}

/* Guest form of a host path: "C:\x\y" -> "/c/x/y" */
static char *guest_path(const char *h)
{
    g_autofree char *s = g_strdup(h);
    size_t len;
    char *p;

    for (p = s; *p; p++) {
        if (*p == '\\') {
            *p = '/';
        }
    }
    len = strlen(s);
    if (len > 3 && s[len - 1] == '/') {
        s[len - 1] = 0;
    }
    if (g_ascii_isalpha(s[0]) && s[1] == ':') {
        return g_strdup_printf("/%c%s", g_ascii_tolower(s[0]),
                               strcmp(s + 2, "/") ? s + 2 : "");
    }
    return g_steal_pointer(&s);
}

static GuestFD *get_fd(int fd)
{
    if (fd < 0 || fd >= W32U_MAX_FDS || fds[fd].kind == FD_FREE) {
        return NULL;
    }
    return &fds[fd];
}

static abi_long resolve_at(int dirfd, const char *g, char **out)
{
    GuestFD *f;

    if (g[0] == '/' || dirfd == LX_AT_FDCWD) {
        *out = host_path(g);
        return 0;
    }
    f = get_fd(dirfd);
    if (!f) {
        return -LX_EBADF;
    }
    if (f->kind != FD_DIR) {
        return -LX_ENOTDIR;
    }
    *out = g_build_filename(f->path, g, NULL);
    return 0;
}

static abi_long get_path_at(int dirfd, abi_ulong addr, char **out)
{
    g_autofree char *g = NULL;
    abi_long ret = get_guest_str(addr, &g);

    if (ret) {
        return ret;
    }
    if (!*g) {
        return -LX_ENOENT;
    }
    return resolve_at(dirfd, g, out);
}

/* File descriptors */

static int alloc_fd(int min)
{
    int fd;

    for (fd = MAX(min, 0); fd < W32U_MAX_FDS; fd++) {
        if (fds[fd].kind == FD_FREE) {
            return fd;
        }
    }
    return -LX_EMFILE;
}

static void dirent_clear(gpointer p)
{
    g_free(((DirEnt *)p)->name);
}

static void release_fd(GuestFD *f)
{
    if (f->kind == FD_HOST) {
        _close(f->host);
    }
    g_free(f->path);
    if (f->dents) {
        g_array_free(f->dents, true);
    }
    memset(f, 0, sizeof(*f));
}

static HANDLE fd_handle(GuestFD *f)
{
    return (HANDLE)_get_osfhandle(f->host);
}

static bool is_console(GuestFD *f)
{
    DWORD mode;

    return f->kind == FD_HOST && GetConsoleMode(fd_handle(f), &mode);
}

static bool is_disk_file(GuestFD *f)
{
    return f->kind == FD_HOST && GetFileType(fd_handle(f)) == FILE_TYPE_DISK;
}

static abi_long dup_into(GuestFD *f, int newfd, bool cloexec)
{
    GuestFD *n = &fds[newfd];

    if (f->kind == FD_HOST) {
        int h = _dup(f->host);

        if (h < 0) {
            return -lx_errno(errno);
        }
        n->host = h;
    }
    n->kind = f->kind;
    n->flags = f->flags;
    n->cloexec = cloexec;
    n->path = g_strdup(f->path);
    return newfd;
}

/* pread/pwrite on a disk file, leaving the file position alone */
static int64_t host_prw(GuestFD *f, void *buf, size_t len, int64_t offset,
                        bool is_write)
{
    OVERLAPPED ov = {
        .Offset = (DWORD)offset,
        .OffsetHigh = (DWORD)(offset >> 32),
    };
    int64_t pos = _lseeki64(f->host, 0, SEEK_CUR);
    DWORD n = 0;
    BOOL ok;

    if (!is_disk_file(f)) {
        return -LX_ESPIPE;
    }
    if (is_write) {
        ok = WriteFile(fd_handle(f), buf, len, &n, &ov);
    } else {
        ok = ReadFile(fd_handle(f), buf, len, &n, &ov);
    }
    if (!ok && GetLastError() != ERROR_HANDLE_EOF) {
        abi_long err = last_win_error();

        _lseeki64(f->host, pos, SEEK_SET);
        return err;
    }
    _lseeki64(f->host, pos, SEEK_SET);
    return n;
}

int64_t w32u_fd_pread(int fd, void *buf, size_t len, int64_t offset)
{
    GuestFD *f = get_fd(fd);
    size_t done = 0;

    if (!f || f->kind != FD_HOST) {
        return -LX_EBADF;
    }
    while (done < len) {
        int64_t n = host_prw(f, (char *)buf + done,
                             MIN(len - done, LX_MAX_RW_COUNT),
                             offset + done, false);
        if (n < 0) {
            return n;
        }
        if (n == 0) {
            break;
        }
        done += n;
    }
    return done;
}

/* stat */

/* FILETIME as a duration, in 100 ns units */
static uint64_t filetime_raw(const FILETIME *ft)
{
    return ((uint64_t)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

/* FILETIME as a date, in ns since the Unix epoch */
static int64_t filetime_ns(const FILETIME *ft)
{
    return (int64_t)(filetime_raw(ft) - FILETIME_UNIX_EPOCH) * 100;
}

/* glibc's makedev() encoding */
static uint64_t lx_makedev(uint32_t major, uint32_t minor)
{
    return ((uint64_t)(major & 0xfffff000) << 32) |
           ((uint64_t)(major & 0xfff) << 8) |
           ((uint64_t)(minor & 0xffffff00) << 12) | (minor & 0xff);
}

static abi_long stat_handle(HANDLE h, HostStat *st)
{
    BY_HANDLE_FILE_INFORMATION bi;
    DWORD mode;

    memset(st, 0, sizeof(*st));
    st->nlink = 1;
    switch (GetFileType(h)) {
    case FILE_TYPE_CHAR:
        st->mode = LX_S_IFCHR | 0620;
        /* a pseudo-terminal or /dev/null */
        st->rdev = GetConsoleMode(h, &mode) ? lx_makedev(136, 0)
                                            : lx_makedev(1, 3);
        return 0;
    case FILE_TYPE_PIPE:
        st->mode = LX_S_IFIFO | 0600;
        return 0;
    case FILE_TYPE_DISK:
        break;
    default:
        return -LX_EBADF;
    }
    if (!GetFileInformationByHandle(h, &bi)) {
        return last_win_error();
    }
    if (bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        st->mode = LX_S_IFDIR | 0755;
    } else {
        st->mode = LX_S_IFREG |
                   (bi.dwFileAttributes & FILE_ATTRIBUTE_READONLY ? 0444 : 0644);
    }
    st->nlink = bi.nNumberOfLinks;
    st->dev = bi.dwVolumeSerialNumber;
    st->ino = ((uint64_t)bi.nFileIndexHigh << 32) | bi.nFileIndexLow;
    st->size = ((int64_t)bi.nFileSizeHigh << 32) | bi.nFileSizeLow;
    st->atime_ns = filetime_ns(&bi.ftLastAccessTime);
    st->mtime_ns = filetime_ns(&bi.ftLastWriteTime);
    st->ctime_ns = st->mtime_ns;
    st->btime_ns = filetime_ns(&bi.ftCreationTime);
    return 0;
}

static HANDLE open_attr_handle(const char *path, DWORD access, bool follow)
{
    g_autofree gunichar2 *w = wide(path);

    if (!w) {
        SetLastError(ERROR_INVALID_NAME);
        return INVALID_HANDLE_VALUE;
    }
    return CreateFileW(w, access,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS |
                       (follow ? 0 : FILE_FLAG_OPEN_REPARSE_POINT), NULL);
}

static abi_long stat_path(const char *path, bool follow, HostStat *st)
{
    HANDLE h = open_attr_handle(path, FILE_READ_ATTRIBUTES, follow);
    abi_long ret;

    if (h == INVALID_HANDLE_VALUE) {
        return last_win_error();
    }
    ret = stat_handle(h, st);
    CloseHandle(h);
    return ret;
}

static abi_long stat_fd(GuestFD *f, HostStat *st)
{
    if (f->kind == FD_DIR) {
        return stat_path(f->path, true, st);
    }
    return stat_handle(fd_handle(f), st);
}

/* stat of (dirfd, path) as newfstatat and statx see it */
static abi_long stat_at(int dirfd, abi_ulong pathaddr, int flags, HostStat *st)
{
    g_autofree char *g = NULL;
    g_autofree char *path = NULL;
    abi_long ret = get_guest_str(pathaddr, &g);

    if (ret) {
        return ret;
    }
    if (!*g) {
        GuestFD *f = get_fd(dirfd);

        if (!(flags & LX_AT_EMPTY_PATH)) {
            return -LX_ENOENT;
        }
        if (dirfd == LX_AT_FDCWD) {
            path = g_get_current_dir();
            return stat_path(path, true, st);
        }
        return f ? stat_fd(f, st) : -LX_EBADF;
    }
    ret = resolve_at(dirfd, g, &path);
    if (ret) {
        return ret;
    }
    return stat_path(path, !(flags & LX_AT_SYMLINK_NOFOLLOW), st);
}

static abi_long put_stat(abi_ulong addr, const HostStat *st)
{
    struct lx_stat s = {
        .st_dev = lx_makedev(0, st->dev),
        .st_ino = st->ino,
        .st_mode = st->mode,
        .st_nlink = st->nlink,
        .st_uid = W32U_UID,
        .st_gid = W32U_UID,
        .st_rdev = st->rdev,
        .st_size = st->size,
        .st_blksize = 4096,
        .st_blocks = DIV_ROUND_UP(st->size, 512),
        .st_atime_sec = st->atime_ns / NANOSECONDS_PER_SECOND,
        .st_atime_nsec = st->atime_ns % NANOSECONDS_PER_SECOND,
        .st_mtime_sec = st->mtime_ns / NANOSECONDS_PER_SECOND,
        .st_mtime_nsec = st->mtime_ns % NANOSECONDS_PER_SECOND,
        .st_ctime_sec = st->ctime_ns / NANOSECONDS_PER_SECOND,
        .st_ctime_nsec = st->ctime_ns % NANOSECONDS_PER_SECOND,
    };

    return put_guest(addr, &s, sizeof(s));
}

static struct lx_statx_timestamp statx_time(int64_t ns)
{
    return (struct lx_statx_timestamp) {
        .tv_sec = ns / NANOSECONDS_PER_SECOND,
        .tv_nsec = ns % NANOSECONDS_PER_SECOND,
    };
}

static abi_long put_statx(abi_ulong addr, const HostStat *st)
{
    struct lx_statx s = {
        .stx_mask = LX_STATX_BASIC_STATS | LX_STATX_BTIME,
        .stx_blksize = 4096,
        .stx_nlink = st->nlink,
        .stx_uid = W32U_UID,
        .stx_gid = W32U_UID,
        .stx_mode = st->mode,
        .stx_ino = st->ino,
        .stx_size = st->size,
        .stx_blocks = DIV_ROUND_UP(st->size, 512),
        .stx_atime = statx_time(st->atime_ns),
        .stx_btime = statx_time(st->btime_ns),
        .stx_ctime = statx_time(st->ctime_ns),
        .stx_mtime = statx_time(st->mtime_ns),
        .stx_rdev_major = (st->rdev >> 8) & 0xfff,
        .stx_rdev_minor = st->rdev & 0xff,
        .stx_dev_minor = st->dev,
    };

    return put_guest(addr, &s, sizeof(s));
}

/* Files */

static abi_long sys_openat(int dirfd, abi_ulong pathaddr, int flags, int mode)
{
    g_autofree char *path = NULL;
    g_autofree gunichar2 *w = NULL;
    DWORD access, disposition, attr;
    int accmode = flags & LX_O_ACCMODE;
    abi_long ret;
    HANDLE h;
    int fd, crt;

    ret = get_path_at(dirfd, pathaddr, &path);
    if (ret) {
        return ret;
    }
    w = wide(path);
    if (!w) {
        return -LX_ENOENT;
    }
    fd = alloc_fd(0);
    if (fd < 0) {
        return fd;
    }

    attr = GetFileAttributesW(w);
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        if ((flags & LX_O_CREAT) && (flags & LX_O_EXCL)) {
            return -LX_EEXIST;
        }
        if (accmode != LX_O_RDONLY) {
            return -LX_EISDIR;
        }
        fds[fd] = (GuestFD) {
            .kind = FD_DIR,
            .flags = flags & ~LX_O_CLOEXEC,
            .cloexec = flags & LX_O_CLOEXEC,
            .path = g_steal_pointer(&path),
        };
        return fd;
    }
    if (flags & LX_O_DIRECTORY) {
        return attr == INVALID_FILE_ATTRIBUTES ? -LX_ENOENT : -LX_ENOTDIR;
    }

    access = accmode == LX_O_WRONLY ? GENERIC_WRITE :
             accmode == LX_O_RDWR ? GENERIC_READ | GENERIC_WRITE :
             GENERIC_READ;
    if ((flags & (LX_O_CREAT | LX_O_EXCL)) == (LX_O_CREAT | LX_O_EXCL)) {
        disposition = CREATE_NEW;
    } else if (flags & LX_O_CREAT) {
        disposition = (flags & LX_O_TRUNC) ? CREATE_ALWAYS : OPEN_ALWAYS;
    } else if ((flags & LX_O_TRUNC) && accmode != LX_O_RDONLY) {
        disposition = TRUNCATE_EXISTING;
    } else {
        disposition = OPEN_EXISTING;
    }
    /* FILE_SHARE_DELETE: open files can be unlinked and renamed, as on Linux */
    h = CreateFileW(w, access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, disposition,
                    (mode & ~guest_umask & 0222) ? FILE_ATTRIBUTE_NORMAL
                                                 : FILE_ATTRIBUTE_READONLY,
                    NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return last_win_error();
    }
    crt = _open_osfhandle((intptr_t)h, _O_BINARY |
                          (flags & LX_O_APPEND ? _O_APPEND : 0) |
                          (accmode == LX_O_RDONLY ? _O_RDONLY : 0));
    if (crt < 0) {
        CloseHandle(h);
        return -LX_EMFILE;
    }
    fds[fd] = (GuestFD) {
        .kind = FD_HOST,
        .host = crt,
        .flags = flags & ~(LX_O_CLOEXEC | LX_O_CREAT | LX_O_EXCL | LX_O_TRUNC),
        .cloexec = flags & LX_O_CLOEXEC,
        .path = g_steal_pointer(&path),
    };
    return fd;
}

static abi_long sys_close(int fd)
{
    GuestFD *f = get_fd(fd);

    if (!f) {
        return -LX_EBADF;
    }
    release_fd(f);
    return 0;
}

static abi_long do_read(GuestFD *f, abi_ulong buf, abi_ulong len)
{
    char *p;
    int n;

    if (f->kind == FD_DIR) {
        return -LX_EISDIR;
    }
    if ((f->flags & LX_O_ACCMODE) == LX_O_WRONLY) {
        return -LX_EBADF;
    }
    len = MIN(len, LX_MAX_RW_COUNT);
    p = guest_ptr(buf, len, PAGE_WRITE);
    if (!p) {
        return -LX_EFAULT;
    }
    n = _read(f->host, p, len);
    if (n < 0) {
        return -lx_errno(errno);
    }
    if (n > 0 && is_console(f)) {
        /* console lines end in CR LF; a line starting with ^Z is EOF */
        int i, j;

        if (p[0] == 0x1a) {
            return 0;
        }
        for (i = j = 0; i < n; i++) {
            if (!(p[i] == '\r' && i + 1 < n && p[i + 1] == '\n')) {
                p[j++] = p[i];
            }
        }
        n = j;
    }
    return n;
}

static abi_long do_write(GuestFD *f, abi_ulong buf, abi_ulong len)
{
    const char *p;
    int n;

    if (f->kind == FD_DIR || (f->flags & LX_O_ACCMODE) == LX_O_RDONLY) {
        return -LX_EBADF;
    }
    len = MIN(len, LX_MAX_RW_COUNT);
    p = guest_ptr(buf, len, PAGE_READ);
    if (!p) {
        return -LX_EFAULT;
    }
    n = _write(f->host, p, len);
    return n < 0 ? -lx_errno(errno) : n;
}

static abi_long do_rw_vec(int fd, abi_ulong iovaddr, abi_long cnt, bool is_write)
{
    GuestFD *f = get_fd(fd);
    struct lx_iovec *iov;
    abi_long total = 0, i;

    if (!f) {
        return -LX_EBADF;
    }
    if (cnt < 0 || cnt > LX_IOV_MAX) {
        return -LX_EINVAL;
    }
    iov = guest_ptr(iovaddr, cnt * sizeof(*iov), PAGE_READ);
    if (!iov) {
        return -LX_EFAULT;
    }
    for (i = 0; i < cnt; i++) {
        abi_long n;

        if (iov[i].iov_len == 0) {
            continue;
        }
        n = is_write ? do_write(f, iov[i].iov_base, iov[i].iov_len)
                     : do_read(f, iov[i].iov_base, iov[i].iov_len);
        if (n < 0) {
            return total ? total : n;
        }
        total += n;
        if (n < iov[i].iov_len) {
            break;
        }
    }
    return total;
}

static abi_long sys_prw(int fd, abi_ulong buf, abi_ulong len, int64_t offset,
                        bool is_write)
{
    GuestFD *f = get_fd(fd);
    void *p;

    if (!f) {
        return -LX_EBADF;
    }
    if (f->kind == FD_DIR) {
        return -LX_EISDIR;
    }
    if (offset < 0) {
        return -LX_EINVAL;
    }
    len = MIN(len, LX_MAX_RW_COUNT);
    p = guest_ptr(buf, len, is_write ? PAGE_READ : PAGE_WRITE);
    if (!p) {
        return -LX_EFAULT;
    }
    return host_prw(f, p, len, offset, is_write);
}

static abi_long sys_lseek(int fd, int64_t offset, int whence)
{
    GuestFD *f = get_fd(fd);
    int64_t ret;

    if (!f) {
        return -LX_EBADF;
    }
    if (f->kind == FD_DIR) {
        if (whence != SEEK_SET || offset < 0) {
            return -LX_EINVAL;
        }
        f->pos = offset;
        return offset;
    }
    if (whence > SEEK_END) {
        return -LX_EINVAL;
    }
    if (!is_disk_file(f)) {
        return -LX_ESPIPE;
    }
    ret = _lseeki64(f->host, offset, whence);
    return ret < 0 ? -lx_errno(errno) : ret;
}

static void list_dir(GuestFD *f)
{
    g_autofree char *pattern = g_build_filename(f->path, "*", NULL);
    g_autofree gunichar2 *w = wide(pattern);
    WIN32_FIND_DATAW fd;
    HANDLE h;

    f->dents = g_array_new(false, false, sizeof(DirEnt));
    g_array_set_clear_func(f->dents, dirent_clear);
    h = w ? FindFirstFileW(w, &fd) : INVALID_HANDLE_VALUE;
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        DirEnt e = {
            .name = g_utf16_to_utf8(fd.cFileName, -1, NULL, NULL, NULL),
            .type = fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
                    ? LX_DT_DIR : LX_DT_REG,
        };
        if (e.name) {
            g_array_append_val(f->dents, e);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static abi_long sys_getdents64(int fd, abi_ulong buf, abi_ulong len)
{
    GuestFD *f = get_fd(fd);
    uint8_t *p;
    abi_ulong off = 0;

    if (!f) {
        return -LX_EBADF;
    }
    if (f->kind != FD_DIR) {
        return -LX_ENOTDIR;
    }
    p = guest_ptr(buf, len, PAGE_WRITE);
    if (!p) {
        return -LX_EFAULT;
    }
    if (!f->dents) {
        list_dir(f);
    }
    while (f->pos < f->dents->len) {
        DirEnt *e = &g_array_index(f->dents, DirEnt, f->pos);
        size_t namelen = strlen(e->name);
        abi_ulong reclen = ROUND_UP(19 + namelen + 1, 8);

        if (off + reclen > len) {
            if (off == 0) {
                return -LX_EINVAL;
            }
            break;
        }
        memset(p + off, 0, reclen);
        stq_le_p(p + off, f->pos + 1);          /* d_ino */
        stq_le_p(p + off + 8, f->pos + 1);      /* d_off */
        stw_le_p(p + off + 16, reclen);         /* d_reclen */
        p[off + 18] = e->type;                  /* d_type */
        memcpy(p + off + 19, e->name, namelen);
        off += reclen;
        f->pos++;
    }
    return off;
}

static abi_long sys_dup3(int oldfd, int newfd, int flags)
{
    GuestFD *f = get_fd(oldfd);

    if (!f) {
        return -LX_EBADF;
    }
    if (oldfd == newfd || (flags & ~LX_O_CLOEXEC)) {
        return -LX_EINVAL;
    }
    if (newfd < 0 || newfd >= W32U_MAX_FDS) {
        return -LX_EBADF;
    }
    if (fds[newfd].kind != FD_FREE) {
        release_fd(&fds[newfd]);
    }
    return dup_into(f, newfd, flags & LX_O_CLOEXEC);
}

static abi_long sys_fcntl(int fd, int cmd, abi_ulong arg)
{
    GuestFD *f = get_fd(fd);
    int newfd;

    if (!f) {
        return -LX_EBADF;
    }
    switch (cmd) {
    case LX_F_DUPFD:
    case LX_F_DUPFD_CLOEXEC:
        if (arg >= W32U_MAX_FDS) {
            return -LX_EINVAL;
        }
        newfd = alloc_fd(arg);
        if (newfd < 0) {
            return newfd;
        }
        return dup_into(f, newfd, cmd == LX_F_DUPFD_CLOEXEC);
    case LX_F_GETFD:
        return f->cloexec ? LX_FD_CLOEXEC : 0;
    case LX_F_SETFD:
        f->cloexec = arg & LX_FD_CLOEXEC;
        return 0;
    case LX_F_GETFL:
        return f->flags;
    case LX_F_SETFL:
        f->flags = (f->flags & ~(LX_O_APPEND | LX_O_NONBLOCK)) |
                   (arg & (LX_O_APPEND | LX_O_NONBLOCK));
        return 0;
    case LX_F_GETLK: {
        /* single process: every lock is available */
        uint16_t unlck = LX_F_UNLCK;

        return put_guest(arg, &unlck, sizeof(unlck));
    }
    case LX_F_SETLK:
    case LX_F_SETLKW:
        return 0;
    default:
        return -LX_EINVAL;
    }
}

static abi_long sys_ioctl(int fd, abi_ulong req, abi_ulong arg)
{
    GuestFD *f = get_fd(fd);

    if (!f) {
        return -LX_EBADF;
    }
    switch (req) {
    case LX_TCGETS: {
        /* a cooked terminal, as a Linux console starts */
        struct lx_termios t = {
            .c_iflag = 0400 | 02000,                    /* ICRNL IXON */
            .c_oflag = 01 | 04,                         /* OPOST ONLCR */
            .c_cflag = 017 | 060 | 0200,                /* B38400 CS8 CREAD */
            .c_lflag = 01 | 02 | 010 | 020 | 040 | 0100000,
        };
        if (!is_console(f)) {
            return -LX_ENOTTY;
        }
        return put_guest(arg, &t, sizeof(t));
    }
    case LX_TCSETS:
    case LX_TCSETSW:
    case LX_TCSETSF:
    case LX_FIONBIO:
        return is_console(f) ? 0 : -LX_ENOTTY;
    case LX_TIOCGPGRP: {
        uint32_t pid = GetCurrentProcessId();

        if (!is_console(f)) {
            return -LX_ENOTTY;
        }
        return put_guest(arg, &pid, sizeof(pid));
    }
    case LX_TIOCGWINSZ: {
        CONSOLE_SCREEN_BUFFER_INFO ci;
        struct lx_winsize ws = { 0 };

        if (!is_console(f)) {
            return -LX_ENOTTY;
        }
        if (GetConsoleScreenBufferInfo(fd_handle(f), &ci) ||
            GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &ci) ||
            GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &ci)) {
            ws.ws_row = ci.srWindow.Bottom - ci.srWindow.Top + 1;
            ws.ws_col = ci.srWindow.Right - ci.srWindow.Left + 1;
        } else {
            ws.ws_row = 24;
            ws.ws_col = 80;
        }
        return put_guest(arg, &ws, sizeof(ws));
    }
    default:
        return -LX_ENOTTY;
    }
}

static abi_long sys_pipe2(abi_ulong addr, int flags)
{
    int host[2];
    int32_t guest[2];

    if (flags & ~(LX_O_CLOEXEC | LX_O_NONBLOCK)) {
        return -LX_EINVAL;
    }
    if (_pipe(host, 65536, _O_BINARY | _O_NOINHERIT) < 0) {
        return -lx_errno(errno);
    }
    guest[0] = alloc_fd(0);
    if (guest[0] >= 0) {
        fds[guest[0]] = (GuestFD) {
            .kind = FD_HOST, .host = host[0], .flags = LX_O_RDONLY,
            .cloexec = flags & LX_O_CLOEXEC,
        };
        guest[1] = alloc_fd(0);
        if (guest[1] >= 0) {
            fds[guest[1]] = (GuestFD) {
                .kind = FD_HOST, .host = host[1], .flags = LX_O_WRONLY,
                .cloexec = flags & LX_O_CLOEXEC,
            };
            if (put_guest(addr, guest, sizeof(guest)) == 0) {
                return 0;
            }
            release_fd(&fds[guest[1]]);
            release_fd(&fds[guest[0]]);
            return -LX_EFAULT;
        }
        release_fd(&fds[guest[0]]);
        _close(host[1]);
        return -LX_EMFILE;
    }
    _close(host[0]);
    _close(host[1]);
    return -LX_EMFILE;
}

static abi_long sys_ftruncate(int fd, int64_t len)
{
    GuestFD *f = get_fd(fd);

    if (!f) {
        return -LX_EBADF;
    }
    if (!is_disk_file(f) || len < 0) {
        return -LX_EINVAL;
    }
    return _chsize_s(f->host, len) ? -lx_errno(errno) : 0;
}

static abi_long sys_fsync(int fd)
{
    GuestFD *f = get_fd(fd);

    if (!f) {
        return -LX_EBADF;
    }
    if (is_disk_file(f) && !FlushFileBuffers(fd_handle(f))) {
        return last_win_error();
    }
    return 0;
}

/* Directory operations */

static abi_long sys_mkdirat(int dirfd, abi_ulong pathaddr)
{
    g_autofree char *path = NULL;
    g_autofree gunichar2 *w = NULL;
    abi_long ret = get_path_at(dirfd, pathaddr, &path);

    if (ret) {
        return ret;
    }
    w = wide(path);
    if (!w || !CreateDirectoryW(w, NULL)) {
        return w ? last_win_error() : -LX_ENOENT;
    }
    return 0;
}

static abi_long sys_unlinkat(int dirfd, abi_ulong pathaddr, int flags)
{
    g_autofree char *path = NULL;
    g_autofree gunichar2 *w = NULL;
    abi_long ret = get_path_at(dirfd, pathaddr, &path);
    DWORD attr;

    if (ret) {
        return ret;
    }
    if (flags & ~LX_AT_REMOVEDIR) {
        return -LX_EINVAL;
    }
    w = wide(path);
    if (!w) {
        return -LX_ENOENT;
    }
    attr = GetFileAttributesW(w);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return last_win_error();
    }
    if (flags & LX_AT_REMOVEDIR) {
        if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            return -LX_ENOTDIR;
        }
        return RemoveDirectoryW(w) ? 0 : last_win_error();
    }
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        return -LX_EISDIR;
    }
    /* unlink only needs write access to the directory on Linux */
    if (attr & FILE_ATTRIBUTE_READONLY) {
        SetFileAttributesW(w, attr & ~FILE_ATTRIBUTE_READONLY);
    }
    return DeleteFileW(w) ? 0 : last_win_error();
}

static abi_long sys_renameat2(int olddirfd, abi_ulong oldaddr, int newdirfd,
                              abi_ulong newaddr, unsigned flags)
{
    g_autofree char *oldpath = NULL, *newpath = NULL;
    g_autofree gunichar2 *wold = NULL, *wnew = NULL;
    abi_long ret;

    if (flags & ~LX_RENAME_NOREPLACE) {
        return -LX_EINVAL;
    }
    ret = get_path_at(olddirfd, oldaddr, &oldpath);
    if (!ret) {
        ret = get_path_at(newdirfd, newaddr, &newpath);
    }
    if (ret) {
        return ret;
    }
    wold = wide(oldpath);
    wnew = wide(newpath);
    if (!wold || !wnew) {
        return -LX_ENOENT;
    }
    if (!MoveFileExW(wold, wnew, flags & LX_RENAME_NOREPLACE
                                 ? 0 : MOVEFILE_REPLACE_EXISTING)) {
        return last_win_error();
    }
    return 0;
}

static abi_long sys_faccessat(int dirfd, abi_ulong pathaddr, int mode)
{
    g_autofree char *path = NULL;
    g_autofree gunichar2 *w = NULL;
    abi_long ret = get_path_at(dirfd, pathaddr, &path);
    DWORD attr;

    if (ret) {
        return ret;
    }
    w = wide(path);
    attr = w ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return w ? last_win_error() : -LX_ENOENT;
    }
    /* W_OK; Windows has no execute permission bit to check */
    if ((mode & 2) && (attr & FILE_ATTRIBUTE_READONLY) &&
        !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        return -LX_EACCES;
    }
    return 0;
}

static abi_long sys_getcwd(abi_ulong buf, abi_ulong size)
{
    g_autofree char *cwd = g_get_current_dir();
    g_autofree char *g = guest_path(cwd);
    size_t len = strlen(g) + 1;
    abi_long ret;

    if (len > size) {
        return -LX_ERANGE;
    }
    ret = put_guest(buf, g, len);
    return ret ? ret : len;
}

static abi_long do_chdir(const char *path)
{
    g_autofree gunichar2 *w = wide(path);

    if (!w || !SetCurrentDirectoryW(w)) {
        return w ? last_win_error() : -LX_ENOENT;
    }
    return 0;
}

static abi_long sys_readlinkat(int dirfd, abi_ulong pathaddr, abi_ulong buf,
                               abi_long bufsiz)
{
    g_autofree char *g = NULL;
    g_autofree char *path = NULL;
    HostStat st;
    abi_long ret = get_guest_str(pathaddr, &g);

    if (ret) {
        return ret;
    }
    if (bufsiz <= 0) {
        return -LX_EINVAL;
    }
    if (!strcmp(g, "/proc/self/exe")) {
        g_autofree char *target = guest_path(exec_host_path);
        size_t n = MIN(strlen(target), bufsiz);

        ret = put_guest(buf, target, n);
        return ret ? ret : n;
    }
    /* no symbolic links: an existing file is "not a link" */
    ret = resolve_at(dirfd, g, &path);
    if (!ret) {
        ret = stat_path(path, false, &st);
    }
    return ret ? ret : -LX_EINVAL;
}

static abi_long sys_utimensat(int dirfd, abi_ulong pathaddr, abi_ulong times,
                              int flags)
{
    g_autofree char *path = NULL;
    struct lx_timespec *ts = NULL;
    FILETIME now, ft[2];
    FILETIME *ftp[2];
    HANDLE h;
    abi_long ret;
    int i;

    if (pathaddr) {
        ret = get_path_at(dirfd, pathaddr, &path);
        if (ret) {
            return ret;
        }
    } else {
        GuestFD *f = get_fd(dirfd);

        if (!f) {
            return -LX_EBADF;
        }
        if (!f->path) {
            return 0;
        }
        path = g_strdup(f->path);
    }
    if (times) {
        ts = guest_ptr(times, 2 * sizeof(*ts), PAGE_READ);
        if (!ts) {
            return -LX_EFAULT;
        }
    }
    GetSystemTimeAsFileTime(&now);
    for (i = 0; i < 2; i++) {
        uint64_t t;

        ftp[i] = &ft[i];
        if (!ts || ts[i].tv_nsec == LX_UTIME_NOW) {
            ft[i] = now;
            continue;
        }
        if (ts[i].tv_nsec == LX_UTIME_OMIT) {
            ftp[i] = NULL;
            continue;
        }
        if (ts[i].tv_nsec < 0 || ts[i].tv_nsec >= NANOSECONDS_PER_SECOND) {
            return -LX_EINVAL;
        }
        t = ts[i].tv_sec * 10000000ULL + ts[i].tv_nsec / 100 +
            FILETIME_UNIX_EPOCH;
        ft[i].dwLowDateTime = (DWORD)t;
        ft[i].dwHighDateTime = (DWORD)(t >> 32);
    }
    h = open_attr_handle(path, FILE_WRITE_ATTRIBUTES,
                         !(flags & LX_AT_SYMLINK_NOFOLLOW));
    if (h == INVALID_HANDLE_VALUE) {
        return last_win_error();
    }
    ret = SetFileTime(h, NULL, ftp[0], ftp[1]) ? 0 : last_win_error();
    CloseHandle(h);
    return ret;
}

/* Memory */

static abi_long sys_mmap(abi_ulong addr, abi_ulong len, int prot, int flags,
                         int fd, int64_t offset)
{
    if (!(flags & LX_MAP_ANONYMOUS)) {
        GuestFD *f = get_fd(fd);

        if (!f || f->kind != FD_HOST) {
            return -LX_EBADF;
        }
        if (!is_disk_file(f)) {
            return -LX_ENODEV;
        }
    }
    return w32u_mmap(addr, len, prot & (PROT_READ | PROT_WRITE | PROT_EXEC),
                     flags, (flags & LX_MAP_ANONYMOUS) ? -1 : fd, offset);
}

static abi_long sys_madvise(abi_ulong addr, abi_ulong len, int advice)
{
    void *p;

    if (advice != LX_MADV_DONTNEED || len == 0) {
        return 0;
    }
    /* anonymous private memory reads back as zeroes */
    len = TARGET_PAGE_ALIGN(len);
    p = guest_ptr(addr, len, PAGE_READ | PAGE_WRITE);
    if (p) {
        memset(p, 0, len);
    }
    return 0;
}

/* Time */

static int64_t realtime_ns(void)
{
    FILETIME ft;

    GetSystemTimePreciseAsFileTime(&ft);
    return filetime_ns(&ft);
}

static int64_t cpu_time_ns(bool thread)
{
    FILETIME c, e, k, u;
    BOOL ok = thread ? GetThreadTimes(GetCurrentThread(), &c, &e, &k, &u)
                     : GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);

    return ok ? (filetime_raw(&k) + filetime_raw(&u)) * 100 : 0;
}

static int64_t clock_ns(int clk)
{
    switch (clk) {
    case LX_CLOCK_REALTIME:
    case LX_CLOCK_REALTIME_COARSE:
        return realtime_ns();
    case LX_CLOCK_MONOTONIC:
    case LX_CLOCK_MONOTONIC_RAW:
    case LX_CLOCK_MONOTONIC_COARSE:
    case LX_CLOCK_BOOTTIME:
        return get_clock();
    case LX_CLOCK_PROCESS_CPUTIME_ID:
        return cpu_time_ns(false);
    case LX_CLOCK_THREAD_CPUTIME_ID:
        return cpu_time_ns(true);
    default:
        return -1;
    }
}

static abi_long put_timespec(abi_ulong addr, int64_t ns)
{
    struct lx_timespec ts = {
        .tv_sec = ns / NANOSECONDS_PER_SECOND,
        .tv_nsec = ns % NANOSECONDS_PER_SECOND,
    };

    return put_guest(addr, &ts, sizeof(ts));
}

static abi_long get_timespec_ns(abi_ulong addr, int64_t *ns)
{
    struct lx_timespec *ts = guest_ptr(addr, sizeof(*ts), PAGE_READ);

    if (!ts) {
        return -LX_EFAULT;
    }
    if (ts->tv_sec < 0 || ts->tv_nsec < 0 ||
        ts->tv_nsec >= NANOSECONDS_PER_SECOND) {
        return -LX_EINVAL;
    }
    *ns = ts->tv_sec * NANOSECONDS_PER_SECOND + ts->tv_nsec;
    return 0;
}

static void sleep_ns(int64_t ns)
{
    if (ns > 0) {
        g_usleep(DIV_ROUND_UP(ns, 1000));
    }
}

static abi_long sys_clock_nanosleep(int clk, int flags, abi_ulong req,
                                    abi_ulong rem)
{
    int64_t ns, now = clock_ns(clk);
    abi_long ret;

    if (now < 0) {
        return -LX_EINVAL;
    }
    ret = get_timespec_ns(req, &ns);
    if (ret) {
        return ret;
    }
    sleep_ns(flags & LX_TIMER_ABSTIME ? ns - now : ns);
    if (rem && !(flags & LX_TIMER_ABSTIME)) {
        put_timespec(rem, 0);
    }
    return 0;
}


/* Process */

static abi_long sys_prlimit64(int resource, abi_ulong newaddr, abi_ulong oldaddr)
{
    struct lx_rlimit rl = { LX_RLIM_INFINITY, LX_RLIM_INFINITY };

    if (resource < 0 || resource >= 16) {
        return -LX_EINVAL;
    }
    if (oldaddr) {
        if (resource == LX_RLIMIT_STACK) {
            rl.rlim_cur = W32U_STACK_SIZE;
        } else if (resource == LX_RLIMIT_NOFILE) {
            rl.rlim_cur = rl.rlim_max = W32U_MAX_FDS;
        }
        return put_guest(oldaddr, &rl, sizeof(rl));
    }
    /* new limits are accepted and not enforced */
    return 0;
}

static abi_long sys_uname(abi_ulong addr)
{
    struct lx_utsname u = { 0 };
    g_autofree char *host = g_ascii_strdown(g_get_host_name(), -1);

    pstrcpy(u.sysname, sizeof(u.sysname), "Linux");
    pstrcpy(u.nodename, sizeof(u.nodename), host);
    pstrcpy(u.release, sizeof(u.release), "6.8.0");
    pstrcpy(u.version, sizeof(u.version), "#1 SMP QEMU Win32 linux-user");
    pstrcpy(u.machine, sizeof(u.machine), W32U_ELF_PLATFORM);
    pstrcpy(u.domainname, sizeof(u.domainname), "(none)");
    return put_guest(addr, &u, sizeof(u));
}

static abi_long sys_getrusage(abi_ulong addr)
{
    FILETIME c, e, k, u;
    struct lx_rusage ru = { 0 };

    if (GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) {
        int64_t uns = filetime_raw(&u) * 100;
        int64_t kns = filetime_raw(&k) * 100;

        ru.ru_utime.tv_sec = uns / NANOSECONDS_PER_SECOND;
        ru.ru_utime.tv_usec = uns % NANOSECONDS_PER_SECOND / 1000;
        ru.ru_stime.tv_sec = kns / NANOSECONDS_PER_SECOND;
        ru.ru_stime.tv_usec = kns % NANOSECONDS_PER_SECOND / 1000;
    }
    return put_guest(addr, &ru, sizeof(ru));
}

static abi_long sys_times(abi_ulong addr)
{
    int64_t ticks = GetTickCount64() / 10;      /* CLK_TCK is 100 */

    if (addr) {
        struct lx_tms t = { 0 };
        FILETIME c, e, k, u;

        if (GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) {
            t.tms_utime = filetime_raw(&u) / 100000;
            t.tms_stime = filetime_raw(&k) / 100000;
        }
        if (put_guest(addr, &t, sizeof(t))) {
            return -LX_EFAULT;
        }
    }
    return ticks;
}

static abi_long sys_sysinfo(abi_ulong addr)
{
    MEMORYSTATUSEX ms = { .dwLength = sizeof(ms) };
    struct lx_sysinfo si = {
        .uptime = GetTickCount64() / 1000,
        .procs = 1,
        .mem_unit = 1,
    };

    if (GlobalMemoryStatusEx(&ms)) {
        si.totalram = ms.ullTotalPhys;
        si.freeram = ms.ullAvailPhys;
        si.totalswap = ms.ullTotalPageFile - ms.ullTotalPhys;
        si.freeswap = ms.ullAvailPageFile > ms.ullAvailPhys
                      ? ms.ullAvailPageFile - ms.ullAvailPhys : 0;
    }
    return put_guest(addr, &si, sizeof(si));
}

static abi_long sys_kill(int pid, int sig)
{
    if (pid != (int)GetCurrentProcessId() && pid != 0 && pid != -1) {
        return -LX_ESRCH;
    }
    if (sig < 0 || sig > LX_NSIG) {
        return -LX_EINVAL;
    }
    if (sig) {
        /* default action; only fatal signals are emulated */
        w32u_die_with_signal(sig);
    }
    return 0;
}

static abi_long sys_rt_sigaction(int sig, abi_ulong act, abi_ulong oact)
{
    if (sig < 1 || sig > LX_NSIG ||
        (act && (sig == LX_SIGKILL || sig == LX_SIGSTOP))) {
        return -LX_EINVAL;
    }
    if (oact) {
        /* struct sigaction: handler SIG_DFL, flags, restorer, mask */
        uint64_t sa[4] = { 0 };

        return put_guest(oact, sa, sizeof(sa));
    }
    return 0;
}

static abi_long sys_prctl(int option, abi_ulong arg2)
{
    switch (option) {
    case LX_PR_SET_NAME: {
        g_autofree char *name = NULL;
        abi_long ret = get_guest_str(arg2, &name);

        if (ret) {
            return ret;
        }
        pstrcpy(task_name, sizeof(task_name), name);
        return 0;
    }
    case LX_PR_GET_NAME:
        return put_guest(arg2, task_name, sizeof(task_name));
    default:
        return -LX_EINVAL;
    }
}

/* statfs, fstatfs: the volume of the path or descriptor */
struct lx_statfs {
    int64_t f_type;
    int64_t f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    int32_t f_fsid[2];
    int64_t f_namelen;
    int64_t f_frsize;
    int64_t f_flags;
    int64_t f_spare[4];
};
QEMU_BUILD_BUG_ON(sizeof(struct lx_statfs) != 120);

static abi_long sys_statfs(bool by_fd, abi_ulong arg, abi_ulong buf)
{
    g_autofree char *path = NULL;
    g_autofree gunichar2 *w = NULL;
    wchar_t root[MAX_PATH];
    ULARGE_INTEGER avail, total, free;
    DWORD serial = 0;
    struct lx_statfs s = { 0 };
    abi_long ret;

    if (by_fd) {
        GuestFD *f = get_fd(arg);

        if (!f) {
            return -LX_EBADF;
        }
        path = g_strdup(f->path ? f->path : ".");
    } else {
        ret = get_path_at(LX_AT_FDCWD, arg, &path);
        if (ret) {
            return ret;
        }
    }
    w = wide(path);
    if (!GetVolumePathNameW((wchar_t *)w, root, MAX_PATH) ||
        !GetDiskFreeSpaceExW(root, &avail, &total, &free)) {
        return last_win_error();
    }
    GetVolumeInformationW(root, NULL, 0, &serial, NULL, NULL, NULL, 0);
    s.f_type = 0x5346544e;              /* NTFS_SB_MAGIC */
    s.f_bsize = s.f_frsize = 4096;
    s.f_blocks = total.QuadPart / 4096;
    s.f_bfree = free.QuadPart / 4096;
    s.f_bavail = avail.QuadPart / 4096;
    s.f_files = s.f_ffree = 1 << 24;
    s.f_fsid[0] = serial;
    s.f_namelen = 255;
    return put_guest(buf, &s, sizeof(s));
}

static G_NORETURN void do_exit(int status)
{
    fflush(NULL);
    exit(status & 0xff);
}


/* poll, ppoll, select, pselect6 */

#define LX_POLLIN       0x001
#define LX_POLLPRI      0x002
#define LX_POLLOUT      0x004
#define LX_POLLERR      0x008
#define LX_POLLHUP      0x010
#define LX_POLLNVAL     0x020
#define LX_POLLRDNORM   0x040
#define LX_POLLWRNORM   0x100

struct lx_pollfd {
    int32_t fd;
    int16_t events;
    int16_t revents;
};

/* what @fd is ready for now (POLL* bits, before masking by events) */
static int fd_ready(int fd)
{
    GuestFD *f = get_fd(fd);
    HANDLE h;
    DWORD type, avail = 0, n;
    int acc;

    if (!f) {
        return LX_POLLNVAL;
    }
    if (f->kind != FD_HOST) {
        return LX_POLLIN | LX_POLLOUT | LX_POLLRDNORM | LX_POLLWRNORM;
    }
    acc = f->flags & LX_O_ACCMODE;
    h = fd_handle(f);
    type = GetFileType(h);
    if (type == FILE_TYPE_PIPE) {
        if (acc == LX_O_WRONLY) {
            /* the reader gone: an error, as EPIPE on writing */
            if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL) &&
                GetLastError() == ERROR_BROKEN_PIPE) {
                return LX_POLLERR;
            }
            return LX_POLLOUT | LX_POLLWRNORM;
        }
        if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL)) {
            return GetLastError() == ERROR_BROKEN_PIPE ?
                   LX_POLLHUP | LX_POLLIN : LX_POLLERR;
        }
        return avail ? LX_POLLIN | LX_POLLRDNORM : 0;
    }
    if (is_console(f)) {
        int r = LX_POLLOUT | LX_POLLWRNORM;

        if (acc != LX_O_WRONLY && GetNumberOfConsoleInputEvents(h, &n) && n) {
            /* only key presses make input: drop the other events */
            INPUT_RECORD rec;
            DWORD got;

            while (n-- && PeekConsoleInputW(h, &rec, 1, &got) && got) {
                if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown &&
                    rec.Event.KeyEvent.uChar.UnicodeChar) {
                    r |= LX_POLLIN | LX_POLLRDNORM;
                    break;
                }
                ReadConsoleInputW(h, &rec, 1, &got);
            }
        }
        return r;
    }
    /* disk files, NUL, other devices: never wait */
    return LX_POLLIN | LX_POLLOUT | LX_POLLRDNORM | LX_POLLWRNORM;
}

/*
 * Wait until one of @p is ready or @timeout_ms (-1: forever) passes;
 * returns the number of ready entries.  Windows has no single wait for
 * pipes and consoles: they are looked at again, every 1 to 10 ms.
 */
static int do_poll(struct lx_pollfd *p, int n, int64_t timeout_ms)
{
    int64_t end = timeout_ms < 0 ? -1 :
                  g_get_monotonic_time() / 1000 + timeout_ms;
    DWORD nap = 1;
    int i, ready;

    for (;;) {
        ready = 0;
        for (i = 0; i < n; i++) {
            int r;

            p[i].revents = 0;
            if (p[i].fd < 0) {
                continue;
            }
            r = fd_ready(p[i].fd);
            p[i].revents = r & (p[i].events | LX_POLLERR | LX_POLLHUP |
                                LX_POLLNVAL);
            if (p[i].revents) {
                ready++;
            }
        }
        if (ready || timeout_ms == 0) {
            return ready;
        }
        if (end >= 0) {
            int64_t left = end - g_get_monotonic_time() / 1000;

            if (left <= 0) {
                return 0;
            }
            nap = MIN(nap, left);
        }
        if (w32u_signal_pending()) {
            return -LX_EINTR;
        }
        Sleep(nap);
        nap = MIN(nap * 2, 10);
    }
}

static abi_long sys_poll(abi_ulong addr, abi_ulong nfds, int64_t timeout_ms)
{
    struct lx_pollfd *p;
    int ret;

    if (nfds > W32U_MAX_FDS * 4) {
        return -LX_EINVAL;
    }
    p = guest_ptr(addr, nfds * sizeof(*p), PAGE_READ | PAGE_WRITE);
    if (!p && nfds) {
        return -LX_EFAULT;
    }
    ret = do_poll(p, nfds, timeout_ms);
    return ret;
}

/* a struct timespec of the guest in ms, -1 for NULL */
static int64_t timespec_ms(abi_ulong addr, abi_long *err)
{
    struct lx_timespec *ts;

    *err = 0;
    if (!addr) {
        return -1;
    }
    ts = guest_ptr(addr, sizeof(*ts), PAGE_READ);
    if (!ts || ts->tv_sec < 0 || ts->tv_nsec < 0 ||
        ts->tv_nsec >= NANOSECONDS_PER_SECOND) {
        *err = ts ? -LX_EINVAL : -LX_EFAULT;
        return 0;
    }
    return ts->tv_sec * 1000 + DIV_ROUND_UP(ts->tv_nsec, 1000000);
}

/* select: the fd_sets become a pollfd array, and back */
static abi_long do_select(int nfds, abi_ulong raddr, abi_ulong waddr,
                          abi_ulong eaddr, int64_t timeout_ms)
{
    uint64_t *sets[3] = { NULL, NULL, NULL };
    abi_ulong addrs[3] = { raddr, waddr, eaddr };
    size_t bytes;
    g_autofree struct lx_pollfd *p = NULL;
    int n = 0, i, k, ret;

    if (nfds < 0 || nfds > 1024) {
        return -LX_EINVAL;
    }
    bytes = DIV_ROUND_UP(nfds, 64) * 8;
    for (k = 0; k < 3; k++) {
        if (addrs[k] && bytes) {
            sets[k] = guest_ptr(addrs[k], bytes, PAGE_READ | PAGE_WRITE);
            if (!sets[k]) {
                return -LX_EFAULT;
            }
        }
    }
    p = g_new0(struct lx_pollfd, nfds ? nfds : 1);
    for (i = 0; i < nfds; i++) {
        int16_t ev = 0;

        if (sets[0] && (sets[0][i / 64] >> (i % 64) & 1)) {
            ev |= LX_POLLIN;
        }
        if (sets[1] && (sets[1][i / 64] >> (i % 64) & 1)) {
            ev |= LX_POLLOUT;
        }
        if (sets[2] && (sets[2][i / 64] >> (i % 64) & 1)) {
            ev |= LX_POLLPRI;
        }
        if (ev) {
            if (!get_fd(i)) {
                return -LX_EBADF;
            }
            p[n].fd = i;
            p[n].events = ev;
            n++;
        }
    }
    ret = do_poll(p, n, timeout_ms);
    if (ret < 0) {
        return ret;
    }
    for (k = 0; k < 3; k++) {
        if (sets[k]) {
            memset(sets[k], 0, bytes);
        }
    }
    ret = 0;
    for (i = 0; i < n; i++) {
        int fd = p[i].fd;
        int16_t r = p[i].revents;

        if (sets[0] && (p[i].events & LX_POLLIN) &&
            (r & (LX_POLLIN | LX_POLLHUP | LX_POLLERR))) {
            sets[0][fd / 64] |= 1ULL << (fd % 64);
            ret++;
        }
        if (sets[1] && (p[i].events & LX_POLLOUT) &&
            (r & (LX_POLLOUT | LX_POLLERR))) {
            sets[1][fd / 64] |= 1ULL << (fd % 64);
            ret++;
        }
        if (sets[2] && (p[i].events & LX_POLLPRI) && (r & LX_POLLPRI)) {
            sets[2][fd / 64] |= 1ULL << (fd % 64);
            ret++;
        }
    }
    return ret;
}

#ifdef TARGET_X86_64
#define LX_NOT_HANDLED  (-0x7fffffff)

#define ARCH_SET_GS     0x1001
#define ARCH_SET_FS     0x1002
#define ARCH_GET_FS     0x1003
#define ARCH_GET_GS     0x1004

static abi_long sys_arch_prctl(CPUArchState *env, int code, abi_ulong addr)
{
    uint64_t v;

    switch (code) {
    case ARCH_SET_FS:
    case ARCH_SET_GS:
        if (addr >= reserved_va) {
            return -LX_EPERM;
        }
        cpu_x86_load_seg(env, code == ARCH_SET_FS ? R_FS : R_GS, 0);
        env->segs[code == ARCH_SET_FS ? R_FS : R_GS].base = addr;
        return 0;
    case ARCH_GET_FS:
    case ARCH_GET_GS:
        v = env->segs[code == ARCH_GET_FS ? R_FS : R_GS].base;
        return put_guest(addr, &v, sizeof(v));
    default:
        return -LX_EINVAL;
    }
}

/* getdents: the records of getdents64, in place (the same sizes) */
static abi_long sys_getdents(int fd, abi_ulong buf, abi_ulong len)
{
    abi_long n = sys_getdents64(fd, buf, len);
    abi_long off = 0;

    while (n > 0 && off < n) {
        uint8_t *rec = g2h_untagged(buf + off);
        uint16_t reclen;
        uint8_t type;
        size_t namelen;

        memcpy(&reclen, rec + 16, 2);
        type = rec[18];
        namelen = strnlen((char *)rec + 19, reclen - 19);
        memmove(rec + 18, rec + 19, namelen + 1);
        rec[reclen - 1] = type;
        off += reclen;
    }
    return n;
}

static abi_long x86_64_legacy(CPUArchState *env, int num, abi_long arg1,
                              abi_long arg2, abi_long arg3, abi_long arg4,
                              abi_long arg5, abi_long arg6)
{
    HostStat st;
    abi_long ret;

    switch (num) {
    case TARGET_NR_open:
        return sys_openat(LX_AT_FDCWD, arg1, arg2, arg3);
    case TARGET_NR_creat:
        return sys_openat(LX_AT_FDCWD, arg1,
                          LX_O_CREAT | LX_O_WRONLY | LX_O_TRUNC, arg2);
    case TARGET_NR_stat:
    case TARGET_NR_lstat:
        ret = stat_at(LX_AT_FDCWD, arg1,
                      num == TARGET_NR_lstat ? LX_AT_SYMLINK_NOFOLLOW : 0,
                      &st);
        return ret ? ret : put_stat(arg2, &st);
    case TARGET_NR_access:
        return sys_faccessat(LX_AT_FDCWD, arg1, arg2);
    case TARGET_NR_pipe:
        return sys_pipe2(arg1, 0);
    case TARGET_NR_dup2:
        if (arg1 == arg2) {
            return get_fd(arg1) ? arg1 : -LX_EBADF;
        }
        return sys_dup3(arg1, arg2, 0);
    case TARGET_NR_mkdir:
        return sys_mkdirat(LX_AT_FDCWD, arg1);
    case TARGET_NR_rmdir:
        return sys_unlinkat(LX_AT_FDCWD, arg1, LX_AT_REMOVEDIR);
    case TARGET_NR_unlink:
        return sys_unlinkat(LX_AT_FDCWD, arg1, 0);
    case TARGET_NR_rename:
        return sys_renameat2(LX_AT_FDCWD, arg1, LX_AT_FDCWD, arg2, 0);
    case TARGET_NR_readlink:
        return sys_readlinkat(LX_AT_FDCWD, arg1, arg2, arg3);
    case TARGET_NR_chmod:
    case TARGET_NR_chown:
    case TARGET_NR_lchown:
        return stat_at(LX_AT_FDCWD, arg1,
                       num == TARGET_NR_lchown ? LX_AT_SYMLINK_NOFOLLOW : 0,
                       &st);
    case TARGET_NR_getdents:
        return sys_getdents(arg1, arg2, arg3);
    case TARGET_NR_arch_prctl:
        return sys_arch_prctl(env, arg1, arg2);
    case TARGET_NR_time: {
        int64_t t = g_get_real_time() / G_USEC_PER_SEC;

        if (arg1) {
            ret = put_guest(arg1, &t, sizeof(t));
            if (ret) {
                return ret;
            }
        }
        return t;
    }
    case TARGET_NR_getpgrp:
        return w32u_vpid;
    case TARGET_NR_fork:
    case TARGET_NR_vfork:
        return w32u_fork(env, 0, 0, 0, 0, 0);
    case TARGET_NR_poll:
        return sys_poll(arg1, arg2, (int)arg3 < 0 ? -1 : (int)arg3);
    case TARGET_NR_select: {
        int64_t ms = -1;

        if (arg5) {
            struct lx_timeval *tv = guest_ptr(arg5, sizeof(*tv), PAGE_READ);

            if (!tv) {
                return -LX_EFAULT;
            }
            if (tv->tv_sec < 0 || tv->tv_usec < 0) {
                return -LX_EINVAL;
            }
            ms = tv->tv_sec * 1000 + DIV_ROUND_UP(tv->tv_usec, 1000);
        }
        return do_select(arg1, arg2, arg3, arg4, ms);
    }
    }
    return LX_NOT_HANDLED;
}
#endif

static abi_long do_syscall(CPUArchState *env, int num, abi_long arg1,
                           abi_long arg2, abi_long arg3, abi_long arg4,
                           abi_long arg5, abi_long arg6)
{
    GuestFD *f;
    HostStat st;
    abi_long ret;

#ifdef TARGET_X86_64
    ret = x86_64_legacy(env, num, arg1, arg2, arg3, arg4, arg5, arg6);
    if (ret != LX_NOT_HANDLED) {
        return ret;
    }
#endif
    switch (num) {
    case TARGET_NR_openat:
        return sys_openat(arg1, arg2, arg3, arg4);
    case TARGET_NR_ppoll: {
        int64_t ms = timespec_ms(arg3, &ret);

        return ret ? ret : sys_poll(arg1, arg2, ms);
    }
    case TARGET_NR_pselect6: {
        int64_t ms = timespec_ms(arg5, &ret);

        return ret ? ret : do_select(arg1, arg2, arg3, arg4, ms);
    }
    case TARGET_NR_close:
        return sys_close(arg1);
    case TARGET_NR_read:
    case TARGET_NR_write:
        f = get_fd(arg1);
        if (!f) {
            return -LX_EBADF;
        }
        return num == TARGET_NR_read ? do_read(f, arg2, arg3)
                                     : do_write(f, arg2, arg3);
    case TARGET_NR_readv:
        return do_rw_vec(arg1, arg2, arg3, false);
    case TARGET_NR_writev:
        return do_rw_vec(arg1, arg2, arg3, true);
    case TARGET_NR_pread64:
        return sys_prw(arg1, arg2, arg3, arg4, false);
    case TARGET_NR_pwrite64:
        return sys_prw(arg1, arg2, arg3, arg4, true);
    case TARGET_NR_lseek:
        return sys_lseek(arg1, arg2, arg3);
    case TARGET_NR_getdents64:
        return sys_getdents64(arg1, arg2, arg3);
    case TARGET_NR_dup:
        f = get_fd(arg1);
        if (!f) {
            return -LX_EBADF;
        }
        ret = alloc_fd(0);
        return ret < 0 ? ret : dup_into(f, ret, false);
    case TARGET_NR_dup3:
        return sys_dup3(arg1, arg2, arg3);
    case TARGET_NR_fcntl:
        return sys_fcntl(arg1, arg2, arg3);
    case TARGET_NR_ioctl:
        return sys_ioctl(arg1, arg2, arg3);
    case TARGET_NR_pipe2:
        return sys_pipe2(arg1, arg2);
    case TARGET_NR_ftruncate:
        return sys_ftruncate(arg1, arg2);
    case TARGET_NR_fsync:
    case TARGET_NR_fdatasync:
        return sys_fsync(arg1);
    case TARGET_NR_fadvise64:
        return get_fd(arg1) ? 0 : -LX_EBADF;

    case TARGET_NR_newfstatat:
        ret = stat_at(arg1, arg2, arg4, &st);
        return ret ? ret : put_stat(arg3, &st);
    case TARGET_NR_statx:
        ret = stat_at(arg1, arg2, arg3, &st);
        return ret ? ret : put_statx(arg5, &st);
    case TARGET_NR_fstat:
        f = get_fd(arg1);
        if (!f) {
            return -LX_EBADF;
        }
        ret = stat_fd(f, &st);
        return ret ? ret : put_stat(arg2, &st);
    case TARGET_NR_readlinkat:
        return sys_readlinkat(arg1, arg2, arg3, arg4);
    case TARGET_NR_faccessat:
    case TARGET_NR_faccessat2:
        return sys_faccessat(arg1, arg2, arg3);
    case TARGET_NR_mkdirat:
        return sys_mkdirat(arg1, arg2);
    case TARGET_NR_unlinkat:
        return sys_unlinkat(arg1, arg2, arg3);
    case TARGET_NR_renameat:
        return sys_renameat2(arg1, arg2, arg3, arg4, 0);
    case TARGET_NR_renameat2:
        return sys_renameat2(arg1, arg2, arg3, arg4, arg5);
    case TARGET_NR_getcwd:
        return sys_getcwd(arg1, arg2);
    case TARGET_NR_chdir: {
        g_autofree char *path = NULL;

        ret = get_path_at(LX_AT_FDCWD, arg1, &path);
        return ret ? ret : do_chdir(path);
    }
    case TARGET_NR_fchdir:
        f = get_fd(arg1);
        if (!f) {
            return -LX_EBADF;
        }
        return f->kind == FD_DIR ? do_chdir(f->path) : -LX_ENOTDIR;
    case TARGET_NR_utimensat:
        return sys_utimensat(arg1, arg2, arg3, arg4);
    case TARGET_NR_fchmod:
    case TARGET_NR_fchown:
        /* no Unix permissions or owners on Windows */
        return get_fd(arg1) ? 0 : -LX_EBADF;
    case TARGET_NR_fchmodat:
    case TARGET_NR_fchownat:
        return stat_at(arg1, arg2, num == TARGET_NR_fchownat ? arg5 : 0, &st);

    case TARGET_NR_brk:
        return w32u_brk(arg1);
    case TARGET_NR_mmap:
        return sys_mmap(arg1, arg2, arg3, arg4, arg5, arg6);
    case TARGET_NR_munmap:
        return w32u_munmap(arg1, arg2);
    case TARGET_NR_mprotect:
        return w32u_mprotect(arg1, arg2,
                             arg3 & (PROT_READ | PROT_WRITE | PROT_EXEC));
    case TARGET_NR_mremap:
        /* callers fall back to mmap + copy */
        return -LX_ENOMEM;
    case TARGET_NR_madvise:
        return sys_madvise(arg1, arg2, arg3);
    case TARGET_NR_msync:
    case TARGET_NR_mlock:
    case TARGET_NR_munlock:
        return 0;

    case TARGET_NR_clock_gettime: {
        int64_t ns = clock_ns(arg1);

        return ns < 0 ? -LX_EINVAL : put_timespec(arg2, ns);
    }
    case TARGET_NR_clock_getres:
        if (clock_ns(arg1) < 0) {
            return -LX_EINVAL;
        }
        return arg2 ? put_timespec(arg2, 100) : 0;
    case TARGET_NR_gettimeofday:
        if (arg1) {
            int64_t ns = realtime_ns();
            struct lx_timeval tv = {
                .tv_sec = ns / NANOSECONDS_PER_SECOND,
                .tv_usec = ns % NANOSECONDS_PER_SECOND / 1000,
            };

            ret = put_guest(arg1, &tv, sizeof(tv));
            if (ret) {
                return ret;
            }
        }
        if (arg2) {
            uint32_t tz[2] = { 0, 0 };

            return put_guest(arg2, tz, sizeof(tz));
        }
        return 0;
    case TARGET_NR_nanosleep:
        return sys_clock_nanosleep(LX_CLOCK_MONOTONIC, 0, arg1, arg2);
    case TARGET_NR_clock_nanosleep:
        return sys_clock_nanosleep(arg1, arg2, arg3, arg4);
    case TARGET_NR_times:
        return sys_times(arg1);
    case TARGET_NR_getrandom: {
        void *p;

        arg2 = MIN(arg2, LX_MAX_RW_COUNT);
        p = guest_ptr(arg1, arg2, PAGE_WRITE);
        if (!p) {
            return -LX_EFAULT;
        }
        qemu_guest_getrandom_nofail(p, arg2);
        return arg2;
    }

    case TARGET_NR_exit:
        w32u_exit_thread(arg1);
    case TARGET_NR_exit_group:
        do_exit(arg1);
    case TARGET_NR_set_tid_address:
        return w32u_set_tid_address(arg1);
    case TARGET_NR_gettid:
        return w32u_gettid();
    case TARGET_NR_getgroups:
        /* one group, the user's */
        if (arg1) {
            int32_t g = W32U_UID;

            if ((int)arg1 < 0) {
                return -LX_EINVAL;
            }
            ret = put_guest(arg2, &g, sizeof(g));
            if (ret) {
                return ret;
            }
        }
        return 1;
    case TARGET_NR_setgroups:
        return -LX_EPERM;
    case TARGET_NR_statfs:
    case TARGET_NR_fstatfs:
        return sys_statfs(num == TARGET_NR_fstatfs, arg1, arg2);
    case TARGET_NR_getpid:
        return w32u_vpid;
    case TARGET_NR_wait4:
        return w32u_wait4(arg1, arg2, arg3, arg4);
    case TARGET_NR_execve:
        return w32u_execve(arg1, arg2, arg3);
    case TARGET_NR_getpgid:
    case TARGET_NR_getsid:
    case TARGET_NR_setsid:
        /* a single thread: tid == pid, leader of its group and session */
        return GetCurrentProcessId();
    case TARGET_NR_getppid:
        return w32u_vppid;
    case TARGET_NR_setpgid:
        return 0;
    case TARGET_NR_getuid:
    case TARGET_NR_geteuid:
    case TARGET_NR_getgid:
    case TARGET_NR_getegid:
        return W32U_UID;
    case TARGET_NR_umask:
        ret = guest_umask;
        guest_umask = arg1 & 0777;
        return ret;
    case TARGET_NR_uname:
        return sys_uname(arg1);
    case TARGET_NR_sysinfo:
        return sys_sysinfo(arg1);
    case TARGET_NR_getrlimit:
        return sys_prlimit64(arg1, 0, arg2);
    case TARGET_NR_setrlimit:
        return sys_prlimit64(arg1, arg2, 0);
    case TARGET_NR_prlimit64:
        if (arg1 != 0 && arg1 != GetCurrentProcessId()) {
            return -LX_ESRCH;
        }
        ret = sys_prlimit64(arg2, 0, arg4);
        return ret ? ret : sys_prlimit64(arg2, arg3, 0);
    case TARGET_NR_getrusage:
        return sys_getrusage(arg2);
    case TARGET_NR_prctl:
        return sys_prctl(arg1, arg2);
    case TARGET_NR_sched_yield:
        SwitchToThread();
        return 0;
    case TARGET_NR_sched_getaffinity: {
        /* the guest runs on one virtual CPU */
        uint8_t *mask;

        if (arg2 < 8 || (arg2 & 7)) {
            return -LX_EINVAL;
        }
        mask = guest_ptr(arg3, arg2, PAGE_WRITE);
        if (!mask) {
            return -LX_EFAULT;
        }
        memset(mask, 0, arg2);
        mask[0] = 1;
        return 8;
    }
    case TARGET_NR_getcpu: {
        uint32_t zero = 0;

        if (arg1 && put_guest(arg1, &zero, sizeof(zero))) {
            return -LX_EFAULT;
        }
        if (arg2 && put_guest(arg2, &zero, sizeof(zero))) {
            return -LX_EFAULT;
        }
        return 0;
    }

    case TARGET_NR_set_robust_list:
        return 0;
    case TARGET_NR_futex:
        return w32u_futex(arg1, arg2, arg3, arg4, arg5, arg6);
    case TARGET_NR_kill:
        return sys_kill(arg1, arg2);
    case TARGET_NR_tkill:
        return sys_kill(arg1, arg2);
    case TARGET_NR_tgkill:
        return arg1 == GetCurrentProcessId() ? sys_kill(arg2, arg3)
                                            : -LX_ESRCH;
    case TARGET_NR_rt_sigaction:
        return sys_rt_sigaction(arg1, arg2, arg3);
    case TARGET_NR_rt_sigprocmask:
        if (arg3) {
            uint64_t empty = 0;

            return put_guest(arg3, &empty, sizeof(empty));
        }
        return 0;
    case TARGET_NR_sigaltstack:
        if (arg2) {
            /* stack_t: ss_sp, ss_flags = SS_DISABLE, ss_size */
            uint64_t ss[3] = { 0, 2, 0 };

            return put_guest(arg2, ss, sizeof(ss));
        }
        return 0;

    case TARGET_NR_clone:
        /* the order of x86_64; the others: flags, sp, ptid, tls, ctid */
#ifdef TARGET_X86_64
        if ((arg1 & 0x10000) /* CLONE_THREAD */) {
            return w32u_clone_thread(env, arg1, arg2, arg3, arg4, arg5);
        }
#else
        if ((arg1 & 0x10000) /* CLONE_THREAD */) {
            return w32u_clone_thread(env, arg1, arg2, arg3, arg5, arg4);
        }
#endif
#ifdef TARGET_X86_64
        return w32u_fork(env, arg1, arg2, arg3, arg4, arg5);
#else
        return w32u_fork(env, arg1, arg2, arg3, arg5, arg4);
#endif
    case TARGET_NR_clone3:
        /* glibc then uses clone */
    case TARGET_NR_rseq:
        return -LX_ENOSYS;

    default:
        qemu_log_mask(LOG_UNIMP, "Unsupported syscall: %d\n", num);
        return -LX_ENOSYS;
    }
}

abi_long w32u_syscall(CPUArchState *env, int num, abi_long arg1,
                      abi_long arg2, abi_long arg3, abi_long arg4,
                      abi_long arg5, abi_long arg6)
{
    abi_long ret;

    if (w32u_strace) {
        const char *name = num >= 0 && num < ARRAY_SIZE(syscall_names)
                           ? syscall_names[num] : NULL;

        if (name) {
            qemu_log("%lu %s(", GetCurrentProcessId(), name);
        } else {
            qemu_log("%lu syscall_%d(", GetCurrentProcessId(), num);
        }
        qemu_log("0x" TARGET_ABI_FMT_lx ",0x" TARGET_ABI_FMT_lx ",0x"
                 TARGET_ABI_FMT_lx ",0x" TARGET_ABI_FMT_lx ",0x"
                 TARGET_ABI_FMT_lx ",0x" TARGET_ABI_FMT_lx ")",
                 arg1, arg2, arg3, arg4, arg5, arg6);
        if (num == TARGET_NR_exit || num == TARGET_NR_exit_group) {
            qemu_log("\n");
        }
    }
    ret = do_syscall(env, num, arg1, arg2, arg3, arg4, arg5, arg6);
    if (w32u_strace) {
        if (ret < 0 && ret >= -4095) {
            qemu_log(" = -1 errno=" TARGET_ABI_FMT_ld "\n", -ret);
        } else {
            qemu_log(" = 0x" TARGET_ABI_FMT_lx "\n", ret);
        }
    }
    return ret;
}

static void restore_console_cp(void)
{
    SetConsoleOutputCP(saved_console_cp);
}

abi_long w32u_get_guest(abi_ulong addr, void *buf, size_t len)
{
    void *p = guest_ptr(addr, len, PAGE_READ);

    if (!p) {
        return -LX_EFAULT;
    }
    memcpy(buf, p, len);
    return 0;
}

abi_long w32u_put_guest(abi_ulong addr, const void *buf, size_t len)
{
    return put_guest(addr, buf, len);
}

abi_long w32u_get_guest_str(abi_ulong addr, char **out)
{
    return get_guest_str(addr, out);
}

const char *w32u_exec_path(void)
{
    return exec_host_path;
}

/*
 * The descriptors a new process gets (all for fork, without the
 * close-on-exec ones for execve): inheritable copies of their handles in
 * @inherit, @std for its standard handles, and their description:
 * "fd kind flags cloexec handle path-in-hex;" for each
 */
char *w32u_fds_export(GArray *inherit, bool exec, HANDLE std[3])
{
    GString *s = g_string_new(NULL);
    int fd;

    for (fd = 0; fd < W32U_MAX_FDS; fd++) {
        GuestFD *f = &fds[fd];
        HANDLE dup = NULL;
        const char *p;

        if (f->kind == FD_FREE || (exec && f->cloexec)) {
            continue;
        }
        if (f->kind == FD_HOST &&
            !DuplicateHandle(GetCurrentProcess(), fd_handle(f),
                             GetCurrentProcess(), &dup, 0, TRUE,
                             DUPLICATE_SAME_ACCESS)) {
            continue;
        }
        if (dup) {
            g_array_append_val(inherit, dup);
            if (fd < 3) {
                std[fd] = dup;
            }
        }
        g_string_append_printf(s, "%d %d %d %d %llu ", fd, f->kind, f->flags,
                               !exec && f->cloexec,
                               (unsigned long long)(uintptr_t)dup);
        for (p = f->path ? f->path : ""; *p; p++) {
            g_string_append_printf(s, "%02x", (uint8_t)*p);
        }
        g_string_append(s, "-;");
    }
    return g_string_free(s, false);
}

static void fds_import(const char *spec)
{
    g_auto(GStrv) items = g_strsplit(spec, ";", -1);
    int i;

    for (i = 0; items[i]; i++) {
        int fd, kind, flags, cloexec, n = 0;
        unsigned long long h;
        char hex[2 * PATH_MAX + 2] = "";
        GString *path;
        const char *p;

        if (sscanf(items[i], "%d %d %d %d %llu %n", &fd, &kind, &flags,
                   &cloexec, &h, &n) < 5 || fd < 0 || fd >= W32U_MAX_FDS) {
            continue;
        }
        pstrcpy(hex, sizeof(hex), items[i] + n);
        path = g_string_new(NULL);
        for (p = hex; p[0] && p[1] && p[0] != '-'; p += 2) {
            g_string_append_c(path, g_ascii_xdigit_value(p[0]) * 16 +
                                    g_ascii_xdigit_value(p[1]));
        }
        fds[fd] = (GuestFD) {
            .kind = kind,
            .flags = flags,
            .cloexec = cloexec,
            .path = path->len ? g_string_free(path, false) : NULL,
        };
        if (!fds[fd].path) {
            g_string_free(path, true);
        }
        if (kind == FD_HOST) {
            int acc = (flags & LX_O_ACCMODE) == LX_O_RDONLY ? _O_RDONLY :
                      (flags & LX_O_ACCMODE) == LX_O_WRONLY ? _O_WRONLY :
                      _O_RDWR;

            fds[fd].host = _open_osfhandle((intptr_t)h, acc | _O_BINARY);
            if (fds[fd].host < 0) {
                memset(&fds[fd], 0, sizeof(fds[fd]));
            }
        }
    }
}

/* execve: what this process had goes, the new program has its own */
void w32u_fds_close_all(void)
{
    int fd;

    for (fd = 0; fd < W32U_MAX_FDS; fd++) {
        if (fds[fd].kind != FD_FREE) {
            release_fd(&fds[fd]);
        }
    }
}

void w32u_syscall_init_launch(const char *exec_path, const char *spec)
{
    w32u_syscall_init(exec_path);
    if (spec) {
        int fd;

        /* the guest's descriptors, not the host stdio */
        for (fd = 0; fd < 3; fd++) {
            memset(&fds[fd], 0, sizeof(fds[fd]));
        }
        fds_import(spec);
    }
}

void w32u_syscall_init(const char *exec_path)
{
    int i;

    exec_host_path = g_canonicalize_filename(exec_path, NULL);

    /* guest 0, 1, 2 are the host stdio, in binary mode */
    for (i = 0; i < 3; i++) {
        if (_get_osfhandle(i) == (intptr_t)INVALID_HANDLE_VALUE ||
            _get_osfhandle(i) == -2) {
            continue;
        }
        _setmode(i, _O_BINARY);
        fds[i] = (GuestFD) {
            .kind = FD_HOST,
            .host = i,
            .flags = i == 0 ? LX_O_RDONLY : LX_O_WRONLY,
        };
        if (is_console(&fds[i])) {
            fds[i].flags = LX_O_RDWR;
        }
    }

    /* guest programs write UTF-8 */
    saved_console_cp = GetConsoleOutputCP();
    if (saved_console_cp && saved_console_cp != CP_UTF8 &&
        SetConsoleOutputCP(CP_UTF8)) {
        atexit(restore_console_cp);
    }
}
