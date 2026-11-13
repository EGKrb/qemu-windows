/*
 * 9p on Windows: the POSIX file functions 9p-local.c uses, on the native
 * API of NT.  See fsdev/9p-win32.h for the conventions (WSL's metadata).
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "fsdev/file-op-9p.h"
#include "qemu/thread.h"
#include "qemu/bswap.h"
#include "9p-util.h"
#include <winioctl.h>
#include <winternl.h>

/* ------------------------------------------------------------------ */
/* The native API, loaded from ntdll.dll                               */

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} P9UnicodeString;

typedef struct {
    ULONG Length;
    HANDLE RootDirectory;
    P9UnicodeString *ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} P9ObjectAttributes;

typedef struct {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} P9IoStatusBlock;

typedef NTSTATUS (NTAPI *NtCreateFileFn)(PHANDLE, ACCESS_MASK,
    P9ObjectAttributes *, P9IoStatusBlock *, PLARGE_INTEGER, ULONG, ULONG,
    ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtQueryInformationFileFn)(HANDLE, P9IoStatusBlock *,
    PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtSetInformationFileFn)(HANDLE, P9IoStatusBlock *,
    PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtQueryDirectoryFileFn)(HANDLE, HANDLE, PVOID, PVOID,
    P9IoStatusBlock *, PVOID, ULONG, ULONG, BOOLEAN, P9UnicodeString *,
    BOOLEAN);
typedef NTSTATUS (NTAPI *NtQueryVolumeInformationFileFn)(HANDLE,
    P9IoStatusBlock *, PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtQueryEaFileFn)(HANDLE, P9IoStatusBlock *, PVOID,
    ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN);
typedef NTSTATUS (NTAPI *NtSetEaFileFn)(HANDLE, P9IoStatusBlock *, PVOID,
    ULONG);
typedef NTSTATUS (NTAPI *NtFsControlFileFn)(HANDLE, HANDLE, PVOID, PVOID,
    P9IoStatusBlock *, ULONG, PVOID, ULONG, PVOID, ULONG);

static struct {
    NtCreateFileFn CreateFile;
    NtQueryInformationFileFn QueryInformationFile;
    NtSetInformationFileFn SetInformationFile;
    NtQueryDirectoryFileFn QueryDirectoryFile;
    NtQueryVolumeInformationFileFn QueryVolumeInformationFile;
    NtQueryEaFileFn QueryEaFile;
    NtSetEaFileFn SetEaFile;
    NtFsControlFileFn FsControlFile;
} nt;

static void nt_init(void)
{
    static gsize once;

    if (g_once_init_enter(&once)) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

        nt.CreateFile = (NtCreateFileFn)
            GetProcAddress(ntdll, "NtCreateFile");
        nt.QueryInformationFile = (NtQueryInformationFileFn)
            GetProcAddress(ntdll, "NtQueryInformationFile");
        nt.SetInformationFile = (NtSetInformationFileFn)
            GetProcAddress(ntdll, "NtSetInformationFile");
        nt.QueryDirectoryFile = (NtQueryDirectoryFileFn)
            GetProcAddress(ntdll, "NtQueryDirectoryFile");
        nt.QueryVolumeInformationFile = (NtQueryVolumeInformationFileFn)
            GetProcAddress(ntdll, "NtQueryVolumeInformationFile");
        nt.QueryEaFile = (NtQueryEaFileFn)
            GetProcAddress(ntdll, "NtQueryEaFile");
        nt.SetEaFile = (NtSetEaFileFn)
            GetProcAddress(ntdll, "NtSetEaFile");
        nt.FsControlFile = (NtFsControlFileFn)
            GetProcAddress(ntdll, "NtFsControlFile");
        g_once_init_leave(&once, 1);
    }
}

/* NTSTATUS values used here */
#define P9_STATUS_BUFFER_OVERFLOW          ((NTSTATUS)0x80000005L)
#define P9_STATUS_NO_MORE_FILES            ((NTSTATUS)0x80000006L)
#define P9_STATUS_NO_MORE_EAS              ((NTSTATUS)0x80000012L)
#define P9_STATUS_INVALID_INFO_CLASS       ((NTSTATUS)0xC0000003L)
#define P9_STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define P9_STATUS_NO_SUCH_FILE             ((NTSTATUS)0xC000000FL)
#define P9_STATUS_END_OF_FILE              ((NTSTATUS)0xC0000011L)
#define P9_STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define P9_STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define P9_STATUS_OBJECT_NAME_INVALID      ((NTSTATUS)0xC0000033L)
#define P9_STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define P9_STATUS_OBJECT_NAME_COLLISION    ((NTSTATUS)0xC0000035L)
#define P9_STATUS_OBJECT_PATH_NOT_FOUND    ((NTSTATUS)0xC000003AL)
#define P9_STATUS_OBJECT_PATH_SYNTAX_BAD   ((NTSTATUS)0xC000003BL)
#define P9_STATUS_SHARING_VIOLATION        ((NTSTATUS)0xC0000043L)
#define P9_STATUS_EA_TOO_LARGE             ((NTSTATUS)0xC0000050L)
#define P9_STATUS_NONEXISTENT_EA_ENTRY     ((NTSTATUS)0xC0000051L)
#define P9_STATUS_NO_EAS_ON_FILE           ((NTSTATUS)0xC0000052L)
#define P9_STATUS_EA_CORRUPT_ERROR         ((NTSTATUS)0xC0000053L)
#define P9_STATUS_DELETE_PENDING           ((NTSTATUS)0xC0000056L)
#define P9_STATUS_DISK_FULL                ((NTSTATUS)0xC000007FL)
#define P9_STATUS_FILE_IS_A_DIRECTORY      ((NTSTATUS)0xC00000BAL)
#define P9_STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#define P9_STATUS_NOT_SAME_DEVICE          ((NTSTATUS)0xC00000D4L)
#define P9_STATUS_FILE_RENAMED             ((NTSTATUS)0xC00000D5L)
#define P9_STATUS_DIRECTORY_NOT_EMPTY      ((NTSTATUS)0xC0000101L)
#define P9_STATUS_NOT_A_DIRECTORY          ((NTSTATUS)0xC0000103L)
#define P9_STATUS_NAME_TOO_LONG            ((NTSTATUS)0xC0000106L)
#define P9_STATUS_CANNOT_DELETE            ((NTSTATUS)0xC0000121L)
#define P9_STATUS_FILE_DELETED             ((NTSTATUS)0xC0000123L)
#define P9_STATUS_MEDIA_WRITE_PROTECTED    ((NTSTATUS)0xC00000A2L)
#define P9_STATUS_NOT_A_REPARSE_POINT      ((NTSTATUS)0xC0000275L)
#define P9_STATUS_IO_REPARSE_TAG_NOT_HANDLED ((NTSTATUS)0xC0000279L)
#define P9_STATUS_STOPPED_ON_SYMLINK       ((NTSTATUS)0x8000002DL)
#define P9_STATUS_TOO_MANY_LINKS           ((NTSTATUS)0xC0000265L)
#define P9_STATUS_INVALID_DEVICE_REQUEST   ((NTSTATUS)0xC0000010L)
#define P9_STATUS_PRIVILEGE_NOT_HELD       ((NTSTATUS)0xC0000061L)
#define P9_STATUS_LOCK_NOT_GRANTED         ((NTSTATUS)0xC0000055L)
#define P9_STATUS_FILE_LOCK_CONFLICT       ((NTSTATUS)0xC0000054L)

static int nt_errno(NTSTATUS s)
{
    switch (s) {
    case P9_STATUS_NO_SUCH_FILE:
    case P9_STATUS_OBJECT_NAME_NOT_FOUND:
    case P9_STATUS_OBJECT_PATH_NOT_FOUND:
    case P9_STATUS_DELETE_PENDING:
    case P9_STATUS_FILE_DELETED:
    case P9_STATUS_FILE_RENAMED:
        return ENOENT;
    case P9_STATUS_OBJECT_NAME_COLLISION:
        return EEXIST;
    case P9_STATUS_ACCESS_DENIED:
    case P9_STATUS_SHARING_VIOLATION:
    case P9_STATUS_LOCK_NOT_GRANTED:
    case P9_STATUS_FILE_LOCK_CONFLICT:
        return EACCES;
    case P9_STATUS_CANNOT_DELETE:
    case P9_STATUS_PRIVILEGE_NOT_HELD:
        return EPERM;
    case P9_STATUS_OBJECT_NAME_INVALID:
    case P9_STATUS_OBJECT_PATH_SYNTAX_BAD:
    case P9_STATUS_INVALID_PARAMETER:
        return EINVAL;
    case P9_STATUS_FILE_IS_A_DIRECTORY:
        return EISDIR;
    case P9_STATUS_NOT_A_DIRECTORY:
        return ENOTDIR;
    case P9_STATUS_DIRECTORY_NOT_EMPTY:
        return ENOTEMPTY;
    case P9_STATUS_DISK_FULL:
        return ENOSPC;
    case P9_STATUS_NAME_TOO_LONG:
        return ENAMETOOLONG;
    case P9_STATUS_NOT_SAME_DEVICE:
        return EXDEV;
    case P9_STATUS_STOPPED_ON_SYMLINK:
    case P9_STATUS_IO_REPARSE_TAG_NOT_HANDLED:
        return ELOOP;
    case P9_STATUS_NOT_SUPPORTED:
    case P9_STATUS_INVALID_INFO_CLASS:
    case P9_STATUS_INVALID_DEVICE_REQUEST:
        return EOPNOTSUPP;
    case P9_STATUS_MEDIA_WRITE_PROTECTED:
        return EROFS;
    case P9_STATUS_TOO_MANY_LINKS:
        return EMLINK;
    case P9_STATUS_EA_TOO_LARGE:
        return ENOSPC;
    case P9_STATUS_NONEXISTENT_EA_ENTRY:
    case P9_STATUS_NO_EAS_ON_FILE:
        return ENODATA;
    case P9_STATUS_NOT_A_REPARSE_POINT:
        return EINVAL;
    default:
        return EIO;
    }
}

static int set_nt_errno(NTSTATUS s)
{
    errno = nt_errno(s);
    return -1;
}

/* the information classes */
#define P9FileBasicInformation          4
#define P9FileRenameInformation         10
#define P9FileLinkInformation           11
#define P9FileDispositionInformation    13
#define P9FileAttributeTagInformation   35
#define P9FileIdBothDirectoryInformation 37
#define P9FileDispositionInformationEx  64
#define P9FileRenameInformationEx       65
#define P9FileStatInformation           68
#define P9FileCaseSensitiveInformation  71
#define P9FileFsVolumeInformation       1
#define P9FileFsFullSizeInformation     7

typedef struct {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} P9FileBasicInfo;

typedef struct {
    LARGE_INTEGER FileId;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
    ULONG ReparseTag;
    ULONG NumberOfLinks;
    ACCESS_MASK EffectiveAccess;
} P9FileStatInfo;

typedef struct {
    ULONG Flags;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} P9FileRenameInfo;

typedef struct {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;           /* the reparse tag of reparse points */
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} P9FileIdBothDirInfo;

typedef struct {
    LARGE_INTEGER VolumeCreationTime;
    ULONG VolumeSerialNumber;
    ULONG VolumeLabelLength;
    BOOLEAN SupportsObjects;
    WCHAR VolumeLabel[64];
} P9FileFsVolumeInfo;

typedef struct {
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER CallerAvailableAllocationUnits;
    LARGE_INTEGER ActualAvailableAllocationUnits;
    ULONG SectorsPerAllocationUnit;
    ULONG BytesPerSector;
} P9FileFsFullSizeInfo;

typedef struct {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} P9FullEaInfo;

typedef struct {
    ULONG NextEntryOffset;
    UCHAR EaNameLength;
    CHAR EaName[1];
} P9GetEaInfo;

#define P9_FILE_DISPOSITION_DELETE                     0x1
#define P9_FILE_DISPOSITION_POSIX_SEMANTICS            0x2
#define P9_FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE  0x10
#define P9_FILE_RENAME_REPLACE_IF_EXISTS               0x1
#define P9_FILE_RENAME_POSIX_SEMANTICS                 0x2
#define P9_FILE_RENAME_IGNORE_READONLY_ATTRIBUTE       0x40
#define P9_FILE_CS_FLAG_CASE_SENSITIVE_DIR             0x1

/* NtCreateFile() dispositions and options */
#define P9_FILE_SUPERSEDE           0
#define P9_FILE_OPEN                1
#define P9_FILE_CREATE              2
#define P9_FILE_OPEN_IF             3
#define P9_FILE_OVERWRITE           4
#define P9_FILE_OVERWRITE_IF        5
#define P9_FILE_DIRECTORY_FILE      0x00000001
#define P9_FILE_WRITE_THROUGH       0x00000002
#define P9_FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define P9_FILE_NON_DIRECTORY_FILE  0x00000040
#define P9_FILE_OPEN_REPARSE_POINT  0x00200000
#define P9_FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define P9_OBJ_CASE_INSENSITIVE     0x00000040

/* the reparse tags of WSL and of Windows links */
#define P9_TAG_SYMLINK      0xA000000CUL
#define P9_TAG_MOUNT_POINT  0xA0000003UL
#define P9_TAG_LX_SYMLINK   0xA000001DUL
#define P9_TAG_AF_UNIX      0x80000023UL
#define P9_TAG_LX_FIFO      0x80000024UL
#define P9_TAG_LX_CHR       0x80000025UL
#define P9_TAG_LX_BLK       0x80000026UL

static bool tag_is_link(ULONG tag)
{
    return tag == P9_TAG_SYMLINK || tag == P9_TAG_MOUNT_POINT ||
           tag == P9_TAG_LX_SYMLINK;
}

/* ------------------------------------------------------------------ */
/* Names: UTF-8 of the guest <-> UTF-16 of NTFS                        */

static bool name_char_mapped(gunichar c)
{
    return c < 0x20 || c == '\\' || c == ':' || c == '*' || c == '?' ||
           c == '"' || c == '<' || c == '>' || c == '|';
}

/* @name: one component; "." is the directory itself (an empty name) */
static gunichar2 *name_to_nt(const char *name, size_t *len)
{
    GString *s;
    const char *p;
    gunichar2 *w;
    glong n;

    if (strcmp(name, ".") == 0) {
        *len = 0;
        return g_new0(gunichar2, 1);
    }
    if (!*name || strcmp(name, "..") == 0 || strchr(name, '/') ||
        !g_utf8_validate(name, -1, NULL)) {
        errno = strcmp(name, "..") == 0 ? EACCES : EINVAL;
        return NULL;
    }
    s = g_string_new(NULL);
    for (p = name; *p; p = g_utf8_next_char(p)) {
        gunichar c = g_utf8_get_char(p);

        g_string_append_unichar(s, name_char_mapped(c) ? 0xF000 + c : c);
    }
    w = g_utf8_to_utf16(s->str, -1, NULL, &n, NULL);
    g_string_free(s, TRUE);
    if (!w) {
        errno = EINVAL;
        return NULL;
    }
    if (n > 255) {
        g_free(w);
        errno = ENAMETOOLONG;
        return NULL;
    }
    *len = n;
    return w;
}

static char *name_from_nt(const WCHAR *w, size_t chars)
{
    g_autofree char *utf8 = g_utf16_to_utf8((const gunichar2 *)w, chars,
                                            NULL, NULL, NULL);
    GString *s;
    const char *p;

    if (!utf8) {
        return g_strdup("?");
    }
    s = g_string_new(NULL);
    for (p = utf8; *p; p = g_utf8_next_char(p)) {
        gunichar c = g_utf8_get_char(p);

        if (c >= 0xF000 && c < 0xF080 && name_char_mapped(c - 0xF000)) {
            c -= 0xF000;
        }
        g_string_append_unichar(s, c);
    }
    return g_string_free(s, FALSE);
}

/* ------------------------------------------------------------------ */
/* Handles and descriptors                                             */

static HANDLE fd_handle(int fd)
{
    if (fd == AT_FDCWD) {
        return NULL;
    }
    return (HANDLE)_get_osfhandle(fd);
}

/* the open() flags of our descriptors, for fcntl(F_GETFL) and O_APPEND */
static GHashTable *fd_flags;
static QemuMutex fd_flags_lock;

static void fd_flags_set(int fd, int flags)
{
    static gsize once;

    if (g_once_init_enter(&once)) {
        qemu_mutex_init(&fd_flags_lock);
        fd_flags = g_hash_table_new(NULL, NULL);
        g_once_init_leave(&once, 1);
    }
    qemu_mutex_lock(&fd_flags_lock);
    /* the handle is kept too: a descriptor number is reused */
    g_hash_table_insert(fd_flags, GINT_TO_POINTER(fd),
                        GINT_TO_POINTER(flags));
    g_hash_table_insert(fd_flags, GINT_TO_POINTER(-2 - fd), fd_handle(fd));
    qemu_mutex_unlock(&fd_flags_lock);
}

static int fd_flags_get(int fd)
{
    int flags = 0;

    if (!fd_flags) {
        return 0;
    }
    qemu_mutex_lock(&fd_flags_lock);
    if (g_hash_table_lookup(fd_flags, GINT_TO_POINTER(-2 - fd)) ==
        fd_handle(fd)) {
        flags = GPOINTER_TO_INT(g_hash_table_lookup(fd_flags,
                                                    GINT_TO_POINTER(fd)));
    }
    qemu_mutex_unlock(&fd_flags_lock);
    return flags;
}

/*
 * Open @name relative to the directory handle @root (NULL: @name is a path
 * of Windows), never following links: the link itself is opened.
 */
static NTSTATUS nt_open(HANDLE root, const char *name, ACCESS_MASK access,
                        ULONG disposition, ULONG options, ULONG attributes,
                        HANDLE *h)
{
    P9UnicodeString us;
    P9ObjectAttributes oa = { sizeof(oa) };
    P9IoStatusBlock iosb;
    g_autofree gunichar2 *w = NULL;
    size_t len;
    NTSTATUS s;

    nt_init();
    if (!root) {
        /* a path of Windows (the root of the export) */
        g_autofree gunichar2 *path = g_utf8_to_utf16(name, -1, NULL, NULL,
                                                     NULL);
        /* as open(): the root of the export may be a link */
        DWORD flags = FILE_FLAG_BACKUP_SEMANTICS;

        if (!path) {
            return P9_STATUS_OBJECT_NAME_INVALID;
        }
        *h = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE |
                         FILE_SHARE_DELETE, NULL, OPEN_EXISTING, flags, NULL);
        if (*h == INVALID_HANDLE_VALUE) {
            switch (GetLastError()) {
            case ERROR_FILE_NOT_FOUND:
            case ERROR_PATH_NOT_FOUND:
                return P9_STATUS_OBJECT_NAME_NOT_FOUND;
            case ERROR_ACCESS_DENIED:
                return P9_STATUS_ACCESS_DENIED;
            default:
                return P9_STATUS_INVALID_PARAMETER;
            }
        }
        return 0;
    }

    w = name_to_nt(name, &len);
    if (!w) {
        return errno == ENAMETOOLONG ? P9_STATUS_NAME_TOO_LONG :
               errno == EACCES ? P9_STATUS_ACCESS_DENIED :
               P9_STATUS_OBJECT_NAME_INVALID;
    }
    us.Buffer = (PWSTR)w;
    us.Length = us.MaximumLength = len * sizeof(WCHAR);
    oa.RootDirectory = root;
    oa.ObjectName = &us;
    s = nt.CreateFile(h, access | SYNCHRONIZE, &oa, &iosb, NULL, attributes,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      disposition,
                      options | P9_FILE_SYNCHRONOUS_IO_NONALERT |
                      P9_FILE_OPEN_REPARSE_POINT |
                      P9_FILE_OPEN_FOR_BACKUP_INTENT,
                      NULL, 0);
    return s;
}

/* A new handle to what @h is open on, with @access */
static NTSTATUS nt_reopen(HANDLE h, ACCESS_MASK access, HANDLE *out)
{
    return nt_open(h, ".", access, P9_FILE_OPEN, 0, 0, out);
}

static NTSTATUS nt_stat_info(HANDLE h, P9FileStatInfo *info)
{
    P9IoStatusBlock iosb;

    return nt.QueryInformationFile(h, &iosb, info, sizeof(*info),
                                   P9FileStatInformation);
}

/* ------------------------------------------------------------------ */
/* Extended attributes                                                 */

/* Read the EA @name of @h into @value (@size bytes); its size or -errno */
static ssize_t ea_get(HANDLE h, const char *name, void *value, size_t size)
{
    char list[sizeof(P9GetEaInfo) + 256];
    P9GetEaInfo *gi = (P9GetEaInfo *)list;
    size_t buflen = sizeof(P9FullEaInfo) + 256 + 65536;
    g_autofree char *buf = g_malloc(buflen);
    P9FullEaInfo *ea = (P9FullEaInfo *)buf;
    P9IoStatusBlock iosb;
    size_t nlen = strlen(name);
    NTSTATUS s;

    if (nlen > 255) {
        return -ERANGE;
    }
    memset(list, 0, sizeof(list));
    gi->EaNameLength = nlen;
    memcpy(gi->EaName, name, nlen + 1);
    s = nt.QueryEaFile(h, &iosb, buf, buflen, TRUE, gi,
                       sizeof(P9GetEaInfo) + nlen, NULL, TRUE);
    if (!NT_SUCCESS(s)) {
        return -nt_errno(s);
    }
    if (ea->EaValueLength == 0) {
        /* NT gives an empty value for an EA that is not there */
        return -ENODATA;
    }
    if (size == 0) {
        return ea->EaValueLength;
    }
    if (size < ea->EaValueLength) {
        return -ERANGE;
    }
    memcpy(value, ea->EaName + ea->EaNameLength + 1, ea->EaValueLength);
    return ea->EaValueLength;
}

/* Set (or with @size == 0, remove) the EA @name of @h */
static int ea_set(HANDLE h, const char *name, const void *value, size_t size)
{
    size_t nlen = strlen(name);
    size_t len = sizeof(P9FullEaInfo) + nlen + 1 + size;
    g_autofree char *buf = NULL;
    P9FullEaInfo *ea;
    P9IoStatusBlock iosb;
    NTSTATUS s;

    if (nlen > 255 || size > 65535) {
        return -ERANGE;
    }
    buf = g_malloc0(len);
    ea = (P9FullEaInfo *)buf;
    ea->EaNameLength = nlen;
    ea->EaValueLength = size;
    memcpy(ea->EaName, name, nlen + 1);
    if (size) {
        memcpy(ea->EaName + nlen + 1, value, size);
    }
    s = nt.SetEaFile(h, &iosb, buf, len);
    return NT_SUCCESS(s) ? 0 : -nt_errno(s);
}

/*
 * The names of extended attributes of Linux are case sensitive, those of
 * NT are not (and are stored in upper case): they are kept as "Q9." and
 * their base 32 (digits and upper case letters only).
 */
#define XATTR_EA_PREFIX "Q9."
static const char b32[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

static char *xattr_to_ea(const char *name)
{
    GString *s = g_string_new(XATTR_EA_PREFIX);
    uint32_t acc = 0;
    int bits = 0;
    const unsigned char *p;

    for (p = (const unsigned char *)name; *p; p++) {
        acc = (acc << 8) | *p;
        bits += 8;
        while (bits >= 5) {
            g_string_append_c(s, b32[(acc >> (bits - 5)) & 31]);
            bits -= 5;
        }
    }
    if (bits) {
        g_string_append_c(s, b32[(acc << (5 - bits)) & 31]);
    }
    return g_string_free(s, FALSE);
}

static char *ea_to_xattr(const char *ea, size_t len)
{
    GString *s;
    uint32_t acc = 0;
    int bits = 0;
    size_t i;

    if (len < 3 || g_ascii_strncasecmp(ea, XATTR_EA_PREFIX, 3)) {
        return NULL;
    }
    s = g_string_new(NULL);
    for (i = 3; i < len; i++) {
        const char *d = strchr(b32, g_ascii_toupper(ea[i]));

        if (!d || !*d) {
            g_string_free(s, TRUE);
            return NULL;
        }
        acc = (acc << 5) | (d - b32);
        bits += 5;
        if (bits >= 8) {
            g_string_append_c(s, (acc >> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return g_string_free(s, FALSE);
}

static ssize_t xattr_get(HANDLE h, const char *name, void *value,
                         size_t size)
{
    g_autofree char *ea = xattr_to_ea(name);
    ssize_t ret = ea_get(h, ea, value, size);

    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static int xattr_set(HANDLE h, const char *name, const void *value,
                     size_t size, int flags)
{
    g_autofree char *ea = xattr_to_ea(name);
    ssize_t exists = ea_get(h, ea, NULL, 0);
    char empty = 0;
    int ret;

    if ((flags & XATTR_CREATE) && exists >= 0) {
        errno = EEXIST;
        return -1;
    }
    if ((flags & XATTR_REPLACE) && exists < 0) {
        errno = ENODATA;
        return -1;
    }
    /*
     * An empty value would remove the EA: it is kept as one byte 0,
     * which xattr_get() cannot tell apart; Linux rarely has empty values
     */
    ret = size ? ea_set(h, ea, value, size) : ea_set(h, ea, &empty, 1);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return 0;
}

static int xattr_remove(HANDLE h, const char *name)
{
    g_autofree char *ea = xattr_to_ea(name);
    int ret;

    if (ea_get(h, ea, NULL, 0) < 0) {
        errno = ENODATA;
        return -1;
    }
    ret = ea_set(h, ea, NULL, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return 0;
}

static ssize_t xattr_list(HANDLE h, char *list, size_t size)
{
    size_t buflen = 128 * 1024;
    g_autofree char *buf = g_malloc(buflen);
    P9IoStatusBlock iosb;
    GString *out = g_string_new(NULL);
    BOOLEAN restart = TRUE;
    ssize_t ret;

    for (;;) {
        NTSTATUS s = nt.QueryEaFile(h, &iosb, buf, buflen, FALSE, NULL, 0,
                                    NULL, restart);
        P9FullEaInfo *ea = (P9FullEaInfo *)buf;

        restart = FALSE;
        if (s == P9_STATUS_NO_EAS_ON_FILE || s == P9_STATUS_NO_MORE_EAS) {
            break;
        }
        if (!NT_SUCCESS(s)) {
            g_string_free(out, TRUE);
            errno = nt_errno(s);
            return -1;
        }
        for (;;) {
            g_autofree char *name = ea_to_xattr(ea->EaName,
                                                ea->EaNameLength);

            if (name) {
                g_string_append_len(out, name, strlen(name) + 1);
            }
            if (!ea->NextEntryOffset) {
                break;
            }
            ea = (P9FullEaInfo *)((char *)ea + ea->NextEntryOffset);
        }
        if (s != P9_STATUS_BUFFER_OVERFLOW) {
            break;
        }
    }
    ret = out->len;
    if (size) {
        if (size < out->len) {
            g_string_free(out, TRUE);
            errno = ERANGE;
            return -1;
        }
        memcpy(list, out->str, out->len);
    }
    g_string_free(out, TRUE);
    return ret;
}

/* The metadata of Linux files, as WSL keeps them */
#define LX_UID "$LXUID"
#define LX_GID "$LXGID"
#define LX_MOD "$LXMOD"
#define LX_DEV "$LXDEV"

/* ------------------------------------------------------------------ */
/* stat                                                                */

static void nt_time_to_timespec(LARGE_INTEGER t, struct timespec *ts)
{
    /* 100 ns since 1601 */
    int64_t v = t.QuadPart - INT64_C(116444736000000000);

    ts->tv_sec = v / 10000000;
    ts->tv_nsec = (v % 10000000) * 100;
    if (ts->tv_nsec < 0) {
        ts->tv_sec--;
        ts->tv_nsec += 1000000000;
    }
}

static int handle_stat(HANDLE h, struct p9_stat *st)
{
    P9FileStatInfo info;
    P9FileFsVolumeInfo vol;
    P9IoStatusBlock iosb;
    uint32_t v32;
    uint32_t dev[2];
    NTSTATUS s;

    nt_init();
    s = nt_stat_info(h, &info);
    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    memset(st, 0, sizeof(*st));
    s = nt.QueryVolumeInformationFile(h, &iosb, &vol, sizeof(vol),
                                      P9FileFsVolumeInformation);
    if (NT_SUCCESS(s) || s == P9_STATUS_BUFFER_OVERFLOW) {
        st->st_dev = vol.VolumeSerialNumber;
    }
    st->st_ino = info.FileId.QuadPart;
    st->st_nlink = info.NumberOfLinks;
    st->st_size = info.EndOfFile.QuadPart;
    st->st_blksize = 4096;
    st->st_blocks = (info.AllocationSize.QuadPart + 511) / 512;
    nt_time_to_timespec(info.LastAccessTime, &st->st_atim);
    nt_time_to_timespec(info.LastWriteTime, &st->st_mtim);
    nt_time_to_timespec(info.ChangeTime, &st->st_ctim);

    if (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        switch (info.ReparseTag) {
        case P9_TAG_SYMLINK:
        case P9_TAG_MOUNT_POINT:
        case P9_TAG_LX_SYMLINK:
            st->st_mode = S_IFLNK | 0777;
            break;
        case P9_TAG_LX_FIFO:
            st->st_mode = S_IFIFO | 0644;
            break;
        case P9_TAG_LX_CHR:
            st->st_mode = S_IFCHR | 0644;
            break;
        case P9_TAG_LX_BLK:
            st->st_mode = S_IFBLK | 0644;
            break;
        case P9_TAG_AF_UNIX:
            st->st_mode = S_IFSOCK | 0755;
            break;
        default:
            st->st_mode = (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ?
                          S_IFDIR | 0755 : S_IFREG | 0644;
            break;
        }
    } else if (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        st->st_mode = S_IFDIR | 0755;
    } else {
        st->st_mode = S_IFREG | 0644;
    }
    if (info.FileAttributes & FILE_ATTRIBUTE_READONLY &&
        !S_ISLNK(st->st_mode)) {
        st->st_mode &= ~0222;
    }

    /* the metadata of Linux, if any */
    if (ea_get(h, LX_MOD, &v32, sizeof(v32)) == sizeof(v32)) {
        st->st_mode = (st->st_mode & S_IFMT) | (le32_to_cpu(v32) & 07777);
    }
    if (ea_get(h, LX_UID, &v32, sizeof(v32)) == sizeof(v32)) {
        st->st_uid = le32_to_cpu(v32);
    }
    if (ea_get(h, LX_GID, &v32, sizeof(v32)) == sizeof(v32)) {
        st->st_gid = le32_to_cpu(v32);
    }
    if ((S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode)) &&
        ea_get(h, LX_DEV, dev, sizeof(dev)) == sizeof(dev)) {
        st->st_rdev = makedev_dotl(le32_to_cpu(dev[0]), le32_to_cpu(dev[1]));
    }
    return 0;
}

int p9_fstat(int fd, struct p9_stat *st)
{
    HANDLE h = fd_handle(fd);

    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    return handle_stat(h, st);
}

int fstatat(int dirfd, const char *name, struct p9_stat *st, int flags)
{
    HANDLE h;
    NTSTATUS s;
    int ret;

    if ((flags & AT_EMPTY_PATH) && !*name) {
        return p9_fstat(dirfd, st);
    }
    s = nt_open(fd_handle(dirfd), name, FILE_READ_ATTRIBUTES | FILE_READ_EA,
                P9_FILE_OPEN, 0, 0, &h);
    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = handle_stat(h, st);
    CloseHandle(h);
    return ret;
}

int p9_lstat(const char *path, struct p9_stat *st)
{
    return fstatat(AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW);
}

/* ------------------------------------------------------------------ */
/* open                                                                */

static int handle_to_fd(HANDLE h, int flags)
{
    int crt = _O_BINARY;
    int fd;

    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        crt |= _O_RDONLY;
        break;
    case O_WRONLY:
        crt |= _O_WRONLY;
        break;
    default:
        crt |= _O_RDWR;
        break;
    }
    if (flags & O_APPEND) {
        crt |= _O_APPEND;
    }
    fd = _open_osfhandle((intptr_t)h, crt);
    if (fd < 0) {
        CloseHandle(h);
        errno = EMFILE;
        return -1;
    }
    fd_flags_set(fd, flags);
    return fd;
}

int openat(int dirfd, const char *name, int flags, ...)
{
    ACCESS_MASK access = FILE_READ_ATTRIBUTES | FILE_READ_EA;
    ULONG disposition = P9_FILE_OPEN;
    ULONG options = 0;
    P9FileStatInfo info;
    HANDLE h;
    NTSTATUS s;

    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        access |= FILE_GENERIC_READ;
        break;
    case O_WRONLY:
        access |= FILE_GENERIC_WRITE;
        break;
    default:
        access |= FILE_GENERIC_READ | FILE_GENERIC_WRITE;
        break;
    }
    if (flags & O_APPEND) {
        /* writes go to the end, atomically, as with O_APPEND */
        access &= ~FILE_WRITE_DATA;
        access |= FILE_APPEND_DATA;
    }
    if (flags & O_DIRECTORY) {
        options |= P9_FILE_DIRECTORY_FILE;
        access |= FILE_LIST_DIRECTORY | FILE_TRAVERSE;
    }
    if (flags & O_CREAT) {
        if (flags & O_EXCL) {
            disposition = P9_FILE_CREATE;
        } else if (flags & O_TRUNC) {
            disposition = P9_FILE_OVERWRITE_IF;
        } else {
            disposition = P9_FILE_OPEN_IF;
        }
        if (!(flags & O_DIRECTORY)) {
            options |= P9_FILE_NON_DIRECTORY_FILE;
        }
    } else if (flags & O_TRUNC) {
        disposition = P9_FILE_OVERWRITE;
    }
    if (flags & O_SYNC) {
        options |= P9_FILE_WRITE_THROUGH;
    }

    s = nt_open(fd_handle(dirfd), name, access, disposition, options,
                FILE_ATTRIBUTE_NORMAL, &h);
    if (!NT_SUCCESS(s)) {
        if (s == P9_STATUS_OBJECT_NAME_INVALID && (flags & O_CREAT)) {
            errno = EINVAL;
            return -1;
        }
        return set_nt_errno(s);
    }

    s = nt_stat_info(h, &info);
    if (NT_SUCCESS(s)) {
        bool dir = info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY;
        bool link = (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                    tag_is_link(info.ReparseTag);

        if (link && !(flags & O_DIRECTORY) && (flags & O_NOFOLLOW) &&
            (flags & O_ACCMODE) == O_RDONLY && !(flags & O_CREAT) &&
            !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            /*
             * O_NOFOLLOW on a link: Linux fails with ELOOP; a link of
             * WSL holds no data anyway
             */
            CloseHandle(h);
            errno = ELOOP;
            return -1;
        }
        if (link && (flags & O_DIRECTORY)) {
            CloseHandle(h);
            errno = (flags & O_NOFOLLOW) ? ELOOP : ENOTDIR;
            return -1;
        }
        if (dir && (flags & O_ACCMODE) != O_RDONLY) {
            CloseHandle(h);
            errno = EISDIR;
            return -1;
        }
    }
    return handle_to_fd(h, flags);
}

int p9_fcntl(int fd, int cmd, ...)
{
    va_list ap;
    int arg;

    switch (cmd) {
    case F_GETFL:
        return fd_flags_get(fd);
    case F_SETFL:
        va_start(ap, cmd);
        arg = va_arg(ap, int);
        va_end(ap);
        fd_flags_set(fd, (fd_flags_get(fd) & O_ACCMODE) |
                         (arg & ~O_ACCMODE));
        return 0;
    default:
        errno = EINVAL;
        return -1;
    }
}

/* ------------------------------------------------------------------ */
/* Directories                                                         */

int mkdirat(int dirfd, const char *name, mode_t mode)
{
    ULONG cs = P9_FILE_CS_FLAG_CASE_SENSITIVE_DIR;
    P9IoStatusBlock iosb;
    HANDLE h;
    NTSTATUS s;

    s = nt_open(fd_handle(dirfd), name,
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES |
                FILE_WRITE_ATTRIBUTES,
                P9_FILE_CREATE, P9_FILE_DIRECTORY_FILE,
                FILE_ATTRIBUTE_NORMAL, &h);
    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    /* names are case sensitive for the guest, as WSL makes them */
    nt.SetInformationFile(h, &iosb, &cs, sizeof(cs),
                          P9FileCaseSensitiveInformation);
    CloseHandle(h);
    return 0;
}

typedef struct {
    ino_t ino;
    unsigned char type;
    char *name;
} P9DirEntry;

struct P9Dir {
    int fd;
    GArray *entries;    /* of P9DirEntry, "." and ".." first */
    bool loaded;
    long pos;
    struct p9_dirent ent;
};

P9Dir *fdopendir(int fd)
{
    P9Dir *d;

    if (fd_handle(fd) == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return NULL;
    }
    d = g_new0(P9Dir, 1);
    d->fd = fd;
    return d;
}

static void dir_clear(P9Dir *d)
{
    guint i;

    if (d->entries) {
        for (i = 0; i < d->entries->len; i++) {
            g_free(g_array_index(d->entries, P9DirEntry, i).name);
        }
        g_array_free(d->entries, TRUE);
        d->entries = NULL;
    }
    d->loaded = false;
}

static unsigned char dirent_type(ULONG attributes, ULONG tag)
{
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        switch (tag) {
        case P9_TAG_SYMLINK:
        case P9_TAG_MOUNT_POINT:
        case P9_TAG_LX_SYMLINK:
            return DT_LNK;
        case P9_TAG_LX_FIFO:
            return DT_FIFO;
        case P9_TAG_LX_CHR:
            return DT_CHR;
        case P9_TAG_LX_BLK:
            return DT_BLK;
        case P9_TAG_AF_UNIX:
            return DT_SOCK;
        }
    }
    return attributes & FILE_ATTRIBUTE_DIRECTORY ? DT_DIR : DT_REG;
}

static int dir_load(P9Dir *d)
{
    HANDLE h = fd_handle(d->fd);
    size_t buflen = 64 * 1024;
    g_autofree char *buf = g_malloc(buflen);
    P9IoStatusBlock iosb;
    P9FileStatInfo self;
    BOOLEAN restart = TRUE;
    P9DirEntry e;

    nt_init();
    dir_clear(d);
    d->entries = g_array_new(FALSE, FALSE, sizeof(P9DirEntry));
    if (!NT_SUCCESS(nt_stat_info(h, &self))) {
        self.FileId.QuadPart = 0;
    }
    e.ino = self.FileId.QuadPart;
    e.type = DT_DIR;
    e.name = g_strdup(".");
    g_array_append_val(d->entries, e);
    e.name = g_strdup("..");
    g_array_append_val(d->entries, e);

    for (;;) {
        NTSTATUS s = nt.QueryDirectoryFile(h, NULL, NULL, NULL, &iosb, buf,
                                           buflen,
                                           P9FileIdBothDirectoryInformation,
                                           FALSE, NULL, restart);
        P9FileIdBothDirInfo *fi = (P9FileIdBothDirInfo *)buf;

        restart = FALSE;
        if (s == P9_STATUS_NO_MORE_FILES) {
            break;
        }
        if (!NT_SUCCESS(s)) {
            dir_clear(d);
            return set_nt_errno(s);
        }
        for (;;) {
            size_t chars = fi->FileNameLength / sizeof(WCHAR);

            if (!(chars == 1 && fi->FileName[0] == L'.') &&
                !(chars == 2 && fi->FileName[0] == L'.' &&
                  fi->FileName[1] == L'.')) {
                e.ino = fi->FileId.QuadPart;
                e.type = dirent_type(fi->FileAttributes, fi->EaSize);
                e.name = name_from_nt(fi->FileName, chars);
                g_array_append_val(d->entries, e);
            }
            if (!fi->NextEntryOffset) {
                break;
            }
            fi = (P9FileIdBothDirInfo *)((char *)fi + fi->NextEntryOffset);
        }
    }
    d->loaded = true;
    return 0;
}

struct p9_dirent *p9_readdir(P9Dir *d)
{
    P9DirEntry *e;

    if (!d->loaded && dir_load(d) < 0) {
        return NULL;
    }
    if (d->pos < 0 || d->pos >= (long)d->entries->len) {
        return NULL;
    }
    e = &g_array_index(d->entries, P9DirEntry, d->pos);
    d->pos++;
    d->ent.d_ino = e->ino;
    d->ent.d_off = d->pos;
    d->ent.d_type = e->type;
    g_strlcpy(d->ent.d_name, e->name, sizeof(d->ent.d_name));
    d->ent.d_reclen = offsetof(struct p9_dirent, d_name) +
                      strlen(d->ent.d_name) + 1;
    return &d->ent;
}

int p9_closedir(P9Dir *d)
{
    int ret = close(d->fd);

    dir_clear(d);
    g_free(d);
    return ret;
}

void p9_rewinddir(P9Dir *d)
{
    dir_clear(d);
    d->pos = 0;
}

long p9_telldir(P9Dir *d)
{
    return d->pos;
}

void p9_seekdir(P9Dir *d, long off)
{
    d->pos = off;
}

int p9_dirfd(P9Dir *d)
{
    return d->fd;
}

/* ------------------------------------------------------------------ */
/* Names: rename, unlink, link                                         */

static NTSTATUS set_name_info(HANDLE h, HANDLE newroot, const char *newname,
                              ULONG flags, ULONG class)
{
    size_t len;
    g_autofree gunichar2 *w = name_to_nt(newname, &len);
    g_autofree P9FileRenameInfo *ri = NULL;
    size_t size;
    P9IoStatusBlock iosb;

    if (!w) {
        return errno == ENAMETOOLONG ? P9_STATUS_NAME_TOO_LONG :
               P9_STATUS_OBJECT_NAME_INVALID;
    }
    size = offsetof(P9FileRenameInfo, FileName) + len * sizeof(WCHAR);
    ri = g_malloc0(size + sizeof(WCHAR));
    ri->Flags = flags;
    ri->RootDirectory = newroot;
    ri->FileNameLength = len * sizeof(WCHAR);
    memcpy(ri->FileName, w, len * sizeof(WCHAR));
    return nt.SetInformationFile(h, &iosb, ri, size, class);
}

int renameat(int olddirfd, const char *oldname,
             int newdirfd, const char *newname)
{
    HANDLE h;
    NTSTATUS s;

    s = nt_open(fd_handle(olddirfd), oldname, DELETE | FILE_READ_ATTRIBUTES,
                P9_FILE_OPEN, 0, 0, &h);
    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    s = set_name_info(h, fd_handle(newdirfd), newname,
                      P9_FILE_RENAME_REPLACE_IF_EXISTS |
                      P9_FILE_RENAME_POSIX_SEMANTICS |
                      P9_FILE_RENAME_IGNORE_READONLY_ATTRIBUTE,
                      P9FileRenameInformationEx);
    if (s == P9_STATUS_INVALID_INFO_CLASS || s == P9_STATUS_NOT_SUPPORTED ||
        s == P9_STATUS_INVALID_PARAMETER) {
        /* file systems without the POSIX semantics (FAT) */
        s = set_name_info(h, fd_handle(newdirfd), newname, TRUE,
                          P9FileRenameInformation);
    }
    CloseHandle(h);
    return NT_SUCCESS(s) ? 0 : set_nt_errno(s);
}

int unlinkat(int dirfd, const char *name, int flags)
{
    P9FileStatInfo info;
    P9IoStatusBlock iosb;
    ULONG disp = P9_FILE_DISPOSITION_DELETE |
                 P9_FILE_DISPOSITION_POSIX_SEMANTICS |
                 P9_FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
    BOOLEAN del = TRUE;
    HANDLE h;
    NTSTATUS s;
    bool dir, link;

    s = nt_open(fd_handle(dirfd), name, DELETE | FILE_READ_ATTRIBUTES,
                P9_FILE_OPEN, 0, 0, &h);
    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    s = nt_stat_info(h, &info);
    if (!NT_SUCCESS(s)) {
        CloseHandle(h);
        return set_nt_errno(s);
    }
    dir = info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    link = (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
           tag_is_link(info.ReparseTag);
    if ((flags & AT_REMOVEDIR) && (!dir || link)) {
        CloseHandle(h);
        errno = ENOTDIR;
        return -1;
    }
    if (!(flags & AT_REMOVEDIR) && dir && !link) {
        CloseHandle(h);
        errno = EISDIR;
        return -1;
    }
    s = nt.SetInformationFile(h, &iosb, &disp, sizeof(disp),
                              P9FileDispositionInformationEx);
    if (s == P9_STATUS_INVALID_INFO_CLASS || s == P9_STATUS_NOT_SUPPORTED ||
        s == P9_STATUS_INVALID_PARAMETER) {
        s = nt.SetInformationFile(h, &iosb, &del, sizeof(del),
                                  P9FileDispositionInformation);
    }
    CloseHandle(h);
    return NT_SUCCESS(s) ? 0 : set_nt_errno(s);
}

int linkat(int olddirfd, const char *oldname,
           int newdirfd, const char *newname, int flags)
{
    HANDLE h;
    NTSTATUS s;

    s = nt_open(fd_handle(olddirfd), oldname, FILE_READ_ATTRIBUTES,
                P9_FILE_OPEN, 0, 0, &h);
    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    s = set_name_info(h, fd_handle(newdirfd), newname, FALSE,
                      P9FileLinkInformation);
    CloseHandle(h);
    if (s == P9_STATUS_ACCESS_DENIED || s == P9_STATUS_FILE_IS_A_DIRECTORY) {
        /* directories cannot be linked */
        errno = EPERM;
        return -1;
    }
    return NT_SUCCESS(s) ? 0 : set_nt_errno(s);
}

/* ------------------------------------------------------------------ */
/* Links and special files: the reparse points of WSL                  */

typedef struct {
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLink;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPoint;
        struct {
            ULONG Version;
            char Target[1];
        } LxSymlink;
        UCHAR Data[1];
    };
} P9ReparseBuffer;

#define P9_REPARSE_HEADER offsetof(P9ReparseBuffer, Data)

static int set_reparse(HANDLE h, ULONG tag, const void *data, size_t len)
{
    size_t size = P9_REPARSE_HEADER + len;
    g_autofree P9ReparseBuffer *rb = g_malloc0(size + 8);
    DWORD out;

    rb->ReparseTag = tag;
    rb->ReparseDataLength = len;
    if (len) {
        memcpy(rb->Data, data, len);
    }
    if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, rb, size, NULL, 0,
                         &out, NULL)) {
        errno = GetLastError() == ERROR_ACCESS_DENIED ? EACCES :
                GetLastError() == ERROR_PRIVILEGE_NOT_HELD ? EPERM :
                EOPNOTSUPP;
        return -1;
    }
    return 0;
}

/* Create @name as an empty file, holding a reparse point @tag */
static int create_special(int dirfd, const char *name, ULONG tag,
                          const void *data, size_t len, HANDLE *out)
{
    P9IoStatusBlock iosb;
    ULONG disp = P9_FILE_DISPOSITION_DELETE |
                 P9_FILE_DISPOSITION_POSIX_SEMANTICS;
    HANDLE h;
    NTSTATUS s;

    s = nt_open(fd_handle(dirfd), name,
                FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | FILE_READ_EA |
                DELETE,
                P9_FILE_CREATE, P9_FILE_NON_DIRECTORY_FILE,
                FILE_ATTRIBUTE_NORMAL, &h);
    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    if (tag && set_reparse(h, tag, data, len) < 0) {
        int err = errno;

        nt.SetInformationFile(h, &iosb, &disp, sizeof(disp),
                              P9FileDispositionInformationEx);
        CloseHandle(h);
        errno = err;
        return -1;
    }
    *out = h;
    return 0;
}

int symlinkat(const char *target, int dirfd, const char *name)
{
    size_t tlen = strlen(target);
    g_autofree char *data = g_malloc(4 + tlen);
    uint32_t version = cpu_to_le32(2);
    HANDLE h;

    memcpy(data, &version, 4);
    memcpy(data + 4, target, tlen);
    if (create_special(dirfd, name, P9_TAG_LX_SYMLINK, data, 4 + tlen,
                       &h) < 0) {
        return -1;
    }
    CloseHandle(h);
    return 0;
}

ssize_t readlinkat(int dirfd, const char *name, char *buf, size_t size)
{
    g_autofree P9ReparseBuffer *rb = g_malloc(MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
    g_autofree char *target = NULL;
    DWORD out;
    HANDLE h;
    NTSTATUS s;
    size_t len;

    s = nt_open(fd_handle(dirfd), name, FILE_READ_ATTRIBUTES, P9_FILE_OPEN,
                0, 0, &h);
    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0, rb,
                         MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &out, NULL)) {
        CloseHandle(h);
        errno = EINVAL;
        return -1;
    }
    CloseHandle(h);

    switch (rb->ReparseTag) {
    case P9_TAG_LX_SYMLINK:
        if (rb->ReparseDataLength < 4) {
            errno = EINVAL;
            return -1;
        }
        target = g_strndup(rb->LxSymlink.Target, rb->ReparseDataLength - 4);
        break;
    case P9_TAG_SYMLINK:
        target = g_utf16_to_utf8(
            (gunichar2 *)((char *)rb->SymbolicLink.PathBuffer +
                          rb->SymbolicLink.PrintNameOffset),
            rb->SymbolicLink.PrintNameLength / sizeof(WCHAR),
            NULL, NULL, NULL);
        break;
    case P9_TAG_MOUNT_POINT:
        target = g_utf16_to_utf8(
            (gunichar2 *)((char *)rb->MountPoint.PathBuffer +
                          rb->MountPoint.PrintNameOffset),
            rb->MountPoint.PrintNameLength / sizeof(WCHAR),
            NULL, NULL, NULL);
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    if (!target) {
        errno = EINVAL;
        return -1;
    }
    if (rb->ReparseTag != P9_TAG_LX_SYMLINK) {
        /* the links of Windows: their separators become those of Linux */
        g_strdelimit(target, "\\", '/');
    }
    len = MIN(strlen(target), size);
    memcpy(buf, target, len);
    return len;
}

int qemu_mknodat(int dirfd, const char *name, mode_t mode, dev_t dev)
{
    ULONG tag;
    uint32_t mod = cpu_to_le32(mode);
    uint32_t devnum[2] = { cpu_to_le32(major(dev)), cpu_to_le32(minor(dev)) };
    HANDLE h;

    switch (mode & S_IFMT) {
    case S_IFREG:
    case 0:
        tag = 0;
        break;
    case S_IFIFO:
        tag = P9_TAG_LX_FIFO;
        break;
    case S_IFCHR:
        tag = P9_TAG_LX_CHR;
        break;
    case S_IFBLK:
        tag = P9_TAG_LX_BLK;
        break;
    case S_IFSOCK:
        tag = P9_TAG_AF_UNIX;
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    if (create_special(dirfd, name, tag, NULL, 0, &h) < 0) {
        return -1;
    }
    if (tag) {
        /* the type and the device number, as WSL keeps them */
        ea_set(h, LX_MOD, &mod, sizeof(mod));
        if (tag == P9_TAG_LX_CHR || tag == P9_TAG_LX_BLK) {
            ea_set(h, LX_DEV, devnum, sizeof(devnum));
        }
    }
    CloseHandle(h);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Owner, mode and times                                               */

static int handle_chmod(HANDLE h, mode_t mode)
{
    uint32_t v = cpu_to_le32(mode & 07777);
    int ret = ea_set(h, LX_MOD, &v, sizeof(v));

    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return 0;
}

static int handle_chown(HANDLE h, uid_t uid, gid_t gid)
{
    uint32_t v;
    int ret = 0;

    if (uid != (uid_t)-1) {
        v = cpu_to_le32(uid);
        ret = ea_set(h, LX_UID, &v, sizeof(v));
    }
    if (!ret && gid != (gid_t)-1) {
        v = cpu_to_le32(gid);
        ret = ea_set(h, LX_GID, &v, sizeof(v));
    }
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return 0;
}

static NTSTATUS open_for_meta(int dirfd, const char *name, HANDLE *h)
{
    return nt_open(fd_handle(dirfd), name,
                   FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
                   FILE_READ_EA | FILE_WRITE_EA, P9_FILE_OPEN, 0, 0, h);
}

static NTSTATUS reopen_for_meta(int fd, HANDLE *h)
{
    HANDLE fh = fd_handle(fd);

    if (fh == INVALID_HANDLE_VALUE) {
        return P9_STATUS_INVALID_PARAMETER;
    }
    nt_init();
    return nt_reopen(fh, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
                     FILE_READ_EA | FILE_WRITE_EA, h);
}

int fchmodat(int dirfd, const char *name, mode_t mode, int flags)
{
    HANDLE h;
    NTSTATUS s = open_for_meta(dirfd, name, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = handle_chmod(h, mode);
    CloseHandle(h);
    return ret;
}

int fchmod(int fd, mode_t mode)
{
    HANDLE h;
    NTSTATUS s = reopen_for_meta(fd, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = handle_chmod(h, mode);
    CloseHandle(h);
    return ret;
}

int fchownat(int dirfd, const char *name, uid_t uid, gid_t gid, int flags)
{
    HANDLE h;
    NTSTATUS s = open_for_meta(dirfd, name, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = handle_chown(h, uid, gid);
    CloseHandle(h);
    return ret;
}

int fchown(int fd, uid_t uid, gid_t gid)
{
    HANDLE h;
    NTSTATUS s = reopen_for_meta(fd, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = handle_chown(h, uid, gid);
    CloseHandle(h);
    return ret;
}

static void timespec_to_nt(const struct timespec *ts, LARGE_INTEGER *t)
{
    if (ts->tv_nsec == UTIME_OMIT) {
        t->QuadPart = 0;            /* unchanged */
    } else if (ts->tv_nsec == UTIME_NOW) {
        FILETIME ft;

        GetSystemTimePreciseAsFileTime(&ft);
        t->LowPart = ft.dwLowDateTime;
        t->HighPart = ft.dwHighDateTime;
    } else {
        t->QuadPart = (int64_t)ts->tv_sec * 10000000 + ts->tv_nsec / 100 +
                      INT64_C(116444736000000000);
    }
}

static int handle_utimens(HANDLE h, const struct timespec times[2])
{
    struct timespec now[2] = {
        { .tv_nsec = UTIME_NOW }, { .tv_nsec = UTIME_NOW },
    };
    P9FileBasicInfo bi = { 0 };
    P9IoStatusBlock iosb;
    NTSTATUS s;

    if (!times) {
        times = now;
    }
    timespec_to_nt(&times[0], &bi.LastAccessTime);
    timespec_to_nt(&times[1], &bi.LastWriteTime);
    s = nt.SetInformationFile(h, &iosb, &bi, sizeof(bi),
                              P9FileBasicInformation);
    return NT_SUCCESS(s) ? 0 : set_nt_errno(s);
}

int utimensat(int dirfd, const char *name, const struct timespec times[2],
              int flags)
{
    HANDLE h;
    NTSTATUS s = open_for_meta(dirfd, name, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = handle_utimens(h, times);
    CloseHandle(h);
    return ret;
}

int futimens(int fd, const struct timespec times[2])
{
    HANDLE h;
    NTSTATUS s = reopen_for_meta(fd, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = handle_utimens(h, times);
    CloseHandle(h);
    return ret;
}

/* ------------------------------------------------------------------ */
/* I/O                                                                 */

int p9_fsync(int fd)
{
    HANDLE h = fd_handle(fd);

    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    if (!FlushFileBuffers(h)) {
        /* read-only descriptors and directories: nothing to write */
        if (GetLastError() == ERROR_ACCESS_DENIED ||
            GetLastError() == ERROR_INVALID_HANDLE) {
            return 0;
        }
        errno = EIO;
        return -1;
    }
    return 0;
}

static ssize_t p9_rw(int fd, const struct iovec *iov, int iovcnt,
                     off_t offset, bool write)
{
    HANDLE h = fd_handle(fd);
    bool append = write && (fd_flags_get(fd) & O_APPEND);
    ssize_t done = 0;
    int i;

    if (h == INVALID_HANDLE_VALUE) {
        errno = EBADF;
        return -1;
    }
    for (i = 0; i < iovcnt; i++) {
        OVERLAPPED ov = { 0 };
        DWORD n = 0;
        BOOL ok;

        if (append) {
            /* as pwrite() with O_APPEND on Linux: at the end */
            ov.Offset = ov.OffsetHigh = 0xFFFFFFFF;
        } else {
            ov.Offset = (DWORD)(offset + done);
            ov.OffsetHigh = (DWORD)((uint64_t)(offset + done) >> 32);
        }
        if (write) {
            ok = WriteFile(h, iov[i].iov_base, iov[i].iov_len, &n, &ov);
        } else {
            ok = ReadFile(h, iov[i].iov_base, iov[i].iov_len, &n, &ov);
            if (!ok && GetLastError() == ERROR_HANDLE_EOF) {
                ok = TRUE;
                n = 0;
            }
        }
        if (!ok) {
            if (done) {
                break;
            }
            switch (GetLastError()) {
            case ERROR_ACCESS_DENIED:
                errno = EBADF;
                break;
            case ERROR_DISK_FULL:
            case ERROR_HANDLE_DISK_FULL:
                errno = ENOSPC;
                break;
            case ERROR_INVALID_FUNCTION:
                errno = EISDIR;
                break;
            default:
                errno = EIO;
                break;
            }
            return -1;
        }
        done += n;
        if (n < iov[i].iov_len) {
            break;
        }
    }
    return done;
}

ssize_t p9_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return p9_rw(fd, iov, iovcnt, offset, false);
}

ssize_t p9_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return p9_rw(fd, iov, iovcnt, offset, true);
}

int fstatfs(int fd, struct statfs *buf)
{
    HANDLE h = fd_handle(fd);
    P9FileFsFullSizeInfo fs;
    P9FileFsVolumeInfo vol;
    P9IoStatusBlock iosb;
    NTSTATUS s;

    nt_init();
    s = nt.QueryVolumeInformationFile(h, &iosb, &fs, sizeof(fs),
                                      P9FileFsFullSizeInformation);
    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    memset(buf, 0, sizeof(*buf));
    buf->f_type = 0x5346544e;       /* NTFS_SB_MAGIC */
    buf->f_bsize = (uint64_t)fs.SectorsPerAllocationUnit * fs.BytesPerSector;
    buf->f_blocks = fs.TotalAllocationUnits.QuadPart;
    buf->f_bfree = fs.ActualAvailableAllocationUnits.QuadPart;
    buf->f_bavail = fs.CallerAvailableAllocationUnits.QuadPart;
    buf->f_namelen = 255;
    s = nt.QueryVolumeInformationFile(h, &iosb, &vol, sizeof(vol),
                                      P9FileFsVolumeInformation);
    if (NT_SUCCESS(s) || s == P9_STATUS_BUFFER_OVERFLOW) {
        buf->f_fsid.__val[0] = vol.VolumeSerialNumber;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Extended attributes of POSIX                                        */

ssize_t fgetxattr(int fd, const char *name, void *value, size_t size)
{
    nt_init();
    return xattr_get(fd_handle(fd), name, value, size);
}

int fsetxattr(int fd, const char *name, const void *value, size_t size,
              int flags)
{
    HANDLE h;
    NTSTATUS s = reopen_for_meta(fd, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = xattr_set(h, name, value, size, flags);
    CloseHandle(h);
    return ret;
}

ssize_t flistxattr(int fd, char *list, size_t size)
{
    nt_init();
    return xattr_list(fd_handle(fd), list, size);
}

int fremovexattr(int fd, const char *name)
{
    HANDLE h;
    NTSTATUS s = reopen_for_meta(fd, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = xattr_remove(h, name);
    CloseHandle(h);
    return ret;
}

ssize_t fgetxattrat_nofollow(int dirfd, const char *filename,
                             const char *name, void *value, size_t size)
{
    HANDLE h;
    NTSTATUS s = nt_open(fd_handle(dirfd), filename,
                         FILE_READ_ATTRIBUTES | FILE_READ_EA, P9_FILE_OPEN,
                         0, 0, &h);
    ssize_t ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = xattr_get(h, name, value, size);
    CloseHandle(h);
    return ret;
}

int fsetxattrat_nofollow(int dirfd, const char *filename, const char *name,
                         void *value, size_t size, int flags)
{
    HANDLE h;
    NTSTATUS s = open_for_meta(dirfd, filename, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = xattr_set(h, name, value, size, flags);
    CloseHandle(h);
    return ret;
}

ssize_t flistxattrat_nofollow(int dirfd, const char *filename,
                              char *list, size_t size)
{
    HANDLE h;
    NTSTATUS s = nt_open(fd_handle(dirfd), filename,
                         FILE_READ_ATTRIBUTES | FILE_READ_EA, P9_FILE_OPEN,
                         0, 0, &h);
    ssize_t ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = xattr_list(h, list, size);
    CloseHandle(h);
    return ret;
}

ssize_t fremovexattrat_nofollow(int dirfd, const char *filename,
                                const char *name)
{
    HANDLE h;
    NTSTATUS s = open_for_meta(dirfd, filename, &h);
    int ret;

    if (!NT_SUCCESS(s)) {
        return set_nt_errno(s);
    }
    ret = xattr_remove(h, name);
    CloseHandle(h);
    return ret;
}
