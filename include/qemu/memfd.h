#ifndef QEMU_MEMFD_H
#define QEMU_MEMFD_H


#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
#define F_SEAL_GROW     0x0004  /* prevent file from growing */
#define F_SEAL_WRITE    0x0008  /* prevent writes */
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 0x0004U
#endif

#ifndef MFD_HUGE_SHIFT
#define MFD_HUGE_SHIFT 26
#endif

#if defined CONFIG_LINUX && !defined CONFIG_MEMFD
int memfd_create(const char *name, unsigned int flags);
#endif

int qemu_memfd_create(const char *name, size_t size, bool hugetlb,
                      uint64_t hugetlbsize, unsigned int seals, Error **errp);
bool qemu_memfd_alloc_check(void);
void *qemu_memfd_alloc(const char *name, size_t size, unsigned int seals,
                       int *fd, Error **errp);
void qemu_memfd_free(void *ptr, size_t size, int fd);
bool qemu_memfd_check(unsigned int flags);

#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010  /* prevent future writes while mapped */
#endif

#ifdef _WIN32
/*
 * Seals on Windows (util/memfd-win32.c): fcntl(F_ADD_SEALS) and
 * fcntl(F_GET_SEALS) for a descriptor or a handle token; 0 or the seals,
 * else -1 with errno as Linux sets it.
 */
int qemu_memfd_add_seals(int fd, unsigned int seals);
int qemu_memfd_get_seals(int fd);
int memfd_create(const char *name, unsigned int flags);

/* For mmap()/munmap() and close() of Windows: the state of the seals */
int qemu_memfd_win32_map_check(HANDLE file, int prot, int flags);
void qemu_memfd_win32_mapped(HANDLE file, void *addr);
void qemu_memfd_win32_unmapped(void *addr);
int qemu_memfd_win32_truncate_check(HANDLE file, int64_t length);
/* Before close(): what to set after it (NULL if nothing), see close() */
HANDLE qemu_memfd_win32_close(int fd);
/* @fd came from another process: if it is a sealed memfd, enforce it too */
void qemu_memfd_win32_received(int fd);
#endif

#endif /* QEMU_MEMFD_H */
