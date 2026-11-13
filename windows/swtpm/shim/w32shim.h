#ifndef W32_SHIM_H
#define W32_SHIM_H
#include <stdio.h>
#include <stdarg.h>
#include <io.h>
static inline int vdprintf(int fd, const char *f, va_list ap)
{
    char b[4096];
    int n = vsnprintf(b, sizeof(b), f, ap);
    if (n > 0) {
        _write(fd, b, n < (int)sizeof(b) ? n : (int)sizeof(b) - 1);
    }
    return n;
}
static inline int dprintf(int fd, const char *f, ...)
{
    va_list ap;
    int n;
    va_start(ap, f);
    n = vdprintf(fd, f, ap);
    va_end(ap);
    return n;
}
#include <stdlib.h>
static inline int w32shim_vasprintf(char **strp, const char *f, va_list ap)
{
    va_list aq;
    int n;

    va_copy(aq, ap);
    n = vsnprintf(NULL, 0, f, aq);
    va_end(aq);
    if (n < 0 || !(*strp = malloc(n + 1))) {
        return -1;
    }
    return vsnprintf(*strp, n + 1, f, ap);
}
#define vasprintf w32shim_vasprintf
static inline int w32shim_asprintf(char **strp, const char *f, ...)
{
    va_list ap;
    int n;

    va_start(ap, f);
    n = w32shim_vasprintf(strp, f, ap);
    va_end(ap);
    return n;
}
#define asprintf w32shim_asprintf
#include <string.h>
#define index(s, c) strchr((s), (c))
#endif
