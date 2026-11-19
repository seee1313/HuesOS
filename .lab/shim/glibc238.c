/*
 * Compatibility shim for the vendored QEMU build (Ubuntu 24.04, glibc 2.38)
 * running on this sandbox (Debian 12, glibc 2.36).
 *
 * Only two families of symbols are newer than 2.36:
 *   - the C23 __isoc23_strto* / __isoc23_*scanf entry points (glibc 2.38),
 *   - strlcpy / strlcat (glibc 2.38).
 * Each one just forwards to the 2.36 equivalent; QEMU never relies on the
 * C23-only behaviour (0b binary prefixes), so this is behaviour-preserving.
 */
#define _GNU_SOURCE
#include <locale.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

long __isoc23_strtol(const char *n, char **e, int b) { return strtol(n, e, b); }
long long __isoc23_strtoll(const char *n, char **e, int b) { return strtoll(n, e, b); }
unsigned long __isoc23_strtoul(const char *n, char **e, int b) { return strtoul(n, e, b); }
unsigned long long __isoc23_strtoull(const char *n, char **e, int b) { return strtoull(n, e, b); }
intmax_t __isoc23_strtoimax(const char *n, char **e, int b) { return strtoimax(n, e, b); }
uintmax_t __isoc23_strtoumax(const char *n, char **e, int b) { return strtoumax(n, e, b); }

long long __isoc23_strtoll_l(const char *n, char **e, int b, locale_t l)
{
    (void)l;
    return strtoll(n, e, b);
}

unsigned long long __isoc23_strtoull_l(const char *n, char **e, int b, locale_t l)
{
    (void)l;
    return strtoull(n, e, b);
}

int __isoc23_vsscanf(const char *s, const char *f, va_list ap) { return vsscanf(s, f, ap); }
int __isoc23_vfscanf(FILE *st, const char *f, va_list ap) { return vfscanf(st, f, ap); }

int __isoc23_sscanf(const char *s, const char *f, ...)
{
    va_list ap;
    int r;
    va_start(ap, f);
    r = vsscanf(s, f, ap);
    va_end(ap);
    return r;
}

int __isoc23_fscanf(FILE *st, const char *f, ...)
{
    va_list ap;
    int r;
    va_start(ap, f);
    r = vfscanf(st, f, ap);
    va_end(ap);
    return r;
}

size_t strlcpy(char *d, const char *s, size_t n)
{
    size_t sl = 0;

    while (s[sl] != '\0')
        sl++;
    if (n != 0) {
        size_t copy = sl < n - 1 ? sl : n - 1;
        for (size_t i = 0; i < copy; i++)
            d[i] = s[i];
        d[copy] = '\0';
    }
    return sl;
}

size_t strlcat(char *d, const char *s, size_t n)
{
    size_t dl = 0;
    size_t sl = 0;

    while (dl < n && d[dl] != '\0')
        dl++;
    while (s[sl] != '\0')
        sl++;
    if (dl == n)
        return n + sl;
    if (sl != 0) {
        size_t room = n - dl - 1;
        size_t copy = sl < room ? sl : room;
        for (size_t i = 0; i < copy; i++)
            d[dl + i] = s[i];
        d[dl + copy] = '\0';
    }
    return dl + sl;
}
