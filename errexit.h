#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Errors are reported from the perspective of the rpmcpio library.
// The basename of the rpm package being processed is usually included
// in the message.
#define PROG "rpmcpio"
#define warn(fmt, args...) fprintf(stderr, PROG ": " fmt "\n", ##args)
#define die(fmt, args...) warn(fmt, ##args), exit(128) // like git

static inline void *xmalloc_(const char *func, size_t n)
{
    void *buf = malloc(n);
    if (buf == NULL)
	die("cannot allocate %zu bytes in %s()", n, func);
    return buf;
}

#define xmalloc(n) xmalloc_(__func__, n)

static inline const char *xbasename_(const char *func, const char *fname)
{
    const char *bn = strrchr(fname, '/');
    bn = bn ? bn + 1 : fname;
    const char *p = bn;
    while (*p == '.')
	p++;
    if (*p == '\0')
	die("%s: cannot make basename", fname);
    return bn;
}

#define xbasename(fname) xbasename_(__func__, fname)
