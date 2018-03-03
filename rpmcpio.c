// Copyright (c) 2016, 2018 Alexey Tourbin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include "rpmcpio.h"
#include "errexit.h"

static unsigned getFileCount(Header h)
{
    // Getting DIRINDEXES is cheaper than BASENAMES, no parsing.
    struct rpmtd_s td;
    int rc = headerGet(h, RPMTAG_DIRINDEXES, &td, HEADERGET_MINMEM);
    if (rc == 1)
	return td.count ? td.count : -1; // zero count not permitted
    return 0;
}

struct rpmcpio {
    FD_t fd;
    // n1: current data pos
    // n2: end data pos
    // n3: next entry pos
    int n1, n2, n3;
    unsigned nent;
    union { bool rpm; } src;
    struct cpioent ent;
    char fname[4096];
    char rpmbname[];
};

static_assert(sizeof(struct cpioent) == 64, "nice cpioent size");

struct rpmcpio *rpmcpio_open(int dirfd, const char *rpmfname,
			     unsigned *nent, bool all)
{
    // dirfd is not yet supported
    assert(*rpmfname == '/' || dirfd == AT_FDCWD);

    const char *rpmbname = xbasename(rpmfname);
    FD_t fd = Fopen(rpmfname, "r.ufdio");
    if (Ferror(fd))
	die("%s: cannot open", rpmbname);

    static rpmts ts;
    if (ts == NULL) {
	// TODO: atomic exchange or else free
	ts = rpmtsCreate();
	assert(ts);
	rpmtsSetVSFlags(ts, (rpmVSFlags) -1);
    }

    Header h = NULL;
    int rc = rpmReadPackageFile(ts, fd, rpmfname, &h);
    if (rc != RPMRC_OK && rc != RPMRC_NOTTRUSTED && rc != RPMRC_NOKEY)
	die("%s: cannot read rpm header", rpmbname);
    assert(h);

    unsigned ne = getFileCount(h);
    if (ne == -1)
	die("%s: bad file count", rpmbname);
    if (nent)
	*nent = ne;

    size_t len = strlen(rpmbname);
    struct rpmcpio *cpio = xmalloc(sizeof(*cpio) + len + 1);
    memcpy(cpio->rpmbname, rpmbname, len + 1);

    char mode[] = "r.gzdio";
    const char *compr = headerGetString(h, RPMTAG_PAYLOADCOMPRESSOR);
    if (compr && compr[0] && compr[1] == 'z')
	mode[2] = compr[0];
    cpio->fd = Fdopen(fd, mode);
    if (Ferror(cpio->fd))
	die("%s: cannot open payload", rpmbname);
    if (cpio->fd != fd)
	Fclose(fd);

    cpio->n1 = cpio->n2 = cpio->n3 = 0;
    cpio->nent = ne;
    cpio->ent.no = -1;
    cpio->src.rpm = !headerGetString(h, RPMTAG_SOURCERPM);

    headerFree(h);
    return cpio;
}

static void rpmcpio_skip(struct rpmcpio *cpio, int n)
{
    assert(n > 0);
    assert(cpio->ent.no >= 0);
    char buf[BUFSIZ];
    do {
	int m = (n > BUFSIZ) ? BUFSIZ : n;
	if (Fread(buf, 1, m, cpio->fd) != m)
	    die("%s: cannot skip cpio bytes", cpio->rpmbname);
	n -= m;
    }
    while (n > 0);
}

static const signed char hex[256] = {
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,  -1,  -1,  -1,  -1,  -1,  -1,
     -1, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
};

// Parse 4-digit hex number, returns > 0xffff on error.
static inline unsigned hex4(const char *s)
{
    unsigned u;
    // hex[] values are sign-extended deliberately.
    u  = hex[(unsigned char) s[0]] << 12;
    u |= hex[(unsigned char) s[1]] << 8;
    u |= hex[(unsigned char) s[2]] << 4;
    u |= hex[(unsigned char) s[3]];
    return u;
}

// Parse 8-digit hex number.
static inline unsigned hex1(const char *s, const char *rpmbname)
{
    unsigned hi = hex4(s);
    unsigned lo = hex4(s + 4);
    if (hi > 0xffff || lo > 0xffff)
	die("%s: bad cpio hex number", rpmbname);
    return hi << 16 | lo;
}

// Convert 6 hex fields.
static void hex6(const char s[6*8], unsigned v[6], const char *rpmbname)
{
    for (int i = 0; i < 6; i++)
	v[i] = hex1(s + 8 * i, rpmbname);
}

const struct cpioent *rpmcpio_next(struct rpmcpio *cpio)
{
    if (cpio->n3 > cpio->n1) {
	rpmcpio_skip(cpio, cpio->n3 - cpio->n1);
	cpio->n1 = cpio->n3;
    }
    char buf[110];
    if (Fread(buf, 1, 110, cpio->fd) != 110)
	die("%s: cannot read cpio header", cpio->rpmbname);
    if (memcmp(buf, "070701", 6) != 0)
	die("%s: bad cpio header magic", cpio->rpmbname);
    cpio->n1 += 110;

    // Parse hex fields.
    const char *s = buf + 6;
    unsigned *v = &cpio->ent.ino;
    hex6(s, v, cpio->rpmbname); // 32-bit fields before cpio->ent.size
    hex6(s + 6 * 8, v + 7, cpio->rpmbname); // includes half of ent.size

    // Grand type punning: assigns 64-bit ent.size from its 32-bit half.
    cpio->ent.size = v[7];

    // The checksum field is not part of cpioent, rpm always sets it to zero.
    if (memcmp(s + 12 * 8, "0000" "0000", 8))
	die("%s: non-zero cpio checksum", cpio->rpmbname);

    cpio->ent.fflags = 0; // not yet supported
    cpio->ent.packaged = true;
    memset(cpio->ent.pad, 0, sizeof cpio->ent.pad);

    // cpio magic is 6 bytes, but filename is padded to a multiple of four bytes
    unsigned fnamesize = ((cpio->ent.fnamelen + 1) & ~3) + 2;
    // At this stage, fnamelen includes '\0', and fname should start with "./".
    // The leading dot will be stripped implicitly by copying to &fname[-1].
    // src.rpm is the exeption: there should be no prefix, and nothing will be stripped.
    bool dot = !cpio->src.rpm;
    if (cpio->ent.fnamelen - dot > sizeof cpio->fname)
	die("%s: cpio filename too long", cpio->rpmbname);
    assert(fnamesize - dot <= sizeof cpio->fname);
    // The shortest filename is "./\0", except for src.rpm,
    // for which the shortest filename is "a\0".
    if (cpio->ent.fnamelen < 3U - dot)
	die("%s: cpio filename too short", cpio->rpmbname);
    char *fnamedest = cpio->fname - dot;
    if (Fread(fnamedest, 1, fnamesize, cpio->fd) != fnamesize)
	die("%s: cannot read cpio filename", cpio->rpmbname);

    cpio->n1 += fnamesize;
    cpio->n2 = cpio->n1 + cpio->ent.size;
    cpio->n3 = (cpio->n2 + 3) & ~3;

    if (memcmp(fnamedest, "TRAILER!!!", cpio->ent.fnamelen) == 0)
	return NULL;

    if (++cpio->ent.no >= cpio->nent)
	die("%s: %s: unexpected extra cpio entry", cpio->rpmbname, fnamedest);

    bool has_prefix = memcmp(fnamedest, "./", 2) == 0;
    if (dot != has_prefix)
	die("%s: %s: invalid cpio filename", cpio->rpmbname, fnamedest);

    cpio->ent.fnamelen -= 1 + dot;

    return &cpio->ent;
}

int rpmcpio_read(struct rpmcpio *cpio, void *buf, int n)
{
    assert(n >= 0);
    assert(cpio->ent.no >= 0);
    int left = cpio->n2 - cpio->n1;
    assert(left >= 0);
    if (n > left)
	n = left;
    if (n == 0)
	return 0;
    if (Fread(buf, 1, n, cpio->fd) != n)
	die("%s: %s: cannot read cpio data", cpio->rpmbname, cpio->fname);
    cpio->n1 += n;
    return n;
}

void rpmcpio_close(struct rpmcpio *cpio)
{
    Fclose(cpio->fd);
    free(cpio);
}
