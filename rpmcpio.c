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
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
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
    unsigned long long curpos; // current data pos
    unsigned long long endpos; // end data pos
    unsigned nent;
    struct { unsigned ino, mode, nlink, cnt; } hard;
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

    cpio->curpos = cpio->endpos = 0;
    cpio->nent = ne;
    cpio->ent.no = -1;
    cpio->hard.nlink = cpio->hard.cnt = 0;
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
    unsigned long long nextpos = (cpio->endpos + 3) & ~3;
    if (nextpos > cpio->curpos) {
	rpmcpio_skip(cpio, nextpos - cpio->curpos);
	cpio->curpos = nextpos;
    }
    char buf[110];
    if (Fread(buf, 1, 110, cpio->fd) != 110)
	die("%s: cannot read cpio header", cpio->rpmbname);
    if (memcmp(buf, "070701", 6) != 0)
	die("%s: bad cpio header magic", cpio->rpmbname);
    cpio->curpos += 110;

    struct cpioent *ent = &cpio->ent;

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

    cpio->curpos += fnamesize;
    cpio->endpos = cpio->curpos + cpio->ent.size;

    if (memcmp(fnamedest, "TRAILER!!!", ent->fnamelen) == 0) {
	// The trailer shouldn't happen in the middle of a hardlink set.
	if (cpio->hard.cnt < cpio->hard.nlink)
	    die("%s: %s: meager hardlink set", cpio->rpmbname, "TRAILER");
	return NULL;
    }

    if (++cpio->ent.no >= cpio->nent)
	die("%s: %s: unexpected extra cpio entry", cpio->rpmbname, fnamedest);

    bool has_prefix = memcmp(fnamedest, "./", 2) == 0;
    if (dot != has_prefix)
	die("%s: %s: invalid cpio filename", cpio->rpmbname, fnamedest);

    cpio->ent.fnamelen -= 1 + dot;

    // A valid ent->mode must fit into 16 bits.
    if (cpio->ent.mode > 0xffff)
	die("%s: %s: bad mode: 0%o", cpio->rpmbname, cpio->fname, cpio->ent.mode);

    // Finalizing an existing hardlink set.
    if (cpio->hard.cnt && cpio->hard.cnt == cpio->hard.nlink) {
	// This new file is already not part of the preceding set.  Or is it?
	if (ent->ino == cpio->hard.ino)
	    die("%s: %s: obese hardlink set", cpio->rpmbname, cpio->fname);
	cpio->hard.nlink = cpio->hard.cnt = 0;
    }

    // So is it a hardlink?
    if (!S_ISDIR(ent->mode) && ent->nlink > 1) {
	// Starting a new hardlink set?
	if (cpio->hard.cnt == 0) {
	    // E.g. ext4 has 16-bit i_links_count.
	    if (ent->nlink > 0xffff)
		die("%s: %s: bad nlink", cpio->rpmbname, cpio->fname);
	    cpio->hard.ino = ent->ino, cpio->hard.mode = ent->mode;
	    cpio->hard.nlink = ent->nlink, cpio->hard.cnt = 1;
	}
	// Advancing in the existing hardlink set.
	else {
	    if (ent->ino != cpio->hard.ino)
		die("%s: %s: meager hardlink set", cpio->rpmbname, cpio->fname);
	    if (ent->mode != cpio->hard.mode)
		die("%s: %s: fickle hardlink mode", cpio->rpmbname, cpio->fname);
	    if (ent->nlink != cpio->hard.nlink)
		die("%s: %s: fickle nlink", cpio->rpmbname, cpio->fname);
	    cpio->hard.cnt++;
	}
	// Non-last hardlink?
	if (cpio->hard.cnt < cpio->hard.nlink) {
	    // Symbolic links can be hardlinked, too.  With rpm-4.0, their size
	    // was misleading.  Starting with rpm-4.12.0-alpha~173, only
	    // regular files can have hardlinks.
	    if (S_ISLNK(ent->mode)) {
		if (0)
		    warn("%s: %s: hardlinked symlink", cpio->rpmbname, cpio->fname);
		cpio->endpos = cpio->curpos;
		ent->size = 0;
	    }
	    // All but the last hardlink in a set must come with no data.
	    else if (ent->size)
		die("%s: %s: non-empty hardlink data", cpio->rpmbname, cpio->fname);
	}
    }
    // Not a hardlink in the middle of the set?
    else if (cpio->hard.cnt)
	die("%s: %s: meager hardlink set", cpio->rpmbname, cpio->fname);

    // Validate the size of symlink target.
    if (S_ISLNK(ent->mode)) {
	if (ent->size == 0 && cpio->hard.cnt == cpio->hard.nlink)
	    die("%s: %s: zero-length symlink target", cpio->rpmbname, cpio->fname);
	if (ent->size >= PATH_MAX)
	    die("%s: %s: symlink target too long", cpio->rpmbname, cpio->fname);
    }

    return &cpio->ent;
}

size_t rpmcpio_read(struct rpmcpio *cpio, void *buf, size_t n)
{
    assert(cpio->ent.no != -1);
    assert(cpio->ent.packaged);
    assert(S_ISREG(cpio->ent.mode));
    assert(n > 0);
    unsigned long long left = cpio->endpos - cpio->curpos;
    if (n > left)
	n = left;
    if (n == 0)
	return 0;
    if (Fread(buf, 1, n, cpio->fd) != n)
	die("%s: %s: cannot read cpio file data", cpio->rpmbname, cpio->fname);
    cpio->curpos += n;
    return n;
}

size_t rpmcpio_readlink(struct rpmcpio *cpio, void *buf, size_t n)
{
    assert(cpio->ent.no != -1);
    assert(cpio->ent.packaged);
    assert(S_ISLNK(cpio->ent.mode));
    assert(cpio->ent.size > 0); // hardlinked symlink? something of a curiosity
    unsigned long long left = cpio->endpos - cpio->curpos;
    assert(left == cpio->ent.size);
    assert(n > cpio->ent.size);
    n = left;
    if (Fread(buf, 1, n, cpio->fd) != n)
	die("%s: %s: cannot read cpio symlink", cpio->rpmbname, cpio->fname);
    char *s = buf;
    s[n] = '\0';
    if (strlen(s) < n)
	die("%s: %s: embedded null byte in cpio symlink", cpio->rpmbname, cpio->fname);
    cpio->curpos += n;
    return n;
}

void rpmcpio_close(struct rpmcpio *cpio)
{
    Fclose(cpio->fd);
    free(cpio);
}
