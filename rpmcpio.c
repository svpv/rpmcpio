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
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "rpmcpio.h"
#include "reada.h"
#include "header.h"
#include "zreader.h"
#include "errexit.h"

struct rpmcpio {
    unsigned long long curpos; // current data pos
    unsigned long long endpos; // end data pos
    struct { unsigned ino, mode, nlink, cnt; } hard;
    struct fda fda;
    char fdabuf[BUFSIZA];
    struct header h;
    struct zreader z;
    struct cpioent ent;
    char fname[4096];
    char rpmbname[];
};

static_assert(sizeof(struct cpioent) == 64, "nice cpioent size");

struct rpmcpio *rpmcpio_open(int dirfd, const char *rpmfname,
			     unsigned *nent, bool all)
{
    const char *rpmbname = xbasename(rpmfname);
    int fd = openat(dirfd, rpmfname, O_RDONLY);
    if (fd < 0)
	die("%s: %m", rpmbname);

    size_t len = strlen(rpmbname);
    struct rpmcpio *cpio = xmalloc(sizeof(*cpio) + len + 1);
    memcpy(cpio->rpmbname, rpmbname, len + 1);

    cpio->fda = (struct fda) { fd, cpio->fdabuf };

    const char *err;
    if (!header_read(&cpio->h, &cpio->fda, &err))
	die("%s: %s", rpmbname, err);
    if (nent)
	*nent = cpio->h.fileCount;

    if (!zreader_init(&cpio->z, cpio->h.zprog))
	die("%s: cannot initialize %s decompressor", rpmbname, cpio->h.zprog);

    cpio->curpos = cpio->endpos = 0;
    cpio->ent.no = -1;
    cpio->hard.nlink = cpio->hard.cnt = 0;

    return cpio;
}

static inline size_t zread(struct rpmcpio *cpio, void *buf, size_t n)
{
    size_t ret = zreader_read(&cpio->z, &cpio->fda, buf, n);
    if (ret == -1) {
	if (errno)
	    die("%s: %m", cpio->rpmbname);
	die("%s: %s decompression failed", cpio->rpmbname, cpio->h.zprog);
    }
    return ret;
}

static void rpmcpio_skip(struct rpmcpio *cpio, int n)
{
    assert(n > 0);
    assert(cpio->ent.no >= 0);
    char buf[BUFSIZ];
    do {
	int m = (n > BUFSIZ) ? BUFSIZ : n;
	if (zread(cpio, buf, m) != m)
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
    if (zread(cpio, buf, 110) != 110)
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
    bool dot = !cpio->h.src.rpm;
    if (cpio->ent.fnamelen - dot > sizeof cpio->fname)
	die("%s: cpio filename too long", cpio->rpmbname);
    assert(fnamesize - dot <= sizeof cpio->fname);
    // The shortest filename is "./\0", except for src.rpm,
    // for which the shortest filename is "a\0".
    if (cpio->ent.fnamelen < 3U - dot)
	die("%s: cpio filename too short", cpio->rpmbname);
    char *fnamedest = cpio->fname - dot;
    if (zread(cpio, fnamedest, fnamesize) != fnamesize)
	die("%s: cannot read cpio filename", cpio->rpmbname);

    cpio->curpos += fnamesize;
    cpio->endpos = cpio->curpos + cpio->ent.size;

    if (memcmp(fnamedest, "TRAILER!!!", ent->fnamelen) == 0) {
	// The trailer shouldn't happen in the middle of a hardlink set.
	if (cpio->hard.cnt < cpio->hard.nlink)
	    die("%s: %s: meager hardlink set", cpio->rpmbname, "TRAILER");
	return NULL;
    }

    if (++cpio->ent.no >= cpio->h.fileCount)
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
	    // was misleading.  Starting with rpm-4.6.0-rc1~93, only regular
	    // files can have hardlinks.
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
    if (zread(cpio, buf, n) != n)
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
    if (zread(cpio, buf, n) != n)
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
    zreader_fini(&cpio->z);
    header_freedata(&cpio->h);
    close(cpio->fda.fd);
    free(cpio);
}
