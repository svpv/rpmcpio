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
    struct hard { unsigned ino, mode, nlink, cnt; } hard;
    struct fda fda;
    char fdabuf[BUFSIZA];
    struct header h;
    struct zreader z;
    struct cpioent ent;
    char buf[8192];
    char rpmbname[];
};

struct rpmcpio *rpmcpio_open(int dirfd, const char *rpmfname, unsigned *nent)
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
    cpio->hard.nlink = cpio->hard.cnt = 0;
    cpio->ent.mode = 0; // S_ISREG will fail

    return cpio;
}

void rpmcpio_close(struct rpmcpio *cpio)
{
    zreader_fini(&cpio->z);
    header_freedata(&cpio->h);
    close(cpio->fda.fd);
    free(cpio);
}

// Read the raw uncompressed stream.
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

// Got an excluded entry, fill cpio->ent from the header.
static void ent_0X(struct rpmcpio *cpio, unsigned ix)
{
    struct header *h = &cpio->h;
    if (ix >= h->fileCount)
	die("%s: bad cpio entry index", cpio->rpmbname);
    struct fi *fi = &h->ffi[ix];
    struct fx *fx = &h->ffx[ix];
    if (fi->seen)
	die("%s: %s%s: file listed twice", cpio->rpmbname,
	    h->src.rpm || h->old.fnames ? "" : h->strtab + fi->dn,
	    h->strtab + fi->bn);
    fi->seen = true;
    struct cpioent *ent = &cpio->ent;
    ent->mode = fi->mode;
    ent->fflags = fi->fflags;
    ent->ino = fx->ino;
    ent->nlink = fx->nlink;
    ent->mtime = fx->mtime;
    ent->size = fx->size;
    // filename
    if (h->src.rpm || h->old.fnames) {
	if (fi->blen == 0 || fi->blen >= (h->src.rpm ? 256 : 4096))
	    die("%s: bad filename length", cpio->rpmbname);
	ent->fnamelen = fi->blen;
	ent->fname = h->strtab + fi->bn;
    }
    else {
	ent->fnamelen = fi->dlen + fi->blen;
	if (ent->fnamelen >= 4096)
	    die("%s: bad filename length", cpio->rpmbname);
	memcpy(cpio->buf,            h->strtab + fi->dn, fi->dlen);
	memcpy(cpio->buf + fi->dlen, h->strtab + fi->bn, fi->blen + 1);
	ent->fname = cpio->buf;
    }
}

// Parse a regular cpio entry, then read filename.
static bool ent_01(struct rpmcpio *cpio, const char buf[110])
{
    if (memcmp(buf, "070701", 6) != 0)
	die("%s: bad cpio header magic", cpio->rpmbname);
    unsigned v[13];
    for (int i = 0; i < 13; i++)
	v[i] = hex1(buf + 6 + 8 * i, cpio->rpmbname);
    struct cpioent *ent = &cpio->ent;
    ent->ino = v[0];
    if (v[1] > 0xffff) die("%s: bad cpio mode", cpio->rpmbname);
    if (v[4] > 0xffff) die("%s: bad cpio nlink", cpio->rpmbname);
    ent->mode = v[1];
    // v[2]: uid, v[3]: gid
    ent->nlink = v[4];
    ent->mtime = v[5];
    ent->size = v[6];
    // v[7]: dev_major, v[8]: dev_minor, v[9]: rdev_major, v[10]: rdev_minor
    ent->fnamelen = v[11] - 1;
    // v[12]: checksum

    // The filename may start with "./", or may lack the leading '/'.
    struct header *h = &cpio->h;
    if (ent->fnamelen == 0 || ent->fnamelen >= (h->src.rpm ? 256 + 2 : 4096 + 1))
	die("%s: bad filename length", cpio->rpmbname);
    // cpio magic is 6 bytes, but filename is padded to a multiple of 4 bytes.
    // So we're going to read at least 2 bytes (minlen=1 + the null byte),
    // and the rest is rounded up to a multiple of 4.
    unsigned fnamesize = ent->fnamelen + 1;
    fnamesize = 2 + ((fnamesize - 2 + 3) & ~3);
    char *fname = cpio->buf + !h->src.rpm;
    if (zread(cpio, fname, fnamesize) != fnamesize)
	die("%s: cannot read cpio filename", cpio->rpmbname);
    cpio->curpos += fnamesize;
    // The filename must be null-terminated.
    if (fname[ent->fnamelen])
	die("%s: bad cpio filename", cpio->rpmbname);
    // Reached the trailer entry?
    if (memcmp(fname, "TRAILER!!!", ent->fnamelen) == 0)
	return true;
    // No embedded null bytes in the filename.
    if (strlen(fname) != ent->fnamelen)
	die("%s: bad cpio filename", cpio->rpmbname);
    // Adjust the prefix.
    if (memcmp(fname, "./", 2) == 0)
	fname++, ent->fnamelen--;
    if (fname[0] == '/')
	fname += h->src.rpm, ent->fnamelen -= h->src.rpm;
    else if (!h->src.rpm)
	*--fname = '/', ent->fnamelen++;
    // Recheck the length.
    if (ent->fnamelen == 0 || ent->fnamelen >= (h->src.rpm ? 256 : 4096))
	die("%s: bad filename length", cpio->rpmbname);
    ent->fname = fname;

    // Now match with the header.
    unsigned ix = header_find(&cpio->h, ent->fname, ent->fnamelen);
    if (ix == -1)
	die("%s: %s: file not in rpm header", cpio->rpmbname, ent->fname);
    struct fi *fi = &h->ffi[ix];
    if (fi->seen)
	die("%s: %s: file listed twice", cpio->rpmbname, ent->fname);
    fi->seen = true;
    if (ent->mode != fi->mode)
	die("%s: %s: bad file mode", cpio->rpmbname, ent->fname);
    ent->fflags = fi->fflags;
    return false;
}

const struct cpioent *rpmcpio_next(struct rpmcpio *cpio)
{
    // Skip the remaining data and read the header.
    // Try to combine it into a single zread call.
    unsigned long long nextpos = (cpio->endpos + 3) & ~3;
    unsigned long long skip = nextpos - cpio->curpos;
    while (skip > sizeof cpio->buf - 110) {
	size_t n = skip < sizeof cpio->buf ? skip : sizeof cpio->buf;
	if (zread(cpio, cpio->buf, n) != n)
	    die("%s: cannot skip cpio bytes", cpio->rpmbname);
	skip -= n;
    }
    struct header *h = &cpio->h;
    if (h->ffx) {
	// Expecting "07070X" + file index + 2-byte padding.
	if (zread(cpio, cpio->buf, skip + 16) != skip + 16)
	    die("%s: cannot read cpio header", cpio->rpmbname);
	if (memcmp(cpio->buf + skip, "07070X", 6) == 0) {
	    cpio->curpos = nextpos + 16;
	    ent_0X(cpio, hex1(cpio->buf + skip + 6, cpio->rpmbname));
	    goto gotent;
	}
	// At least the trailer is still "070701", so read the rest.
	if (zread(cpio, cpio->buf + skip + 16, 110 - 16) != 110 - 16)
	    die("%s: cannot read cpio header", cpio->rpmbname);
    }
    else if (zread(cpio, cpio->buf, skip + 110) != skip + 110)
	die("%s: cannot read cpio header", cpio->rpmbname);
    cpio->curpos = nextpos + 110;

    bool eof = ent_01(cpio, cpio->buf + skip);
    if (eof) {
	// Check for trailing garbage.
	char c;
	if (zread(cpio, &c, 1) == 1)
	    die("%s: trailing garbage", cpio->rpmbname);
	// The trailer shouldn't happen in the middle of a hardlink set.
	if (cpio->hard.cnt < cpio->hard.nlink)
	    die("%s: %s: meager hardlink set", cpio->rpmbname, "TRAILER");
	return NULL;
    }

gotent:;
    struct cpioent *ent = &cpio->ent;
    struct hard *hard = &cpio->hard;

    // Finalizing an existing hardlink set.
    if (hard->cnt && hard->cnt == hard->nlink) {
	// This new file is already not part of the preceding set.  Or is it?
	if (ent->ino == hard->ino)
	    die("%s: %s: obese hardlink set", cpio->rpmbname, ent->fname);
	hard->nlink = hard->cnt = 0;
    }

    // So is it a hardlink?  (With directories though, nlink has a special
    // meaning: it accounts for subdirs which reference the dir back via "..".)
    if (!S_ISDIR(ent->mode) && ent->nlink > 1) {
	// Old rpmbuild could package hardlinked symlinks, but such packages
	// could not be installed.  Starting with rpm-4.6.0-rc1~93, only
	// regular files can be packaged as hardlinks.  Forbidding hardlinked
	// symlinks is a sensible option.  (Hardlinks are much less of a problem
	// with file types other than regular files or symlinks, because there
	// is no data attached to those other files.)
	if (S_ISLNK(ent->mode))
	    die("%s: %s: hardlinked symlink", cpio->rpmbname, ent->fname);
	// Starting a new hardlink set?
	if (hard->cnt == 0) {
	    // E.g. ext4 has 16-bit i_links_count.
	    if (ent->nlink > 0xffff)
		die("%s: %s: bad nlink", cpio->rpmbname, ent->fname);
	    hard->ino = ent->ino, hard->mode = ent->mode;
	    hard->nlink = ent->nlink, hard->cnt = 1;
	}
	// Advancing in the existing hardlink set.
	else {
	    if (ent->ino != hard->ino)
		die("%s: %s: meager hardlink set", cpio->rpmbname, ent->fname);
	    if (ent->mode != hard->mode)
		die("%s: %s: fickle hardlink mode", cpio->rpmbname, ent->fname);
	    if (ent->nlink != hard->nlink)
		die("%s: %s: fickle nlink", cpio->rpmbname, ent->fname);
	    hard->cnt++;
	}
	// Non-last hardlink?
	if (hard->cnt < hard->nlink) {
	    // With ffx[], we've got the actual file size, so reset it to zero.
	    if (h->ffx)
		ent->size = 0;
	    // All but the last hardlink in a set must come with no data.
	    else if (ent->size)
		die("%s: %s: non-empty hardlink data", cpio->rpmbname, ent->fname);
	}
    }
    // Not a hardlink in the middle of the set?
    else if (hard->cnt)
	die("%s: %s: meager hardlink set", cpio->rpmbname, ent->fname);

    // Validate the size of symlink target.
    if (S_ISLNK(ent->mode)) {
	if (ent->size == 0)
	    die("%s: %s: zero-length symlink target", cpio->rpmbname, ent->fname);
	if (ent->size >= 4096)
	    die("%s: %s: symlink target too long", cpio->rpmbname, ent->fname);
    }

    cpio->endpos = cpio->curpos + ent->size;
    return ent;
}

size_t rpmcpio_read(struct rpmcpio *cpio, void *buf, size_t n)
{
    assert(S_ISREG(cpio->ent.mode));
    assert(n > 0);
    unsigned long long left = cpio->endpos - cpio->curpos;
    if (n > left)
	n = left;
    if (n == 0)
	return 0;
    if (zread(cpio, buf, n) != n)
	die("%s: %s: cannot read cpio file data", cpio->rpmbname, cpio->ent.fname);
    cpio->curpos += n;
    return n;
}

size_t rpmcpio_readlink(struct rpmcpio *cpio, char *buf)
{
    assert(S_ISLNK(cpio->ent.mode));
    unsigned long long n = cpio->endpos - cpio->curpos;
    struct cpioent *ent = &cpio->ent;
    assert(n == ent->linklen);
    if (zread(cpio, buf, n) != n)
	die("%s: %s: cannot read cpio symlink", cpio->rpmbname, ent->fname);
    char *s = buf;
    s[n] = '\0';
    if (strlen(s) < n)
	die("%s: %s: embedded null byte in cpio symlink", cpio->rpmbname, ent->fname);
    cpio->curpos += n;
    return n;
}
