// Copyright (c) 2018 Alexey Tourbin
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
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <arpa/inet.h>
#include <endian.h>
#include <sys/stat.h>
#include "reada.h"
#include "header.h"

#define ERR(s) (*err = s, false)

bool header_read(struct header *h, struct fda *fda, const char **err)
{
    struct rpmlead {
	unsigned char magic[4];
	unsigned char major;
	unsigned char minor;
	short type;
	short archnum;
	char name[66];
	short osnum;
	short signature_type;
	char reserved[16];
    } lead;
    if (reada(fda, &lead, sizeof lead) != sizeof lead)
	return ERR("cannot read rpmlead");
    const unsigned char lmag[4] = { 0xed, 0xab, 0xee, 0xdb };
    if (memcmp(lead.magic, lmag, 4))
	return ERR("bad rpmlead magic");
    // The file format version should be 3.0.  rpm once used to set
    // lead.major=4, specifically in conjunction with --nodirtokens.
    // rpm does not check lead.minor.
    if (lead.major < 3 || lead.major > 4)
	return ERR("unsupported rpmlead version");
    if (lead.type == 0)
	h->src.rpm = false;
    else if (lead.type == htons(1))
	h->src.rpm = true;
    else
	return ERR("bad rpmlead type");
    // Pre-historic, before 2000.
    if (lead.signature_type != htons(5))
	return ERR("old rpmlead signature not supported");

    struct { unsigned mag[2], il, dl; } hdr;
    if (reada(fda, &hdr, sizeof hdr) != sizeof hdr)
	return ERR("cannot read sig header");
    const unsigned char hmag[8] = { 0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00 };
    if (memcmp(&hdr.mag, hmag, 8))
	return ERR("bad sig header magic");
    hdr.il = ntohl(hdr.il);
    hdr.dl = ntohl(hdr.dl);
    if (hdr.il > 32 || hdr.dl > (64<<10)) // like hdrblobRead
	return ERR("bad sig header size");
    size_t sigsize = 16 * hdr.il + ((hdr.dl + 7) & ~7);
    if (sigsize && skipa(fda, sigsize) != sigsize)
	return ERR("cannot read sig header");

    if (reada(fda, &hdr, sizeof hdr) != sizeof hdr)
	return ERR("cannot read pkg header");
    if (memcmp(&hdr.mag, hmag, 8))
	return ERR("bad pkg header magic");
    hdr.il = ntohl(hdr.il);
    hdr.dl = ntohl(hdr.dl);
    if (hdr.il > (64<<10) || hdr.dl > (256<<20))
	return ERR("bad sig header size");

#define RPM_INT16_TYPE        3
#define RPM_INT32_TYPE        4
#define RPM_INT64_TYPE        5
#define RPM_STRING_TYPE       6
#define RPM_STRING_ARRAY_TYPE 8

#define RPMTAG_OLDFILENAMES      1027
#define RPMTAG_FILESIZES         1028
#define RPMTAG_FILEMODES         1030
#define RPMTAG_FILEMTIMES        1034
#define RPMTAG_FILEFLAGS         1037
#define RPMTAG_FILEUSERNAME      1039
#define RPMTAG_FILEGROUPNAME     1040
#define RPMTAG_SOURCERPM         1044
#define RPMTAG_FILEDEVICES       1095
#define RPMTAG_FILEINODES        1096
#define RPMTAG_DIRINDEXES        1116
#define RPMTAG_BASENAMES         1117
#define RPMTAG_DIRNAMES          1118
#define RPMTAG_PAYLOADCOMPRESSOR 1125
#define RPMTAG_LONGFILESIZES     5008

    // The tags that we need will be placed in a tightly-packed table.
    // If a tag exists and its table entry is filled, cnt must be non-zero.
    struct tabent { unsigned tag, type, cnt, off, nextoff; };
    struct {
	struct tabent oldfilenames;
	struct tabent filesizes;
	struct tabent filemodes;
	struct tabent filemtimes;
	struct tabent fileflags;
	struct tabent fileusername;
	struct tabent filegroupname;
	struct tabent sourcerpm;
	struct tabent filedevices;
	struct tabent fileinodes;
	struct tabent dirindexes;
	struct tabent basenames;
	struct tabent dirnames;
	struct tabent payloadcompressor;
	struct tabent longfilesizes;
	// Non-existent tag with maximum value, to facilitate the merge-like algorithm.
	struct tabent nil;
    } tab = {
	.oldfilenames      = { RPMTAG_OLDFILENAMES, RPM_STRING_ARRAY_TYPE },
	.filesizes         = { RPMTAG_FILESIZES, RPM_INT32_TYPE },
	.filemodes         = { RPMTAG_FILEMODES, RPM_INT16_TYPE },
	.filemtimes        = { RPMTAG_FILEMTIMES, RPM_INT32_TYPE },
	.fileflags         = { RPMTAG_FILEFLAGS, RPM_INT32_TYPE },
	.fileusername      = { RPMTAG_FILEUSERNAME, RPM_STRING_ARRAY_TYPE },
	.filegroupname     = { RPMTAG_FILEGROUPNAME, RPM_STRING_ARRAY_TYPE },
	.sourcerpm         = { RPMTAG_SOURCERPM, RPM_STRING_TYPE },
	.filedevices       = { RPMTAG_FILEDEVICES, RPM_INT32_TYPE },
	.fileinodes        = { RPMTAG_FILEINODES, RPM_INT32_TYPE },
	.dirindexes        = { RPMTAG_DIRINDEXES, RPM_INT32_TYPE },
	.basenames         = { RPMTAG_BASENAMES, RPM_STRING_ARRAY_TYPE },
	.dirnames          = { RPMTAG_DIRNAMES, RPM_STRING_ARRAY_TYPE },
	.payloadcompressor = { RPMTAG_PAYLOADCOMPRESSOR, RPM_STRING_TYPE },
	.longfilesizes     = { RPMTAG_LONGFILESIZES, RPM_INT64_TYPE },
	.nil               = { -1, -1 }
    };

    // Run the merge which fills the table.
    struct tabent *te = &tab.oldfilenames;
    struct tabent *nextoffte = NULL;
    unsigned lasttag = 0, lastoff = 0;
    for (unsigned i = 0; i < hdr.il; i++) {
	struct { unsigned tag, type, off, cnt; } e;
	if (reada(fda, &e, sizeof e) != sizeof e)
	    return ERR("cannot read pkg header");
	unsigned tag = ntohl(e.tag);
	unsigned off = ntohl(e.off);
	if (tag <= lasttag)
	    return ERR("tags out of order");
	lasttag = tag;
	if (nextoffte) {
	    nextoffte->nextoff = off;
	    nextoffte = NULL;
	}
	while (te->tag < tag)
	    te++;
	if (te->tag > tag)
	    continue;
	if (lastoff >= off)
	    return ERR("offsets out of order");
	lastoff = off;
	if (e.cnt == 0)
	    return ERR("zero tag count");
	unsigned type = ntohl(e.type);
	if (type != te->type)
	    return ERR("bad tag type");
	te->cnt = ntohl(e.cnt);
	te->off = off;
	nextoffte = te; // set te->nextoff on the next iteration
    }
    if (nextoffte && nextoffte != &tab.nil) {
	if (nextoffte->off >= hdr.dl)
	    return ERR("offsets out of order");
	nextoffte->off = hdr.dl;
	nextoffte = NULL;
    }

    if (h->src.rpm ^ !tab.sourcerpm.cnt)
	return ERR("lead.type and header.sourcerpm do not match");

    // FILEMODES and FILEFLAGS are mandatory, and determine file count.
    if (tab.filemodes.cnt != tab.fileflags.cnt)
	return ERR("file count mismatch");

    // File info, to be malloc'd.
    struct fi *ffi = h->ffi = NULL;
    struct fx *ffx = h->ffx = NULL;

    // Current offset within the header's data store.
    unsigned doff = 0;

    // File count is zero?  Fast forward to PayloadCompressor.
    unsigned fileCount = h->fileCount = tab.filemodes.cnt;
    if (!fileCount)
	goto compressor;

    // If it's LONGFILESIZES, we're about to load more tags.
    if (tab.longfilesizes.cnt) {
	if (tab.longfilesizes.cnt != fileCount || tab.filesizes.cnt)
	    return ERR("bad longfilesizes");
	if (tab.filemtimes.cnt != fileCount)
	    return ERR("bad filemtimes");
    }

    // Either OLDFILENAMES or BASENAMES+DIRNAMES+DIRINDEXES.
    if (tab.oldfilenames.cnt == fileCount) {
	if (tab.basenames.cnt)
	    return ERR("bad filenames");
    }
    else {
	if (tab.basenames.cnt != fileCount || tab.oldfilenames.cnt)
	    return ERR("bad filenames");
	// Will directories be loaded?
	if (!h->src.rpm) {
	    if (tab.dirindexes.cnt != fileCount)
		return ERR("bad dirindexes");
	    // Suppose the dirnames count is too big, so what?  Couldn't it be
	    // that some dirnames are unused?  Well, this can induce integer
	    // overflow with malloc.  (And the package is probably corrupt.)
	    if (tab.dirnames.cnt > tab.basenames.cnt)
		return ERR("bad dirnames");
	    // Whether dirnames count is too small is determined at the time
	    // of unpacking dirindexes.
	}
    }
    h->old.fnames = tab.oldfilenames.cnt;

    // Assume each file takes at least 16 bytes in the data store.
    // This is mostly to avoid integer overflow with malloc.
    if (h->fileCount > (16<<20))
	return ERR("bad file count");
    // Allocate in a single chunk.
    size_t alloc = fileCount * sizeof(*ffi);
#define tabSize(x) (tab.x.nextoff - tab.x.off)
    if (tab.oldfilenames.cnt)
	alloc += tabSize(oldfilenames);
    if (tab.longfilesizes.cnt)
	alloc += fileCount * sizeof(*ffx);
    // We have a few stages which need temporary storage:
    // - read fileusername and convert them to fi->uid
    // - read filegroupname and convert them to fi->gid
    // - read filedevices and fileinodes to detect hardinks and set fx->ino
    // - remap dirindexes to direct offsets into strtab
    // Trying to replay the events and estimate the usage precisely.
    size_t morealloc = 0;
#define peakAlloc(s) morealloc = (s) > morealloc ? (s) : morealloc
    peakAlloc(tabSize(fileusername));
    peakAlloc(tabSize(filegroupname));
    if (tab.longfilesizes.cnt)
	peakAlloc(fileCount * 12);
    if (tab.basenames.cnt) {
	size_t s = tabSize(basenames);
	if (!h->src.rpm)
	    s += tabSize(dirnames) + fileCount * 6;
	peakAlloc(s);
    }
    alloc += morealloc + 4; // strtab[0] + align to 4
    ffi = h->ffi = malloc(alloc);
    if (!ffi)
	return ERR("malloc failed");
    if (tab.longfilesizes.cnt) {
	ffx = h->ffx = (void *) (ffi + fileCount);
	h->strtab = (void *) (ffx + fileCount);
    }
    else
	h->strtab = (void *) (ffi + fileCount);

    // Fill the strtab with basenames and dirnames.
    char *strpos = h->strtab;
    // E.g. linkto=0 points to an empty string.
    *strpos++ = '\0';
    // The end of a segment loaded into the strtab.
    char *strend;

#undef ERR
#define ERR(s) (free(ffi), *err = s, false)

#define SkipTo(off)					\
    do {						\
	assert(off >= doff);				\
	unsigned skip = off - doff;			\
	if (skip && skipa(fda, skip) != skip)		\
	    return ERR("cannot read header data");	\
	doff += skip;					\
    } while (0)

#define Taking(te, cnt, w, s)				\
    do {						\
	if (te->nextoff - te->off < cnt * sizeof w)	\
	    return ERR("bad " s);			\
	doff += cnt * sizeof w;				\
    } while (0)

#define Read1(w)					\
    do {						\
	if (reada(fda, &w, sizeof w) != sizeof w)	\
	    return ERR("cannot read header data");	\
    } while (0)

    // Take a string or a string array into the strtab.
#define TakeS(te)					\
    do {						\
	unsigned size = te->nextoff - te->off;		\
	if (reada(fda, strpos, size) != size)		\
	    return ERR("cannot read header data");	\
	doff += size;					\
	strend = strpos + size;				\
	if (strend[-1] != '\0')				\
	    return ERR("malformed string tag");		\
    } while (0)

    te = &tab.oldfilenames;
    if (te->cnt) {
	SkipTo(te->off);
	TakeS(te);
	for (unsigned i = 0; i < fileCount; i++) {
	    if (strpos == strend)
		return ERR("bad filenames");
	    size_t len = strlen(strpos);
	    if (len > 0xffff)
		return ERR("bad filenames");
	    ffi[i].bn = strpos - h->strtab;
	    ffi[i].blen = len;
	    strpos += len + 1;
	    // dn and dlen not set for h->old.fnames,
	    // neither for h->src.rpm
	}
    }

    te = &tab.filemodes;
    SkipTo(te->off);
    unsigned short fmode;
    Taking(te, fileCount, fmode, "filemodes");
    for (unsigned i = 0; i < fileCount; i++) {
	Read1(fmode);
	ffi[i].mode = ntohs(fmode);
	// Zero out fi->seen with the first unconditional field.
	ffi[i].seen = false;
    }

    if (ffx) {
	te = &tab.filemtimes;
	SkipTo(te->off);
	unsigned fmtime;
	Taking(te, fileCount, fmtime, "filemtimes");
	for (unsigned i = 0; i < fileCount; i++) {
	    Read1(fmtime);
	    ffx[i].mtime = ntohl(fmtime);
	}
    }

    te = &tab.fileflags;
    SkipTo(te->off);
    unsigned fflags;
    Taking(te, fileCount, fflags, "fileflags");
    for (unsigned i = 0; i < fileCount; i++) {
	Read1(fflags);
	fflags = ntohl(fflags);
	ffi[i].fflags = fflags;
    }

    // Fill strtab for a temporary pass, then reset.
    char *savepos;

    te = &tab.fileusername;
    savepos = strpos;
    TakeS(te);
    for (unsigned i = 0; i < fileCount; i++) {
	if (strpos == strend)
	    return ERR("bad fileusername");
	size_t len = strlen(strpos);
	if (len == 0)
	    return ERR("bad fileusername");
	ffi[i].uid = len != 4 || memcmp(strpos, "root", 4);
	strpos += len + 1;
    }
    strpos = savepos;

    te = &tab.filegroupname;
    savepos = strpos;
    TakeS(te);
    for (unsigned i = 0; i < fileCount; i++) {
	if (strpos == strend)
	    return ERR("bad filegroupname");
	size_t len = strlen(strpos);
	if (len == 0)
	    return ERR("bad filegroupname");
	ffi[i].gid = len != 4 || memcmp(strpos, "root", 4);
	strpos += len + 1;
    }
    strpos = savepos;

    if (ffx) {
	// TODO: hardlink detection pass.
    }

    te = &tab.dirindexes;
    if (te->cnt && !h->src.rpm) {
	SkipTo(te->off);
	unsigned dindex;
	Taking(te, fileCount, dindex, "dirindexes");
	for (unsigned i = 0; i < fileCount; i++) {
	    Read1(dindex);
	    dindex = ntohl(dindex);
	    if (dindex >= tab.dirnames.cnt)
		return ERR("bad dirindexes");
	    // Place raw di into dn, will update in just a moment.
	    ffi[i].dn = dindex;
	}
    }

    te = &tab.basenames;
    if (te->cnt) {
	SkipTo(te->off);
	TakeS(te);
	for (unsigned i = 0; i < fileCount; i++) {
	    if (strpos == strend)
		return ERR("bad basenames");
	    size_t len = strlen(strpos);
	    if (len > 0xffff)
		return ERR("bad basenames");
	    ffi[i].bn = strpos - h->strtab;
	    ffi[i].blen = len;
	    strpos += len + 1;
	}
    }

    te = &tab.dirnames;
    if (te->cnt && !h->src.rpm) {
	SkipTo(te->off);
	TakeS(te);
	// Unpack dirnames' offsets and lengths into temporary arrays.
	unsigned *dn = (void *) (((uintptr_t) strend + 3) & ~3);
	unsigned short *dl = (void *) (dn + tab.dirnames.cnt);
	for (unsigned i = 0; i < tab.dirnames.cnt; i++) {
	    if (strpos == strend)
		return ERR("bad dirnames");
	    if (*strpos != '/')
		return ERR("bad dirnames");
	    size_t len = strlen(strpos);
	    if (len > 0xffff)
		return ERR("bad dirnames");
	    dn[i] = strpos - h->strtab;
	    dl[i] = len;
	    strpos += len + 1;
	}
	// Now replace di with dn.
	for (unsigned i = 0; i < fileCount; i++) {
	    unsigned j = ffi[i].dn;
	    ffi[i].dn = dn[j];
	    ffi[i].dlen = dl[j];
	}
    }

    // Take a small string into a fixed-size buffer.
#define TakeSB(te, buf, s)				\
    do {						\
	unsigned size = te->nextoff - te->off;		\
	if (size > sizeof buf)				\
	    return ERR(s " too long");			\
	if (reada(fda, buf, size) != size)		\
	    return ERR("cannot read header data");	\
	doff += size;					\
	if (buf[size-1] != '\0')			\
	    return ERR("malformed string tag");		\
	if (buf[0] == '\0')				\
	    return ERR("empty " s);			\
    } while (0)

compressor:
    te = &tab.payloadcompressor;
    if (te->cnt) {
	SkipTo(te->off);
	TakeSB(te, h->zprog, "payloadcompressor");
    }
    else
	memcpy(h->zprog, "gzip", sizeof "gzip");

    if (ffx) {
	te = &tab.longfilesizes;
	SkipTo(te->off);
	unsigned long long longfsize;
	Taking(te, fileCount, longfsize, "longfilesizes");
	for (unsigned i = 0; i < fileCount; i++) {
	    Read1(longfsize);
	    if (S_ISLNK(ffi[i].mode))
		continue; // already set to target length
	    longfsize = be64toh(longfsize);
	    if (longfsize > 0xffffFFFFffffUL)
		return ERR("bad longfilesizes");
	    ffx[i].size = longfsize;
	}
    }

    SkipTo(hdr.dl);

    h->prevFound = -1;
    return true;
}

void header_freedata(struct header *h)
{
    if (h->fileCount)
	free(h->ffi);
}

// Compare two strings whose lengths are known.
static inline int strlencmp(const char *s1, size_t len1, const char *s2, size_t len2)
{
    if (len1 == len2)
	return memcmp(s1, s2, len1);
    if (len1 < len2) {
	int cmp = memcmp(s1, s2, len1);
	// If cmp == 0, still s1 < s2, because s1 is shorter.
	return cmp - (cmp == 0);
    }
    int cmp = memcmp(s1, s2, len2);
    return cmp + (cmp == 0);
}

unsigned header_find(struct header *h, const char *fname, size_t flen)
{
    // Initialize the binary search range.
    size_t lo = 0, hi = h->fileCount;

    // Direct the first iteration of the binary search loop to examine
    // the element following the previously found one, rather than the
    // middle element.  Since filenames in the payload are mostly sorted
    // (the exception being hardlinks), we expect the immediate hit.
    size_t at = ++h->prevFound;
    if (at >= h->fileCount) {
	assert(h->fileCount > 0);
	at = (lo + hi) / 2;
    }

    // If no dirnames need to be considered, run a much simplified version
    // of the binary search loop (which also delivers better performance).
    if (h->src.rpm || h->old.fnames) {
	while (1) {
	    struct fi *fi = &h->ffi[at];
	    int cmp = strlencmp(fname, flen, h->strtab + fi->bn, fi->blen);
	    if (cmp == 0) {
		h->prevFound = at;
		return at;
	    }
	    if (cmp < 0)
		hi = at;
	    else
		lo = at + 1;
	    if (lo >= hi)
		return -1;
	    at = (lo + hi) / 2;
	}
    }

    // Digest fname.
    const char *dn = fname;
    const char *slash = strrchr(fname, '/');
    assert(slash);
    const char *bn = slash + 1;
    // Dirnames have trailing slashes.
    size_t dlen = bn - fname;
    size_t blen = flen - dlen;

    // Previous fi->dn against which dn was matched.
    unsigned lastdn = -1;
    int dircmp = 0;

    while (1) {
	struct fi *fi = &h->ffi[at];
	int cmp;
	if (dlen == fi->dlen) {
	    if (fi->dn != lastdn) {
		dircmp = memcmp(dn, h->strtab + fi->dn, dlen);
		lastdn = fi->dn;
	    }
	    cmp = dircmp;
	    if (cmp == 0) {
		// If dirnames are equal, proceed with basenames.  This is
		// the only case where both basenames need to be compared.
		cmp = strlencmp(bn, blen, h->strtab + fi->bn, fi->blen);
		if (cmp == 0) {
		    h->prevFound = at;
		    return at;
		}
	    }
	}
	else if (dlen < fi->dlen) {
	    // dn is shorter than fi->dn, the result of comparsion should only
	    // depend on [dn,bn] and fi->dn, but not on fi->bn.  Thus dircmp
	    // can cache a full comparsion, not just the dirname comparison.
	    if (fi->dn != lastdn) {
		dircmp = memcmp(dn, h->strtab + fi->dn, dlen);
		lastdn = fi->dn;
		if (dircmp == 0) {
		    // dn is shorter than fi->dn, compare bn with the rest of fi->dn.
		    dircmp = strlencmp(bn, blen, h->strtab + fi->dn + dlen, fi->dlen - dlen);
		    // Equality should never hold, even with dir+subdir pairs,
		    // because dirnames have trailing slashes.
		    if (dircmp == 0)
			return -1;
		}
	    }
	    cmp = dircmp;
	}
	else {
	    if (fi->dn != lastdn) {
		dircmp = memcmp(fname, h->strtab + fi->dn, fi->dlen);
		lastdn = fi->dn;
	    }
	    cmp = dircmp;
	    if (cmp == 0) {
		// dn is longer than fi->dn, compare the rest of dn with fi->bn.
		cmp = strlencmp(dn + fi->dlen, dlen - fi->dlen, h->strtab + fi->bn, fi->blen);
		if (cmp == 0)
		    return -1;
	    }
	}
	if (cmp < 0)
	    hi = at;
	else
	    lo = at + 1;
	if (lo >= hi)
	    return -1;
	at = (lo + hi) / 2;
    }
}
