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
#include <arpa/inet.h>
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
#define RPMTAG_FILEFLAGS         1037
#define RPMTAG_SOURCERPM         1044
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
	struct tabent fileflags;
	struct tabent sourcerpm;
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
	.fileflags         = { RPMTAG_FILEFLAGS, RPM_INT32_TYPE },
	.sourcerpm         = { RPMTAG_SOURCERPM, RPM_STRING_TYPE },
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

    if (skipa(fda, hdr.dl) != hdr.dl)
	return ERR("cannot read pkg header");

    h->fileCount = tab.filemodes.cnt;
    memcpy(h->zprog, "lzma", sizeof "lzma");

    return true;
}
