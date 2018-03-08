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

    // defaults
    h->fileCount = 0;
    memcpy(h->zprog, "lzma", sizeof "lzma");

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

    for (unsigned i = 0; i < hdr.il; i++) {
	struct { unsigned tag, type, off, cnt; } e;
	if (reada(fda, &e, sizeof e) != sizeof e)
	    return ERR("cannot read pkg header");
	if (e.tag == htonl(RPMTAG_FILEMODES)) {
	    h->fileCount = -1;
	    if (e.type == htonl(RPM_INT16_TYPE) && e.cnt)
		h->fileCount = ntohl(e.cnt);
	    if (h->fileCount == -1)
		return ERR("bad file count");
	}
    }

    if (skipa(fda, hdr.dl) != hdr.dl)
	return ERR("cannot read pkg header");

    return true;
}
