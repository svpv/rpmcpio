#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <rpm/rpmlib.h>
#include "rpmcpio.h"
#include "errexit.h"

static const char *getStringTag(Header h, int tag)
{
   int type;
   int count;
   void *data;
   int rc = headerGetEntry(h, tag, &type, &data, &count);
   if (rc == 1) {
      assert(type == RPM_STRING_TYPE && count == 1);
      return (const char *)data;
   }
   return NULL;
}

static int getFileCount(Header h)
{
   int count;
   int ret = headerGetEntry(h, RPMTAG_BASENAMES, NULL, NULL, &count);
   return ret == 1 ? count : 0;
}

struct rpmcpio {
    FD_t fd;
    // n1: current data pos
    // n2: end data pos
    // n3: next entry pos
    int n1, n2, n3;
    int nent;
    union { bool rpm; } src;
    struct { char buf[1024]; int size; } peek;
    struct cpioent ent;
    // two more bytes for padding, see below
    char fname[PATH_MAX+2];
    const char *rpmbname;
    char rpmfname[];
};

struct rpmcpio *rpmcpio_open(const char *rpmfname, int *nent)
{
    const char *rpmbname = xbasename(rpmfname);
    FD_t fd = Fopen(rpmfname, "r.ufdio");
    if (Ferror(fd))
	die("%s: cannot open", rpmbname);

    Header h;
    union { int rpm; } src;
    int rc = rpmReadPackageHeader(fd, &h, &src.rpm, NULL, NULL);
    if (rc)
	die("%s: cannot read rpm header", rpmbname);

    int ne = getFileCount(h);
    if (nent)
	*nent = ne;
    if (ne == 0) {
	headerFree(h);
	Fclose(fd);
	return NULL;
    }

    size_t len = strlen(rpmfname);
    struct rpmcpio *cpio = xmalloc(sizeof(*cpio) + len + 1);
    cpio->ent.rpmfname = memcpy(cpio->rpmfname, rpmfname, len + 1);
    cpio->ent.rpmbname = cpio->rpmbname = cpio->rpmfname + (rpmbname - rpmfname);

    char mode[] = "r.gzdio";
    const char *compr = getStringTag(h, RPMTAG_PAYLOADCOMPRESSOR);
    if (compr && compr[0] && compr[1] == 'z')
	mode[2] = compr[0];
    headerFree(h);
    cpio->fd = Fdopen(fd, mode);
    if (Ferror(cpio->fd))
	die("%s: cannot open payload", rpmbname);
    if (cpio->fd != fd)
	Fclose(fd);

    cpio->n1 = cpio->n2 = cpio->n3 = 0;
    cpio->nent = ne;
    cpio->ent.no = -1;
    cpio->src.rpm = src.rpm;
    cpio->peek.size = 0;
    return cpio;
}

static void rpmcpio_skip(struct rpmcpio *cpio, int n)
{
    assert(n > 0);
    assert(cpio->ent.no >= 0);
    char buf[BUFSIZ];
    do {
	int m = (n > BUFSIZ) ? BUFSIZ : n;
	if (Fread(buf, m, 1, cpio->fd) != 1)
	    die("%s: cannot skip cpio bytes", cpio->rpmbname);
	n -= m;
    }
    while (n > 0);
}

static const unsigned char hex[256] = {
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
};

const struct cpioent *rpmcpio_next(struct rpmcpio *cpio)
{
    if (cpio->n3 > cpio->n1) {
	rpmcpio_skip(cpio, cpio->n3 - cpio->n1);
	cpio->n1 = cpio->n3;
    }
    char buf[110];
    if (Fread(buf, 110, 1, cpio->fd) != 1)
	die("%s: cannot read cpio header", cpio->rpmbname);
    if (memcmp(buf, "070701", 6) != 0)
	die("%s: bad cpio header magic", cpio->rpmbname);
    cpio->n1 += 110;

    unsigned *out = (unsigned *) &cpio->ent;
    for (int i = 0; i < 13; i++) {
	const char *s = buf + 6 + i * 8;
	unsigned u = 0;
	for (int j = 0; j < 8; j++) {
	    unsigned v = hex[(unsigned char) s[j]];
	    if (v == 0xee)
		die("%s: invalid header", cpio->rpmbname);
	    u = (u << 4) | v;
	}
	out[i] = u;
    }

    // cpio magic is 6 bytes, but filename is padded to a multiple of four bytes
    unsigned fnamesize = ((cpio->ent.fnamelen + 1) & ~3) + 2;
    // At this stage, fnamelen includes '\0', and fname should start with "./".
    // The leading dot will be stripped implicitly by copying to &fname[-1].
    // src.rpm is the exeption: there should be no prefix, and nothing will be stripped.
    bool dot = !cpio->src.rpm;
    if (cpio->ent.fnamelen - dot > PATH_MAX)
	die("%s: cpio filename too long", cpio->rpmbname);
    assert(fnamesize - dot <= sizeof cpio->fname);
    // The shortest filename is "./\0", except for src.rpm,
    // for which the shortest filename is "a\0".
    if (cpio->ent.fnamelen < 3U - dot)
	die("%s: cpio filename too short", cpio->rpmbname);
    char *fnamedest = cpio->fname - dot;
    if (Fread(fnamedest, fnamesize, 1, cpio->fd) != 1)
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

    cpio->ent.fnamelen--;

    return &cpio->ent;
}

#define READ(cpio, buf, n)			\
    do {					\
	assert(n >= 0);				\
	assert(cpio->ent.no >= 0);		\
	int left = cpio->n2 - cpio->n1;		\
	assert(left >= 0);			\
	if (n > left)				\
	    n = left;				\
	if (n == 0)				\
	    break;				\
	if (Fread(buf, n, 1, cpio->fd) != 1)	\
	    die("%s: %s: cannot read cpio data", cpio->rpmbname, cpio->fname); \
	cpio->n1 += n;				\
    }						\
    while (0)

int rpmcpio_peek(struct rpmcpio *cpio, void *buf, int n)
{
    assert(cpio->peek.size == 0);
    assert(n <= (int) sizeof cpio->peek.buf);
    READ(cpio, buf, n);
    if (n == 0)
	return 0;
    memcpy(cpio->peek.buf, buf, n);
    cpio->peek.size = n;
    return n;
}

int rpmcpio_read(struct rpmcpio *cpio, void *buf, int n)
{
    if (cpio->peek.size) {
	assert(n >= cpio->peek.size);
	memcpy(buf, cpio->peek.buf, cpio->peek.size);
	buf += cpio->peek.size;
	n -= cpio->peek.size;
    }
    READ(cpio, buf, n);
    n += cpio->peek.size;
    cpio->peek.size = 0;
    return n;
}

void rpmcpio_close(struct rpmcpio *cpio)
{
    Fclose(cpio->fd);
    free(cpio);
}
