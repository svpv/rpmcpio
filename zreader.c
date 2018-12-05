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
#include <assert.h>
#include <errno.h>
#include "reada.h"
#include "zreader.h"

// Decompresson error, as opposed to a system error.
#define ZREAD_ERR (errno = 0, -1)

static size_t read_gzip(struct zreader *z, struct fda *fda, void *buf, size_t size)
{
    assert(size + 1 > 1);

    size_t total = 0;
    z_stream *strm = &z->u.strm;

    do {
	// Prefill the internal buffer.
	unsigned long w;
	ssize_t ret = peeka(fda, &w, sizeof w);
	if (ret <= 0) {
	    // expected vs unexpected EOF
	    if (ret == 0) {
		if (z->eos)
		    return total;
		// not a system failure, reset errno
		errno = 0;
	    }
	    return -1;
	}

	// Got some data, but the last inflate call may have reported
	// Z_STREAM_END.  Trying to concatenate the next gzip stream.
	// This is slightly different from zlib:gzread(), which tends
	// to discard "trailing grabage".
	if (z->eos) {
	    z->eos = false;
	    if (inflateReset(strm) != Z_OK)
		return ZREAD_ERR;
	}

	// The inflate call is imminent.
	strm->next_in = (void *) fda->cur;
	strm->avail_in = fda->end - fda->cur;
	strm->next_out = buf;
	strm->avail_out = size;

	int zret = inflate(strm, Z_NO_FLUSH);
	if (zret == Z_STREAM_END)
	    z->eos = true;
	else if (zret != Z_OK)
	    // XXX zlib.h says Z_BUF_ERROR is not fatal,
	    // but obviously we can't expand the output buffer.
	    // The condition probably can't happen.
	    return ZREAD_ERR;

	// See how many bytes have been consumed.
	fda->cur = fda->end - strm->avail_in;
	assert(fda->cur == (void *) strm->next_in);

	// See how many bytes have been recovered.
	size_t n = size - strm->avail_out;
	size = strm->avail_out, buf = (char *) buf + n;
	total += n;
    } while (size);

    return total;
}

static void fini_gzip(struct zreader *z)
{
    inflateEnd(&z->u.strm);
}

static bool init_gzip(struct zreader *z)
{
    z_stream *strm = &z->u.strm;

    // inflateInit2 demands that these fields be initialized.
    strm->next_in = NULL;
    strm->avail_in = 0;
    strm->zalloc = NULL;
    strm->zfree = NULL;
    strm->opaque = NULL;

    int zret = inflateInit2(strm, 15 + 16); // 32K window + gzip only
    if (zret != Z_OK)
	return false;

    z->read = read_gzip;
    z->fini = fini_gzip;
    return true;
}

static size_t read_lzma(struct zreader *z, struct fda *fda, void *buf, size_t size)
{
    assert(size + 1 > 1);

    size_t total = 0;
    lzma_stream *lzma = &z->u.lzma;

    do {
	unsigned long w;
	ssize_t ret = peeka(fda, &w, sizeof w);
	if (ret <= 0) {
	    if (ret == 0) {
		if (z->eos)
		    return total;
		errno = 0;
	    }
	    return -1;
	}

	// Still have some data?  LZMA1 streams don't have magic, but they
	// do have uncompressed size / EOS marker, so EOS is reported reliably.
	// LZMA1 streams are not supposed to be concatenated, trailing garbage
	// not supported.
	if (z->eos)
	    return ZREAD_ERR;

	lzma->next_in = (void *) fda->cur;
	lzma->avail_in = fda->end - fda->cur;
	lzma->next_out = buf;
	lzma->avail_out = size;

	lzma_ret zret = lzma_code(lzma, LZMA_RUN);
	if (zret == Z_STREAM_END)
	    z->eos = true;
	else if (zret != LZMA_OK)
	    return ZREAD_ERR;

	fda->cur = fda->end - lzma->avail_in;
	assert(fda->cur == (void *) lzma->next_in);

	size_t n = size - lzma->avail_out;
	size = lzma->avail_out, buf = (char *) buf + n;
	total += n;
    } while (size);

    return total;
}

static size_t read_xz(struct zreader *z, struct fda *fda, void *buf, size_t size)
{
    assert(size + 1 > 1);

    size_t total = 0;
    lzma_stream *lzma = &z->u.lzma;

    do {
	unsigned long w;
	ssize_t ret = peeka(fda, &w, sizeof w);
	if (ret <= 0) {
	    if (ret < 0)
		return -1;
	    if (z->eos)
		return total;
	    // XZ frames permit zero padding and may somehow be combined
	    // with other kinds of frames, but when LZMA_CONCATENATED is
	    // enabled, trailing garbage is explicitly porhibited.  Thus
	    // underlying EOF must be signalled by LZMA_FINISH.
	    lzma->next_in = NULL;
	    lzma->avail_in = 0;
	    lzma->next_out = buf;
	    lzma->avail_out = size;

	    lzma_ret zret = lzma_code(lzma, LZMA_FINISH);
	    if (zret == Z_STREAM_END)
		z->eos = true;
	    else
		return ZREAD_ERR;

	    // Still may produce some data at this stage.
	    size_t n = size - lzma->avail_out;
	    return total += n;
	}

	// This is hardly possible, but what if they call again after
	// eof+eos and there is more data on the file descriptor?
	if (z->eos)
	    return ZREAD_ERR;

	lzma->next_in = (void *) fda->cur;
	lzma->avail_in = fda->end - fda->cur;
	lzma->next_out = buf;
	lzma->avail_out = size;

	lzma_ret zret = lzma_code(lzma, LZMA_RUN);
	if (zret != LZMA_OK)
	    return ZREAD_ERR;

	fda->cur = fda->end - lzma->avail_in;
	assert(fda->cur == (void *) lzma->next_in);

	size_t n = size - lzma->avail_out;
	size = lzma->avail_out, buf = (char *) buf + n;
	total += n;
    } while (size);

    return total;
}

static void fini_lzma(struct zreader *z)
{
    lzma_end(&z->u.lzma);
}

static bool init_lzma(struct zreader *z)
{
    lzma_stream *lzma = &z->u.lzma;
    *lzma = (lzma_stream) LZMA_STREAM_INIT;

    // 100M is rpm's default limit, we follow suit.
    lzma_ret zret = lzma_alone_decoder(lzma, 100<<20);
    if (zret != LZMA_OK)
	return false;

    z->read = read_lzma;
    z->fini = fini_lzma;
    return true;
}

static bool init_xz(struct zreader *z)
{
    lzma_stream *lzma = &z->u.lzma;
    *lzma = (lzma_stream) LZMA_STREAM_INIT;

    lzma_ret zret = lzma_stream_decoder(lzma, 100<<20, LZMA_CONCATENATED);
    if (zret != LZMA_OK)
	return false;

    z->read = read_xz;
    z->fini = fini_lzma;
    return true;
}

bool zreader_init(struct zreader *z, const char *zprog)
{
    z->eos = false;
    switch (*zprog) {
    case 'g':
	if (strcmp(zprog, "gzip") == 0)
	    return init_gzip(z);
	break;
    case 'l':
	if (strcmp(zprog, "lzma") == 0)
	    return init_lzma(z);
	break;
    case 'x':
	if (strcmp(zprog, "xz") == 0)
	    return init_xz(z);
	break;
    }
    errno = 0;
    return false;
}

#ifdef ZREADER_MAIN
#include <stdio.h>
#include <unistd.h>

#define PROG "zreader"
#define warn(fmt, args...) fprintf(stderr, PROG ": " fmt "\n", ##args)
#define die(fmt, args...) return warn(fmt, ##args), 2

int main(int argc, char **argv)
{
    if (argc != 2) {
usage:	fprintf(stderr, "Usage: " PROG " COMPRESSION-METHOD < COMPRESSED-INPUT\n");
	return 2;
    }
    if (isatty(0)) {
	warn("refusing to read binary data from a terminal");
	goto usage;
    }

    char fdabuf[NREADA];
    struct fda fda = { 0, fdabuf };

    struct zreader z;
    if (!zreader_init(&z, argv[1]))
	die("cannot initialize %s decoder", argv[1]);

    char buf[BUFSIZ];
    size_t size;
    while ((size = zreader_read(&z, &fda, buf, sizeof buf)) + 1 > 1)
	if (fwrite_unlocked(buf, 1, size, stdout) != size)
	    die("fwrite: %m");

    if (size + 1 == 0) {
	if (errno)
	    die("read: %m");
	else
	    die("%s decompression failed", argv[1]);
    }

    return 0;
}
#endif

// ex:set ts=8 sts=4 sw=4 noet:
