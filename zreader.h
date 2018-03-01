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

#include <zlib.h>
#include <lzma.h>

#pragma GCC visibility push(hidden)

struct zreader {
    union {
	z_stream strm;
	lzma_stream lzma;
    } u;
    size_t (*read)(struct zreader *z, struct fda *fda, void *buf, size_t size);
    void (*fini)(struct zreader *z);
    bool eos; // end of compressed stream
};

// Initialize the decompressor.  The compression method must be known
// in advance, and zprog set accordingly to either of the following:
// gzip, lzma, xz.  Returns false on failure.  If the decompression method
// wasn't recognized, errno is set to 0.  Otherwise, errno is most probably
// set to ENOMEM by an underlying library call.
bool zreader_init(struct zreader *z, const char *zprog);

// Free internal buffers in z->u.
void zreader_fini(struct zreader *z);

// Read as much as possible, compressed frames concatenated automatically.
// Returns the number of bytes read, 0 on EOF, (size_t) -1 on error.
// errno is set to 0 on decompression failure.  Otherwise, errno indicates
// a disk read error.
static inline size_t zreader_read(struct zreader *z, struct fda *fda,
				  void *buf, size_t size)
{
    return z->read(z, fda, buf, size);
}

#pragma GCC visibility pop
