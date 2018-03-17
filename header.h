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

#pragma GCC visibility push(hidden)

struct header {
    unsigned fileCount;
    unsigned prevFound;
    union { bool rpm; } src;
    union { bool fnames; } old;
    char zprog[14];
    // Basic info, maps fname->(mode,fflags,uid,gid) + dup detector.
    struct fi {
	unsigned bn;
	unsigned dn;
	unsigned short blen;
	unsigned short dlen;
	unsigned fflags;
	unsigned short mode;
	unsigned char uid: 4;
	unsigned char gid: 4;
	bool seen;
    } *ffi;
    // Additional info for large files / excluded cpio entries.
    struct fx {
	unsigned ino;
	unsigned mtime;
	struct {
	    unsigned long long size : 48;
	    unsigned short nlink;
	} __attribute__((packed,aligned(4)));
    } *ffx;
    // Strings point here, e.g. strlen(strtab + dn) == dlen.
    char *strtab;
};

static_assert(sizeof(struct fi) == 20, "struct fi tightly packed");
static_assert(sizeof(struct fx) == 16, "struct fx tightly packed");

bool header_read(struct header *h, struct fda *fda, const char **err);
void header_freedata(struct header *h);

// Find file info by filename.  Returns the index into ffi[], -1 if not found.
unsigned header_find(struct header *h, const char *fname, size_t flen);

#pragma GCC visibility pop
