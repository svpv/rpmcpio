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
    union { bool rpm; } src;
    union { bool fnames; } old;
    char zprog[10];
    struct fi {
	unsigned bn;
	unsigned dn;
	unsigned short blen;
	unsigned short dlen;
	// rpmbuild uses fflags' high bits for RPMFILE_EXCLUDE etc.
	unsigned fflags : 24;
	unsigned seen : 8;
	unsigned long long size : 48;
	unsigned long long mode : 16;
    } *ff;
    // Strings point here, e.g. strlen(strtab + dn) == dlen.
    char *strtab;
};

bool header_read(struct header *h, struct fda *fda, const char **err);
void header_freedata(struct header *h);

#pragma GCC visibility pop
