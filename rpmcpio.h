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

#pragma once
#include <stdbool.h>

// Open the package payload to process its file data.
// The API is deliberately simplified for automated testing and the like:
// it will simply die on the first error rather than return any error code.
// If rpmfname is a relative path, dirfd must be set to its directory fd,
// or to AT_FDCWD.  The total file count, obtained from the package header,
// is returned via nent; the actual number of cpio entries can be fewer,
// because of %ghost files; the handle is created even if nent=0.
// If all=true is requested, unpackaged files, its entries restored from
// the package header, will be traversed after the regular cpio entries.
struct rpmcpio *rpmcpio_open(int dirfd, const char *rpmfname,
			     unsigned *nent, bool all) __attribute__((nonnull(2)));

// The handle can be reused for another package.  Dies on error.
void rpmcpio_reopen(struct rpmcpio *cpio, int dirfd, const char *rpmfname,
		    unsigned *nent, bool all) __attribute__((nonnull(1,3)));

void rpmcpio_close(struct rpmcpio *cpio) __attribute__((nonnull(1)));

struct cpioent {
    unsigned ino;
    unsigned mode;
    unsigned uid;
    unsigned gid;
    unsigned nlink;
    unsigned mtime;
    unsigned long long size;
    unsigned dev_major, dev_minor;
    unsigned rdev_major, rdev_minor;
    unsigned fnamelen; // strlen(fname) < PATH_MAX
    unsigned checksum;
    unsigned no; // this entry's number, no >= 0 && no < nent
    // If the entry comes from cpio, packaged is set to true.
    // Otherwise the entry is restored from the header,
    // most probably because it's a %ghost file.
    bool packaged;
    char pad[3];
    char fname[]; // PATH_MAX = 4096, including trailing '\0'
};

const struct cpioent *rpmcpio_next(struct rpmcpio *cpio);

int rpmcpio_read(struct rpmcpio *cpio, void *buf, int n);
