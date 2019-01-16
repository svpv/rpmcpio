// Copyright (c) 2016, 2018, 2019 Alexey Tourbin
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
#ifndef __cplusplus
#include <stddef.h>
#else
#include <cstddef>
extern "C" {
#endif

// Open the package payload to process its file data.
// The API is deliberately simplified for automated testing and the like:
// it will simply die on the first error rather than return any error code.
// If rpmfname is a relative path, dirfd must be set to its directory fd,
// or to AT_FDCWD.  The total file count, obtained from the package header,
// is returned via nent; the actual number of cpio entries can be fewer,
// because of %ghost files; the handle is created even if nent=0.
struct rpmcpio *rpmcpio_open(int dirfd, const char *rpmfname, unsigned *nent);
void rpmcpio_close(struct rpmcpio *cpio);

// Archive entries are exposed through this structure:
struct cpioent {
    // Each file in the archive is identified by its inode number.
    // Together with nlink, ino can be used to track hardlinks.
    // Hardlinked files are grouped together, and marked with the same ino
    // and the same nlink > 1.  All but the last file have size set to 0,
    // i.e. file data comes with the last file in a hardlink set.
    // Hence one simple strategy to deal with hardlinks is to skip files
    // whose size is 0.  The library performs many additional checks on
    // hardlink sets, such as that only regular files can be hardlinks,
    // and that the sets are complete.
    unsigned ino;
    unsigned short nlink;
    // File type and permissions.
    unsigned short mode;
    // Last modification time.
    unsigned mtime;
    // File flags from the rpm header, such as RPMFILE_CONFIG | RPMFILE_DOC.
    unsigned fflags;
    // File size.
    union {
	unsigned long long size;
	// For symlinks, this is also the length of the link target,
	// not including the trailing '\0'.
	unsigned long long linklen;
    };
    // Filename length: fnamelen = strlen(fname) < PATH_MAX = 4096.
    size_t fnamelen;
    // The filename of the entry, null-terminated.  Source packages have
    // basename-only filenames with no slashes in them.  Binary packages have
    // absolute pathnames which start with '/'.
    const char *fname;
};

// Iterate the archive entries, until NULL is returned.  Dies on error.
// Returns a pointer to an internal (read-only) cpioent structure.  The call
// can be proceeded with reading file data, in full or in part, or with the
// next rpmcpio_next call (the remaining data will be skipped as necessary).
const struct cpioent *rpmcpio_next(struct rpmcpio *cpio);

// Read file data.  The entry must be S_ISREG(ent->mode).  Dies on error.
// Piecemeal reads are okay, no need to read the data in one fell swoop.
size_t rpmcpio_read(struct rpmcpio *cpio, void *buf, size_t size);

// The rules for reading the target of a symbolic link.  The entry must be
// S_ISLNK(ent->mode).  The strlen of the target, without the trailing '\0',
// is ent->linklen.  The caller must provide a buffer of at least linklen + 1
// bytes, or PATH_MAX.  The string will be null-terminated, and its length
// returned.  There will be no embedded null bytes in the string.
size_t rpmcpio_readlink(struct rpmcpio *cpio, char *buf);

#ifdef __cplusplus
}
#endif
