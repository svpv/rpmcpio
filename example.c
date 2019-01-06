/*
 * This is a minimal working example of a program that uses the rpmcpio
 * library.  The program prints four leading characters of each packaged
 * file whose size is 4+ bytes.  This file was placed in the public domain.

$ ./example perl-version-0.99.18-5.fc27.x86_64.rpm
7f  E  L  F  /usr/lib64/perl5/vendor_perl/auto/version/vxs/vxs.so
 #  !  p  e  /usr/lib64/perl5/vendor_perl/version.pm
 =  h  e  a  /usr/lib64/perl5/vendor_perl/version.pod
 p  a  c  k  /usr/lib64/perl5/vendor_perl/version/regex.pm
1f 8b 08 00  /usr/share/man/man3/version.3pm.gz
 */

#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <rpmcpio.h>

static void process(const char *rpmfname)
{
    struct rpmcpio *cpio = rpmcpio_open(AT_FDCWD, rpmfname, NULL);
    const struct cpioent *ent;
    while ((ent = rpmcpio_next(cpio))) {
	unsigned char buf[4];
	if (!(S_ISREG(ent->mode) && ent->size >= sizeof buf))
	    continue;
	rpmcpio_read(cpio, buf, sizeof buf);
	for (int i = 0; i < sizeof buf; i++)
	    printf(isprint(buf[i]) ? " %c " : "%02x ", buf[i]);
	printf(" %s\n", ent->fname);
    }
    rpmcpio_close(cpio);
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
	process(argv[i]);
    return 0;
}
