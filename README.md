# rpmcpio - read RPM cpio archive

The `rpmcpio` library provides [a simple API](rpmcpio.h) for reading
the `cpio` archive of `.rpm` packages.  The [minimal example](example.c)
shows how packaged files can be iterated and looked into.
The [rpmfile2](https://github.com/svpv/rpmfile2) program servers
as a more complete example, which demonstrates, among other things,
handling of hard links.
