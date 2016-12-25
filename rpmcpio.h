struct rpmcpio *rpmcpio_open(const char *rpmfname);

struct cpioent {
    unsigned ino;
    unsigned mode;
    unsigned uid;
    unsigned gid;
    unsigned nlink;
    unsigned mtime;
    unsigned size;
    unsigned dev_major, dev_minor;
    unsigned rdev_major, rdev_minor;
    unsigned fnamelen; // strlen(fname) < PATH_MAX
    unsigned checksum;
    char fname[];
};

const struct cpioent *rpmcpio_next(struct rpmcpio *cpio);

int rpmcpio_read(struct rpmcpio *cpio, void *buf, int n);
