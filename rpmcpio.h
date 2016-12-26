struct rpmcpio *rpmcpio_open(const char *rpmfname, int *nent);
void rpmcpio_close(struct rpmcpio *cpio);

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
    int no; // this entry's number, starting with 0
    char pad[4];
    char fname[];
};

const struct cpioent *rpmcpio_next(struct rpmcpio *cpio);

int rpmcpio_read(struct rpmcpio *cpio, void *buf, int n);
