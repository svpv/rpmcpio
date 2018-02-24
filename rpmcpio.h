struct rpmcpio *rpmcpio_open(const char *rpmfname, unsigned *nent);
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
    unsigned no; // this entry's number, no >= 0 && no < nent
    const char *rpmfname;
    const char *rpmbname;
    char pad[sizeof(void *)];
    char fname[];
};

const struct cpioent *rpmcpio_next(struct rpmcpio *cpio);

int rpmcpio_peek(struct rpmcpio *cpio, void *buf, int n);
int rpmcpio_read(struct rpmcpio *cpio, void *buf, int n);