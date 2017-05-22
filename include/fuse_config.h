#pragma once
struct fuse_config {
    unsigned int uid;
    unsigned int gid;
    unsigned int  umask;
    double entry_timeout;
    double negative_timeout;
    double attr_timeout;
    double ac_attr_timeout;
    int ac_attr_timeout_set;
    int remember;
    int nopath;
    int debug;
    int hard_remove;
    int use_ino;
    int readdir_ino;
    int set_mode;
    int set_uid;
    int set_gid;
    int direct_io;
    int kernel_cache;
    int auto_cache;
    int intr;
    int intr_signal;
    int help;
    char *modules;
};

static inline int lru_enabled(struct fuse_config *f)
{
    return f->remember > 0;
}
