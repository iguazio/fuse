#pragma once
#include "fuse.h"
struct fuse_fs {
    struct fuse_operations op;
    struct fuse_module *m;
    void *user_data;
    int debug;
};

