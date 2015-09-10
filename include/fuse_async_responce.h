#pragma once
#include <sys/stat.h>
#include "fuse_lowlevel.h"
#include "fuse_kernel.h"
#include "fuse_fsm.h"

struct fuse_async_responce{
    void *cmd_req;
    struct fuse_fsm *fsm;
};



void fuse_async_add_pending(struct fuse_fsm *fsm);
