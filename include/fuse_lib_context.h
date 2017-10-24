#pragma once
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "fuse.h"
#include "fuse_lowlevel.h"

struct fuse_context_i {
    struct fuse_context ctx;
    fuse_req_t req;
    uint64_t req_id;
};

extern pthread_key_t fuse_context_key;
extern pthread_mutex_t fuse_context_lock;
extern int fuse_context_ref;


struct fuse_context_i *fuse_create_context(struct fuse *f);
struct fuse_context_i *fuse_get_context_internal(void);
void fuse_freecontext(void *data);

