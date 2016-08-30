#pragma once
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <dlfcn.h>
#include <assert.h>
#include <poll.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/file.h>
#include "fuse_lowlevel.h"

struct fuse_intr_data {
    pthread_t id;
    pthread_cond_t cond;
    int finished;
};
struct fuse;
void fuse_intr_sighandler(int sig);
void fuse_interrupt(fuse_req_t req, void *d_);
void fuse_do_prepare_interrupt(fuse_req_t req, struct fuse_intr_data *d);
void fuse_do_finish_interrupt(struct fuse *f, fuse_req_t req,struct fuse_intr_data *d);
void fuse_finish_interrupt(struct fuse *f, fuse_req_t req,struct fuse_intr_data *d);
void fuse_prepare_interrupt(struct fuse *f, fuse_req_t req,struct fuse_intr_data *d);
