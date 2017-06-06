#pragma once
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include "fuse_lowlevel.h"

struct lock_queue_element {
    struct lock_queue_element *next;
    pthread_cond_t cond;
    fuse_ino_t nodeid1;
    const char *name1;
    char **path1;
    struct node **wnode1;
    fuse_ino_t nodeid2;
    const char *name2;
    char **path2;
    struct node **wnode2;
    int err;
    bool first_locked : 1;
    bool second_locked : 1;
    bool done : 1;
};
struct fuse;
void queue_element_unlock(struct fuse *f, struct lock_queue_element *qe);
void queue_element_wakeup(struct fuse *f, struct lock_queue_element *qe);

