#pragma once
#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include "fuse_lowlevel.h"
#include "fuse_node.h"

struct lock {
    int type;
    off_t start;
    off_t end;
    pid_t pid;
    uint64_t owner;
    struct lock *next;
};

void flock_to_lock(struct flock *flock, struct lock *lock);
void lock_to_flock(struct lock *lock, struct flock *flock);
int fuse_lock_common(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, struct flock *lock, int cmd);
void insert_lock(struct lock **pos, struct lock *lock);
void delete_lock(struct lock **lockp);
struct lock *locks_conflict(struct node *node, const struct lock *lock);
int locks_insert(struct node *node, struct lock *lock);




