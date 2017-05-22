#pragma once
#include <assert.h>
#include <stdbool.h>
#include "fuse_node.h"
#include "fuse_lowlevel.h"

#define TREELOCK_WRITE -1
#define TREELOCK_WAIT_OFFSET INT_MIN

#include "fuse_queue_element.h"
void debug_path(struct fuse *f, const char *msg, fuse_ino_t nodeid,
                const char *name, bool wr);

void queue_path(struct fuse *f, struct lock_queue_element *qe);

void dequeue_path(struct fuse *f, struct lock_queue_element *qe);

int wait_path(struct fuse *f, struct lock_queue_element *qe);

int get_path_common(struct fuse *f, fuse_ino_t nodeid, const char *name,
                    char **path, struct node **wnode);

int get_path(struct fuse *f, fuse_ino_t nodeid, char **path);

int get_path_nullok(struct fuse *f, fuse_ino_t nodeid, char **path);

int get_path_name(struct fuse *f, fuse_ino_t nodeid, const char *name,
                  char **path);

int get_path_wrlock(struct fuse *f, fuse_ino_t nodeid, const char *name,
                    char **path, struct node **wnode);

int try_get_path2(struct fuse *f, fuse_ino_t nodeid1, const char *name1,
                  fuse_ino_t nodeid2, const char *name2,
                  char **path1, char **path2,struct node **wnode1, struct node **wnode2);

int get_path2(struct fuse *f, fuse_ino_t nodeid1, const char *name1,
              fuse_ino_t nodeid2, const char *name2,
              char **path1, char **path2,struct node **wnode1, struct node **wnode2);

void wake_up_queued(struct fuse *f);

void free_path_wrlock(struct fuse *f, fuse_ino_t nodeid,struct node *wnode, char *path);

void free_path(struct fuse *f, fuse_ino_t nodeid, char *path);

void free_path2(struct fuse *f, fuse_ino_t nodeid1, fuse_ino_t nodeid2,struct node *wnode1, struct node *wnode2,char *path1, char *path2);

void unlock_path(struct fuse *f, fuse_ino_t nodeid, struct node *wnode,struct node *end);

char *add_name(char **buf, unsigned *bufsize, char *s, const char *name);

int try_get_path(struct fuse *f, fuse_ino_t nodeid, const char *name,char **path, struct node **wnodep, bool need_lock);



