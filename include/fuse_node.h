#pragma once
#include "fuse_list.h"
#include "fuse_config.h"
#include "fuse_lowlevel.h"

struct node_slab {
    struct list_head list;  /* must be the first member */
    struct list_head freelist;
    int used;
};

struct node {
    struct node *name_next;
    struct node *id_next;
    fuse_ino_t nodeid;
    unsigned int generation;
    int refctr;
    struct node *parent;
    char *name;
    uint64_t nlookup;
    int open_count;
    struct timespec stat_updated;
    struct timespec mtime;
    off_t size;
    struct lock *locks;
    unsigned int is_hidden : 1;
    unsigned int cache_valid : 1;
//    int treelock;
    char inline_name[32];
};

struct node_lru {
    struct node node;
    struct list_head lru;
    struct timespec forget_time;
};
struct node_table {
    struct node **array;
    size_t use;
    size_t size;
    size_t split;
};

struct fuse;
struct node_lru *node_lru(struct node *node);
size_t get_node_size(struct fuse_config *f);
struct node *alloc_node(struct fuse_config *f);
void free_node_mem(struct fuse *f, struct node *node);

