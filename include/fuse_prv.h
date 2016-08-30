#pragma once
#define FUSE_NODE_SLAB 1

#ifndef MAP_ANONYMOUS
#undef FUSE_NODE_SLAB
#endif

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE		(1 << 1)	/* Exchange source and dest */
#endif

#define FUSE_DEFAULT_INTR_SIGNAL SIGUSR1

#define FUSE_UNKNOWN_INO 0xffffffff
#define OFFSET_MAX 0x7fffffffffffffffLL

#define NODE_TABLE_MIN_SIZE 8192

#include "fuse.h"
#include "fuse_node.h"
#include "fuse_list.h"
#include "fuse_config.h"
#include "fuse_mem.h"

struct fuse {
    struct fuse_session *se;
    struct node_table name_table;
    struct node_table id_table;
    struct list_head lru_table;
    fuse_ino_t ctr;
    unsigned int generation;
    unsigned int hidectr;
    pthread_mutex_t lock;
    struct fuse_config conf;
    int intr_installed;
    struct fuse_fs *fs;
    struct lock_queue_element *lockq;
    int pagesize;
    struct list_head partial_slabs;
    struct list_head full_slabs;
    pthread_t prune_thread;
};


struct fuse_dh {
    pthread_mutex_t lock;
    struct fuse *fuse;
    fuse_req_t req;
    char *contents;
    struct fuse_direntry *first;
    struct fuse_direntry **last;
    int allocated;
    unsigned len;
    unsigned size;
    unsigned needlen;
    int filled;
    uint64_t fh;
    int error;
    fuse_ino_t nodeid;
};

struct fuse_direntry {
    struct stat stat;
    char *name;
    struct fuse_direntry *next;
};



struct node *get_node_nocheck(struct fuse *f, fuse_ino_t nodeid);
void reply_entry(fuse_req_t req, const struct fuse_entry_param *e,
                        int err);
int fuse_flush_common(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
                      const char *path, struct fuse_file_info *fi);

int fuse_do_release(fuse_req_t req,struct fuse *f, fuse_ino_t ino, const char *path,struct fuse_file_info *fi);
struct node *get_node(struct fuse *f, fuse_ino_t nodeid);
struct node *lookup_node(struct fuse *f, fuse_ino_t parent,
    const char *name);
int do_lookup(struct fuse *f, fuse_ino_t nodeid, const char *name,
struct fuse_entry_param *e);
void delete_node(struct fuse *f, struct node *node);
void unref_node(struct fuse *f, struct node *node);
void forget_node(struct fuse *f, fuse_ino_t nodeid, uint64_t nlookup);
void remove_node(struct fuse *f, fuse_ino_t dir, const char *name);
int rename_node(struct fuse *f, fuse_ino_t olddir, const char *oldname,
                fuse_ino_t newdir, const char *newname, int hide);
int exchange_node(struct fuse *f, fuse_ino_t olddir, const char *oldname,
                         fuse_ino_t newdir, const char *newname);


void update_stat(struct node *node, const struct stat *stbuf);
void set_stat(struct fuse *f, fuse_ino_t nodeid, struct stat *stbuf);
void reply_err(fuse_req_t req, int err);
int is_open(struct fuse *f, fuse_ino_t dir, const char *name);
char *hidden_name(struct fuse_fsm* fsm __attribute__((unused)), struct fuse *f, fuse_ino_t dir, const char *oldname, char *newname, size_t bufsize);
int hide_node( struct fuse_fsm* fsm __attribute__((unused)), struct fuse *f, const char *oldpath, fuse_ino_t dir, const char *oldname);

int fill_dir(void *dh_, const char *name, const struct stat *statp,
             off_t off, enum fuse_fill_dir_flags flags);
int fill_dir_plus(void *dh_, const char *name, const struct stat *statp,
                  off_t off, enum fuse_fill_dir_flags flags);
void free_direntries(struct fuse_direntry *de);
int extend_contents(struct fuse_dh *dh, unsigned minsize);
struct fuse_dh *get_dirhandle(const struct fuse_file_info *llfi,struct fuse_file_info *fi);

void curr_time(struct timespec *now);
double diff_timespec(const struct timespec *t1,
	const struct timespec *t2);
