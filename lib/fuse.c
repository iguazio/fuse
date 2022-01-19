/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/


/* For pthread_rwlock_t */
#define _GNU_SOURCE

#include "config.h"
#include "fuse_log.h"
#include "fuse_i.h"
#include "fuse_lowlevel.h"
#include "fuse_opt.h"
#include "fuse_misc.h"
#include "fuse_kernel.h"
#include "fuse_async_response.h"
#include "fuse_fsm.h"
#include "fuse_fs.h"
#include "fuse_prv.h"
#include "fuse_path.h"
#include "fuse_queue_element.h"
#include "fuse_module.h"
#include "fuse_interrupt.h"
#include "fuse_lib_context.h"
#include "fuse_id_hash.h"
#include "fuse_req.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
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
#include <stdarg.h>



struct node *get_node_nocheck(struct fuse *f, fuse_ino_t nodeid)
{
    size_t hash = id_hash(f, nodeid);
    struct node *node;

    for (node = f->id_table.array[hash]; node != NULL; node = node->id_next)
        if (node->nodeid == nodeid)
            return node;

    return NULL;
}

struct node *get_node(struct fuse *f, fuse_ino_t nodeid)
{
    struct node *node = get_node_nocheck(f, nodeid);
    if (!node) {
        fuse_log_err( "fuse internal error: node %llu not found\n",
            (unsigned long long) nodeid);
        abort();
    }
    return node;
}



static void remove_node_lru(struct node *node)
{
	struct node_lru *lnode = node_lru(node);
	list_del(&lnode->lru);
	init_list_head(&lnode->lru);
}

static void set_forget_time(struct fuse *f, struct node *node)
{
	struct node_lru *lnode = node_lru(node);

	list_del(&lnode->lru);
	list_add_tail(&lnode->lru, &f->lru_table);
	curr_time(&lnode->forget_time);
}

static void free_node(struct fuse *f, struct node *node)
{
	if (node->name != node->inline_name)
		fuse_free(node->name);
	free_node_mem(f, node);
}

static void node_table_reduce(struct node_table *t)
{
	size_t newsize = t->size / 2;
	void *newarray;

	if (newsize < NODE_TABLE_MIN_SIZE)
		return;

	newarray = fuse_realloc(t->array, sizeof(struct node *) * newsize);
	if (newarray != NULL)
		t->array = newarray;

	t->size = newsize;
	t->split = t->size / 2;
}

static void remerge_id(struct fuse *f)
{
	struct node_table *t = &f->id_table;
	int iter;

	if (t->split == 0)
		node_table_reduce(t);

	for (iter = 8; t->split > 0 && iter; iter--) {
		struct node **upper;

		t->split--;
		upper = &t->array[t->split + t->size / 2];
		if (*upper) {
			struct node **nodep;

			for (nodep = &t->array[t->split]; *nodep;
			     nodep = &(*nodep)->id_next);

			*nodep = *upper;
			*upper = NULL;
			break;
		}
	}
}

static void unhash_id(struct fuse *f, struct node *node)
{
	struct node **nodep = &f->id_table.array[id_hash(f, node->nodeid)];

	for (; *nodep != NULL; nodep = &(*nodep)->id_next)
		if (*nodep == node) {
			*nodep = node->id_next;
			f->id_table.use--;

			if(f->id_table.use < f->id_table.size / 4)
				remerge_id(f);
			return;
		}
}

static int node_table_resize(struct node_table *t)
{
	size_t newsize = t->size * 2;
	void *newarray;

	newarray = fuse_realloc(t->array, sizeof(struct node *) * newsize);
	if (newarray == NULL)
		return -1;

	t->array = newarray;
	memset(t->array + t->size, 0, t->size * sizeof(struct node *));
	t->size = newsize;
	t->split = 0;

	return 0;
}

static void rehash_id(struct fuse *f)
{
	struct node_table *t = &f->id_table;
	struct node **nodep;
	struct node **next;
	size_t hash;

	if (t->split == t->size / 2)
		return;

	hash = t->split;
	t->split++;
	for (nodep = &t->array[hash]; *nodep != NULL; nodep = next) {
		struct node *node = *nodep;
		size_t newhash = id_hash(f, node->nodeid);

		if (newhash != hash) {
			next = nodep;
			*nodep = node->id_next;
			node->id_next = t->array[newhash];
			t->array[newhash] = node;
		} else {
			next = &node->id_next;
		}
	}
	if (t->split == t->size / 2)
		node_table_resize(t);
}

static void hash_id(struct fuse *f, struct node *node)
{
	size_t hash = id_hash(f, node->nodeid);
	node->id_next = f->id_table.array[hash];
	f->id_table.array[hash] = node;
	f->id_table.use++;

	if (f->id_table.use >= f->id_table.size / 2)
		rehash_id(f);
}

static size_t name_hash(struct fuse *f, fuse_ino_t parent,
			const char *name)
{
	uint64_t hash = parent;
	uint64_t oldhash;

	for (; *name; name++)
		hash = hash * 31 + (unsigned char) *name;

	hash %= f->name_table.size;
	oldhash = hash % (f->name_table.size / 2);
	if (oldhash >= f->name_table.split)
		return oldhash;
	else
		return hash;
}


static void remerge_name(struct fuse *f)
{
	struct node_table *t = &f->name_table;
	int iter;

	if (t->split == 0)
		node_table_reduce(t);

	for (iter = 8; t->split > 0 && iter; iter--) {
		struct node **upper;

		t->split--;
		upper = &t->array[t->split + t->size / 2];
		if (*upper) {
			struct node **nodep;

			for (nodep = &t->array[t->split]; *nodep;
			     nodep = &(*nodep)->name_next);

			*nodep = *upper;
			*upper = NULL;
			break;
		}
	}
}

static void unhash_name(struct fuse *f, struct node *node)
{
	if (node->name) {
		size_t hash = name_hash(f, node->parent->nodeid, node->name);
		struct node **nodep = &f->name_table.array[hash];

		for (; *nodep != NULL; nodep = &(*nodep)->name_next)
			if (*nodep == node) {
				*nodep = node->name_next;
				node->name_next = NULL;
				unref_node(f, node->parent);
				if (node->name != node->inline_name)
					fuse_free(node->name);
				node->name = NULL;
				node->parent = NULL;
				f->name_table.use--;

				if (f->name_table.use < f->name_table.size / 4)
					remerge_name(f);
				return;
			}
		fuse_log_err(
			"fuse internal error: unable to unhash node: %llu\n",
			(unsigned long long) node->nodeid);
		abort();
	}
}

static void rehash_name(struct fuse *f)
{
	struct node_table *t = &f->name_table;
	struct node **nodep;
	struct node **next;
	size_t hash;

	if (t->split == t->size / 2)
		return;

	hash = t->split;
	t->split++;
	for (nodep = &t->array[hash]; *nodep != NULL; nodep = next) {
		struct node *node = *nodep;
		size_t newhash = name_hash(f, node->parent->nodeid, node->name);

		if (newhash != hash) {
			next = nodep;
			*nodep = node->name_next;
			node->name_next = t->array[newhash];
			t->array[newhash] = node;
		} else {
			next = &node->name_next;
		}
	}
	if (t->split == t->size / 2)
		node_table_resize(t);
}

static int hash_name(struct fuse *f, struct node *node, fuse_ino_t parentid,
		     const char *name)
{
	size_t hash = name_hash(f, parentid, name);
	struct node *parent = get_node(f, parentid);
	if (strlen(name) < sizeof(node->inline_name)) {
		strcpy(node->inline_name, name);
		node->name = node->inline_name;
	} else {
		node->name = fuse_strdup(name);
		if (node->name == NULL)
			return -1;
	}

	parent->refctr ++;
	node->parent = parent;
	node->name_next = f->name_table.array[hash];
	f->name_table.array[hash] = node;
	f->name_table.use++;

	if (f->name_table.use >= f->name_table.size / 2)
		rehash_name(f);

	return 0;
}

void delete_node(struct fuse *f, struct node *node)
{
	if (f->conf.debug)
        fuse_log_debug( "DELETE: %llu\n",
			(unsigned long long) node->nodeid);

//	assert(node->treelock == 0);
	unhash_name(f, node);
	if (lru_enabled(&f->conf))
		remove_node_lru(node);
	unhash_id(f, node);
	free_node(f, node);
}

void unref_node(struct fuse *f, struct node *node)
{
	assert(node->refctr > 0);
	node->refctr --;
	if (!node->refctr)
		delete_node(f, node);
}

static fuse_ino_t next_id(struct fuse *f)
{
	do {
		f->ctr = (f->ctr + 1) & 0xffffffff;
		if (!f->ctr)
			f->generation ++;
	} while (f->ctr == 0 || f->ctr == FUSE_UNKNOWN_INO ||
		 get_node_nocheck(f, f->ctr) != NULL);
	return f->ctr;
}

struct node *lookup_node(struct fuse *f, fuse_ino_t parent,
				const char *name)
{
	size_t hash = name_hash(f, parent, name);
	struct node *node;

	for (node = f->name_table.array[hash]; node != NULL; node = node->name_next)
		if (node->parent->nodeid == parent &&
		    strcmp(node->name, name) == 0)
			return node;

	return NULL;
}

static void inc_nlookup(struct node *node)
{
	if (!node->nlookup)
		node->refctr++;
	node->nlookup++;
}
static struct node *find_node(struct fuse *f, fuse_ino_t parent,
			      const char *name)
{
	struct node *node;

	if (!name)
		node = get_node(f, parent);
	else
		node = lookup_node(f, parent, name);
	if (node == NULL) {
		node = alloc_node(&f->conf);
		if (node == NULL)
			goto out_err;

		node->nodeid = next_id(f);
		node->generation = f->generation;
		if (f->conf.remember)
			inc_nlookup(node);

		if (hash_name(f, node, parent, name) == -1) {
			free_node(f, node);
			node = NULL;
			goto out_err;
		}
		hash_id(f, node);
		if (lru_enabled(&f->conf)) {
			struct node_lru *lnode = node_lru(node);
			init_list_head(&lnode->lru);
		}
	} else if (lru_enabled(&f->conf) && node->nlookup == 1) {
		remove_node_lru(node);
	}
	inc_nlookup(node);
out_err:
	pthread_mutex_unlock(&f->lock);
	return node;
}




void forget_node(struct fuse *f, fuse_ino_t nodeid, uint64_t nlookup)
{
	struct node *node;
	if (nodeid == FUSE_ROOT_ID)
		return;
	pthread_mutex_lock(&f->lock);
	node = get_node(f, nodeid);

	/*
	 * Node may still be locked due to interrupt idiocy in open,
	 * create and opendir
	 */
// 	while (node->nlookup == nlookup && node->treelock) {
// 		struct lock_queue_element qe = {
// 			.nodeid1 = nodeid,
// 		};
// 
// 		debug_path(f, "QUEUE PATH (forget)", nodeid, NULL, false);
// 		queue_path(f, &qe);
// 
// 		do {
// 			pthread_cond_wait(&qe.cond, &f->lock);
// 		} while (node->nlookup == nlookup && node->treelock);
// 
// 		dequeue_path(f, &qe);
// 		debug_path(f, "DEQUEUE_PATH (forget)", nodeid, NULL, false);
// 	}

	assert(node->nlookup >= nlookup);
	node->nlookup -= nlookup;
	if (!node->nlookup) {
		unref_node(f, node);
	} else if (lru_enabled(&f->conf) && node->nlookup == 1) {
		set_forget_time(f, node);
	}
	pthread_mutex_unlock(&f->lock);
}

static void unlink_node(struct fuse *f, struct node *node)
{
	if (f->conf.remember) {
		assert(node->nlookup > 1);
		node->nlookup--;
	}
	unhash_name(f, node);
}

void remove_node(struct fuse *f, fuse_ino_t dir, const char *name)
{
	struct node *node;

	pthread_mutex_lock(&f->lock);
	node = lookup_node(f, dir, name);
	if (node != NULL)
		unlink_node(f, node);
	pthread_mutex_unlock(&f->lock);
}


static size_t str_format_ok(char *dest, const size_t max_len, const char *format, ...)
{
    va_list ar;
    int32_t count;

    va_start(ar, format);
    count = vsnprintf(dest, max_len, format, ar);
    va_end(ar);
    if ((count < 0) || (count >= (int)max_len)) {
        dest[max_len - 1] = 0;
        return max_len;
    }
    return (size_t)count;
}

size_t sprintf_node_trace(struct node *node, char *buf, int buf_len) {
    if (!node)
        return str_format_ok(buf, buf_len, "nul");
    return str_format_ok(buf, buf_len, "%s %d(%p->%p)->", node->name, node->nodeid, node, node->parent);
}




static char rename_node_trace[5][4096];
void print_rename_trace() {
    for (int i = 0; i < 5; i++) {
        fuse_log_err("rename trace %d - %s\n", i, rename_node_trace[i]);
    }
}
int rename_node(struct fuse *f, fuse_ino_t olddir, const char *oldname,
		       fuse_ino_t newdir, const char *newname, int hide)
{
	struct node *node;
	struct node *newnode;
	int err = 0;
    int depth;

	pthread_mutex_lock(&f->lock);
	node  = lookup_node(f, olddir, oldname);
	newnode	 = lookup_node(f, newdir, newname);

    sprintf_node_parent_trace(rename_node_trace[0], node, depth);
    sprintf_node_parent_trace(rename_node_trace[1], newnode, depth);

    if (node == NULL)
        goto out;

	if (newnode != NULL) {
		if (hide) {
            fuse_log_debug( "fuse: hidden file got created during hiding\n");
			err = -EBUSY;
			goto out;
		}
		unlink_node(f, newnode);
        sprintf_node_parent_trace(rename_node_trace[2], newnode, depth);
    }

	unhash_name(f, node);
    sprintf_node_parent_trace(rename_node_trace[3], newnode, depth);

	if (hash_name(f, node, newdir, newname) == -1) {
		err = -ENOMEM;
		goto out;
	}

    sprintf_node_parent_trace(rename_node_trace[4], newnode, depth);

	if (hide)
		node->is_hidden = 1;

out:
	pthread_mutex_unlock(&f->lock);
	return err;
}

int exchange_node(struct fuse *f, fuse_ino_t olddir, const char *oldname,
			 fuse_ino_t newdir, const char *newname)
{
	struct node *oldnode;
	struct node *newnode;
	int err;

	pthread_mutex_lock(&f->lock);
	oldnode  = lookup_node(f, olddir, oldname);
	newnode	 = lookup_node(f, newdir, newname);

	if (oldnode)
		unhash_name(f, oldnode);
	if (newnode)
		unhash_name(f, newnode);

	err = -ENOMEM;
	if (oldnode) {
		if (hash_name(f, oldnode, newdir, newname) == -1)
			goto out;
	}
	if (newnode) {
		if (hash_name(f, newnode, olddir, oldname) == -1)
			goto out;
	}
	err = 0;
out:
	pthread_mutex_unlock(&f->lock);
	return err;
}

void set_stat(struct fuse *f, fuse_ino_t nodeid, struct stat *stbuf)
{
	if (!f->conf.use_ino)
		stbuf->st_ino = nodeid;
	if (f->conf.set_mode)
		stbuf->st_mode = (stbuf->st_mode & S_IFMT) |
				 (0777 & ~f->conf.umask);
	if (f->conf.set_uid)
		stbuf->st_uid = f->conf.uid;
	if (f->conf.set_gid)
		stbuf->st_gid = f->conf.gid;
}





int is_open(struct fuse *f, fuse_ino_t dir, const char *name)
{
	struct node *node;
	int isopen = 0;
	pthread_mutex_lock(&f->lock);
	node = lookup_node(f, dir, name);
	if (node && node->open_count > 0)
		isopen = 1;
	pthread_mutex_unlock(&f->lock);
	return isopen;
}

static int mtime_eq(const struct stat *stbuf, const struct timespec *ts)
{
	return stbuf->st_mtime == ts->tv_sec &&
		ST_MTIM_NSEC(stbuf) == ts->tv_nsec;
}

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC CLOCK_REALTIME
#endif

void curr_time(struct timespec *now)
{
	static clockid_t clockid = CLOCK_MONOTONIC;
	int res = clock_gettime(clockid, now);
	if (res == -1 && errno == EINVAL) {
		clockid = CLOCK_REALTIME;
		res = clock_gettime(clockid, now);
	}
	if (res == -1) {
		perror("fuse: clock_gettime");
		abort();
	}
}

void update_stat(struct node *node, const struct stat *stbuf)
{
	if (node->cache_valid && (!mtime_eq(stbuf, &node->mtime) ||
				  stbuf->st_size != node->size))
		node->cache_valid = 0;
	node->mtime.tv_sec = stbuf->st_mtime;
	node->mtime.tv_nsec = ST_MTIM_NSEC(stbuf);
	node->size = stbuf->st_size;
	curr_time(&node->stat_updated);
}

int do_lookup(struct fuse *f, fuse_ino_t nodeid, const char *name,
		     struct fuse_entry_param *e)
{
	struct node *node;

	pthread_mutex_lock(&f->lock);
	node = find_node(f, nodeid, name);
	if (node == NULL)
		return -ENOMEM;

	e->ino = node->nodeid;
	e->generation = node->generation;
	e->entry_timeout = f->conf.entry_timeout;
	e->attr_timeout = f->conf.attr_timeout;
	if (f->conf.auto_cache) {
		pthread_mutex_lock(&f->lock);
		update_stat(node, &e->attr);
		pthread_mutex_unlock(&f->lock);
	}
	set_stat(f, e->ino, &e->attr);
	return 0;
}
void reply_err(fuse_req_t req, int err)
{
	/* fuse_reply_err() uses non-negated errno values */
	fuse_reply_err(req, -err);
}

void reply_entry(fuse_req_t req, const struct fuse_entry_param *e,
			int err)
{
	if (!err) {
		struct fuse *f = req_fuse(req);
		if (fuse_reply_entry(req, e) == -ENOENT) {
			/* Skip forget for negative result */
			if  (e->ino != 0)
				forget_node(f, e->ino, 1);
		}
	} else
		reply_err(req, err);
}



double diff_timespec(const struct timespec *t1,
			    const struct timespec *t2)
{
	return (t1->tv_sec - t2->tv_sec) +
		((double) t1->tv_nsec - (double) t2->tv_nsec) / 1000000000.0;
}


int extend_contents(struct fuse_dh *dh, unsigned minsize)
{
	if (minsize > dh->size) {
		char *newptr;
		unsigned newsize = dh->size;
		if (!newsize)
			newsize = 1024;
		while (newsize < minsize) {
			if (newsize >= 0x80000000)
				newsize = 0xffffffff;
			else
				newsize *= 2;
		}

		newptr = (char *) fuse_realloc(dh->contents, newsize);
		if (!newptr) {
			dh->error = -ENOMEM;
			return -1;
		}
		dh->contents = newptr;
		dh->size = newsize;
	}
	return 0;
}

static int fuse_add_direntry_to_dh(struct fuse_dh *dh, const char *name,
				   struct stat *st)
{
	struct fuse_direntry *de;

	de = fuse_malloc(sizeof(struct fuse_direntry));
	if (!de) {
		dh->error = -ENOMEM;
		return -1;
	}
	de->name = fuse_strdup(name);
	if (!de->name) {
		dh->error = -ENOMEM;
		fuse_free(de);
		return -1;
	}
	de->stat = *st;
	de->next = NULL;

	*dh->last = de;
	dh->last = &de->next;

	return 0;
}

static fuse_ino_t lookup_nodeid(struct fuse *f, fuse_ino_t parent,
				const char *name)
{
	struct node *node;
	fuse_ino_t res = FUSE_UNKNOWN_INO;

	pthread_mutex_lock(&f->lock);
	node = lookup_node(f, parent, name);
	if (node)
		res = node->nodeid;
	pthread_mutex_unlock(&f->lock);

	return res;
}

int fill_dir(void *dh_, const char *name, const struct stat *statp,
		    off_t off, enum fuse_fill_dir_flags flags)
{
	struct fuse_dh *dh = (struct fuse_dh *) dh_;
	struct stat stbuf;

	if ((flags & ~FUSE_FILL_DIR_PLUS) != 0) {
		dh->error = -EIO;
		return 1;
	}

	if (statp)
		stbuf = *statp;
	else {
		memset(&stbuf, 0, sizeof(stbuf));
		stbuf.st_ino = FUSE_UNKNOWN_INO;
	}

	if (!dh->fuse->conf.use_ino) {
		stbuf.st_ino = FUSE_UNKNOWN_INO;
		if (dh->fuse->conf.readdir_ino) {
			stbuf.st_ino = (ino_t)
				lookup_nodeid(dh->fuse, dh->nodeid, name);
		}
	}

	if (off) {
		size_t newlen;

		if (dh->first) {
			dh->error = -EIO;
			return 1;
		}

		if (extend_contents(dh, dh->needlen) == -1)
			return 1;

		dh->filled = 0;
		newlen = dh->len +
			fuse_add_direntry(dh->req, dh->contents + dh->len,
					  dh->needlen - dh->len, name,
					  &stbuf, off);
		if (newlen > dh->needlen)
			return 1;

		dh->len = newlen;
	} else {
		if (!dh->filled) {
			dh->error = -EIO;
			return 1;
		}
		if (fuse_add_direntry_to_dh(dh, name, &stbuf) == -1)
			return 1;
	}
	return 0;
}

static int is_dot_or_dotdot(const char *name)
{
	return name[0] == '.' && (name[1] == '\0' ||
				  (name[1] == '.' && name[2] == '\0'));
}

int fill_dir_plus(void *dh_, const char *name, const struct stat *statp,
			 off_t off, enum fuse_fill_dir_flags flags)
{
	struct fuse_dh *dh = (struct fuse_dh *) dh_;
	struct fuse_entry_param e = {
		/* ino=0 tells the kernel to ignore readdirplus stat info */
		.ino = 0,
	};
	struct fuse *f = dh->fuse;
	int res;

	if ((flags & ~FUSE_FILL_DIR_PLUS) != 0) {
		dh->error = -EIO;
		return 1;
	}

	if (off && statp && (flags & FUSE_FILL_DIR_PLUS)) {
		e.attr = *statp;

		if (!is_dot_or_dotdot(name)) {
			res = do_lookup(f, dh->nodeid, name, &e);
			if (res) {
				dh->error = res;
				return 1;
			}
		}
	} else {
		e.attr.st_ino = FUSE_UNKNOWN_INO;
		if (!f->conf.use_ino && f->conf.readdir_ino) {
			e.attr.st_ino = (ino_t)
				lookup_nodeid(f, dh->nodeid, name);
		}
	}

	if (off) {
		size_t newlen;

		if (dh->first) {
			dh->error = -EIO;
			return 1;
		}
		if (extend_contents(dh, dh->needlen) == -1)
			return 1;

		dh->filled = 0;
		newlen = dh->len +
			fuse_add_direntry_plus(dh->req, dh->contents + dh->len,
					       dh->needlen - dh->len, name,
					       &e, off);
		if (newlen > dh->needlen)
			return 1;
		dh->len = newlen;
	} else {
		if (!dh->filled) {
			dh->error = -EIO;
			return 1;
		}
		if (fuse_add_direntry_to_dh(dh, name, &e.attr) == -1)
			return 1;
	}

	return 0;
}

void free_direntries(struct fuse_direntry *de)
{
	while (de) {
		struct fuse_direntry *next = de->next;
		fuse_free(de->name);
		fuse_free(de);
		de = next;
	}
}




static int clean_delay(struct fuse *f)
{
	/*
	 * This is calculating the delay between clean runs.  To
	 * reduce the number of cleans we are doing them 10 times
	 * within the remember window.
	 */
	int min_sleep = 60;
	int max_sleep = 3600;
	int sleep_time = f->conf.remember / 10;

	if (sleep_time > max_sleep)
		return max_sleep;
	if (sleep_time < min_sleep)
		return min_sleep;
	return sleep_time;
}

int fuse_clean_cache(struct fuse *f)
{
	struct node_lru *lnode;
	struct list_head *curr, *next;
	struct node *node;
	struct timespec now;

	pthread_mutex_lock(&f->lock);

	curr_time(&now);

	for (curr = f->lru_table.next; curr != &f->lru_table; curr = next) {
		double age;

		next = curr->next;
		lnode = list_entry(curr, struct node_lru, lru);
		node = &lnode->node;

		age = diff_timespec(&now, &lnode->forget_time);
		if (age <= f->conf.remember)
			break;

		assert(node->nlookup == 1);

		/* Don't forget active directories */
		if (node->refctr > 1)
			continue;

		node->nlookup = 0;
		unhash_name(f, node);
		unref_node(f, node);
	}
	pthread_mutex_unlock(&f->lock);

	return clean_delay(f);
}

extern struct fuse_lowlevel_ops fuse_path_ops;

int fuse_notify_poll(struct fuse_pollhandle *ph)
{
	return fuse_lowlevel_notify_poll(ph);
}

struct fuse_session *fuse_get_session(struct fuse *f)
{
	return f->se;
}

static int fuse_session_loop_remember(struct fuse *f)
{
	struct fuse_session *se = f->se;
	int res = 0;
	struct timespec now;
	time_t next_clean;
	struct fuse_chan *ch = fuse_session_chan(se);
	struct pollfd fds = {
		.fd = fuse_chan_fd(ch),
		.events = POLLIN
	};
	struct fuse_buf fbuf = {
		.mem = NULL,
	};

	curr_time(&now);
	next_clean = now.tv_sec;
	while (!fuse_session_exited(se)) {
		unsigned timeout;

		curr_time(&now);
		if (now.tv_sec < next_clean)
			timeout = next_clean - now.tv_sec;
		else
			timeout = 0;

		res = poll(&fds, 1, timeout * 1000);
		if (res == -1) {
			if (errno == -EINTR)
				continue;
			else
				break;
		} else if (res > 0) {
			res = fuse_session_receive_buf(se, &fbuf, ch);

			if (res == -EINTR)
				continue;
			if (res <= 0)
				break;

			fuse_session_process_buf(se, &fbuf, ch);
		} else {
			timeout = fuse_clean_cache(f);
			curr_time(&now);
			next_clean = now.tv_sec + timeout;
		}
	}

	fuse_free(fbuf.mem);
	fuse_session_reset(se);
	return res < 0 ? -1 : 0;
}

int fuse_loop(struct fuse *f)
{
	if (!f)
		return -1;

	if (lru_enabled(&f->conf))
		return fuse_session_loop_remember(f);

	return fuse_session_loop(f->se);
}

int fuse_loop_async(struct fuse *f, int fd, fuse_async_get_msg_t callback_on_new_msg, void* callback_payload)
{
    if (!f)
        return -1;

    if (lru_enabled(&f->conf))
        return fuse_session_loop_remember(f);

    return fuse_session_loop_async(f->se, fd, callback_on_new_msg, callback_payload);
}

void fuse_exit(struct fuse *f)
{
	fuse_session_exit(f->se);
}

struct fuse_context *fuse_get_context(void)
{
	struct fuse_context_i *c = fuse_get_context_internal();

	if (c)
		return &c->ctx;
	else
		return NULL;
}

int fuse_getgroups(int size, gid_t list[])
{
	struct fuse_context_i *c = fuse_get_context_internal();
	if (!c)
		return -EINVAL;

	return fuse_req_getgroups(c->req, size, list);
}

int fuse_interrupted(void)
{
	struct fuse_context_i *c = fuse_get_context_internal();

	if (c)
		return fuse_req_interrupted(c->req);
	else
		return 0;
}
/*Used for tracing request*/
static uint64_t current_req_uniqueid_context = 0;
uint64_t fuse_current_context_uniqueid(void)
{
    return current_req_uniqueid_context;
}

void fuse_set_current_context_uniqueid(uint64_t  id)
{
    current_req_uniqueid_context = id;
}

enum {
	KEY_HELP,
};

#define FUSE_LIB_OPT(t, p, v) { t, offsetof(struct fuse_config, p), v }

static const struct fuse_opt fuse_lib_opts[] = {
	FUSE_OPT_KEY("-h",		      KEY_HELP),
	FUSE_OPT_KEY("--help",		      KEY_HELP),
	FUSE_OPT_KEY("debug",		      FUSE_OPT_KEY_KEEP),
	FUSE_OPT_KEY("-d",		      FUSE_OPT_KEY_KEEP),
	FUSE_LIB_OPT("debug",		      debug, 1),
	FUSE_LIB_OPT("-d",		      debug, 1),
	FUSE_LIB_OPT("hard_remove",	      hard_remove, 1),
	FUSE_LIB_OPT("use_ino",		      use_ino, 1),
	FUSE_LIB_OPT("readdir_ino",	      readdir_ino, 1),
	FUSE_LIB_OPT("direct_io",	      direct_io, 1),
	FUSE_LIB_OPT("kernel_cache",	      kernel_cache, 1),
	FUSE_LIB_OPT("auto_cache",	      auto_cache, 1),
	FUSE_LIB_OPT("noauto_cache",	      auto_cache, 0),
	FUSE_LIB_OPT("umask=",		      set_mode, 1),
	FUSE_LIB_OPT("umask=%o",	      umask, 0),
	FUSE_LIB_OPT("uid=",		      set_uid, 1),
	FUSE_LIB_OPT("uid=%d",		      uid, 0),
	FUSE_LIB_OPT("gid=",		      set_gid, 1),
	FUSE_LIB_OPT("gid=%d",		      gid, 0),
	FUSE_LIB_OPT("entry_timeout=%lf",     entry_timeout, 0),
	FUSE_LIB_OPT("attr_timeout=%lf",      attr_timeout, 0),
	FUSE_LIB_OPT("ac_attr_timeout=%lf",   ac_attr_timeout, 0),
	FUSE_LIB_OPT("ac_attr_timeout=",      ac_attr_timeout_set, 1),
	FUSE_LIB_OPT("negative_timeout=%lf",  negative_timeout, 0),
	FUSE_LIB_OPT("noforget",              remember, -1),
	FUSE_LIB_OPT("remember=%u",           remember, 0),
	FUSE_LIB_OPT("nopath",                nopath, 1),
	FUSE_LIB_OPT("intr",		      intr, 1),
	FUSE_LIB_OPT("intr_signal=%d",	      intr_signal, 0),
	FUSE_LIB_OPT("modules=%s",	      modules, 0),
	FUSE_OPT_END
};

static void fuse_lib_help(void)
{
    fuse_log_err(
"    -o hard_remove         immediate removal (don't hide files)\n"
"    -o use_ino             let filesystem set inode numbers\n"
"    -o readdir_ino         try to fill in d_ino in readdir\n"
"    -o direct_io           use direct I/O\n"
"    -o kernel_cache        cache files in kernel\n"
"    -o [no]auto_cache      enable caching based on modification times (off)\n"
"    -o umask=M             set file permissions (octal)\n"
"    -o uid=N               set file owner\n"
"    -o gid=N               set file group\n"
"    -o entry_timeout=T     cache timeout for names (1.0s)\n"
"    -o negative_timeout=T  cache timeout for deleted names (0.0s)\n"
"    -o attr_timeout=T      cache timeout for attributes (1.0s)\n"
"    -o ac_attr_timeout=T   auto cache timeout for attributes (attr_timeout)\n"
"    -o noforget            never forget cached inodes\n"
"    -o remember=T          remember cached inodes for T seconds (0s)\n"
"    -o nopath              don't supply path if not necessary\n"
"    -o intr                allow requests to be interrupted\n"
"    -o intr_signal=NUM     signal to send on interrupt (%i)\n"
"    -o modules=M1[:M2...]  names of modules to push onto filesystem stack\n"
"\n", FUSE_DEFAULT_INTR_SIGNAL);
}

static void fuse_lib_help_modules(void)
{
	struct fuse_module *m;
    fuse_log_err("\nModule options:\n");
	pthread_mutex_lock(&fuse_context_lock);
	for (m = fuse_modules; m; m = m->next) {
		struct fuse_fs *fs = NULL;
		struct fuse_fs *newfs;
		struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
		if (fuse_opt_add_arg(&args, "") != -1 &&
		    fuse_opt_add_arg(&args, "-h") != -1) {
            fuse_log_err("\n[%s]\n", m->name);
			newfs = m->factory(&args, &fs);
			assert(newfs == NULL);
		}
		fuse_opt_free_args(&args);
	}
	pthread_mutex_unlock(&fuse_context_lock);
}

static int fuse_lib_opt_proc(void *data, const char *arg, int key,
			     struct fuse_args *outargs)
{
	(void) arg; (void) outargs;

	if (key == KEY_HELP) {
		struct fuse_config *conf = (struct fuse_config *) data;
		fuse_lib_help();
		conf->help = 1;
	}

	return 1;
}

static int fuse_init_intr_signal(int signum, int *installed)
{
	struct sigaction old_sa;

	if (sigaction(signum, NULL, &old_sa) == -1) {
		perror("fuse: cannot get old signal handler");
		return -1;
	}

	if (old_sa.sa_handler == SIG_DFL) {
		struct sigaction sa;

		memset(&sa, 0, sizeof(struct sigaction));
		sa.sa_handler = fuse_intr_sighandler;
		sigemptyset(&sa.sa_mask);

		if (sigaction(signum, &sa, NULL) == -1) {
			perror("fuse: cannot set interrupt signal handler");
			return -1;
		}
		*installed = 1;
	}
	return 0;
}

static void fuse_restore_intr_signal(int signum)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = SIG_DFL;
	sigaction(signum, &sa, NULL);
}


static int fuse_push_module(struct fuse *f, const char *module,
			    struct fuse_args *args)
{
	struct fuse_fs *fs[2] = { f->fs, NULL };
	struct fuse_fs *newfs;
	struct fuse_module *m = fuse_get_module(module);

	if (!m)
		return -1;

	newfs = m->factory(args, fs);
	if (!newfs) {
		fuse_put_module(m);
		return -1;
	}
	newfs->m = m;
	f->fs = newfs;
	f->conf.nopath = newfs->op.flag_nopath && f->conf.nopath;
	return 0;
}

struct fuse_fs *fuse_fs_new(const struct fuse_operations *op, size_t op_size,
			    void *user_data)
{
	struct fuse_fs *fs;

	if (sizeof(struct fuse_operations) < op_size) {
		fuse_log_err( "fuse: warning: library too old, some operations may not not work\n");
		op_size = sizeof(struct fuse_operations);
	}

	fs = (struct fuse_fs *) fuse_calloc(1, sizeof(struct fuse_fs));
	if (!fs) {
		fuse_log_err( "fuse: failed to allocate fuse_fs object\n");
		return NULL;
	}

	fs->user_data = user_data;
	if (op)
		memcpy(&fs->op, op, op_size);
	return fs;
}

static int node_table_init(struct node_table *t)
{
	t->size = NODE_TABLE_MIN_SIZE;
	t->array = (struct node **) fuse_calloc(1, sizeof(struct node *) * t->size);
	if (t->array == NULL) {
		fuse_log_err( "fuse: memory allocation failed\n");
		return -1;
	}
	t->use = 0;
	t->split = 0;

	return 0;
}

static void *fuse_prune_nodes(void *fuse)
{
	struct fuse *f = fuse;
	int sleep_time;

	while(1) {
		sleep_time = fuse_clean_cache(f);
		sleep(sleep_time);
	}
	return NULL;
}

int fuse_start_cleanup_thread(struct fuse *f)
{
	if (lru_enabled(&f->conf))
		return fuse_start_thread(&f->prune_thread, fuse_prune_nodes, f);

	return 0;
}

void fuse_stop_cleanup_thread(struct fuse *f)
{
	if (lru_enabled(&f->conf)) {
		pthread_mutex_lock(&f->lock);
		pthread_cancel(f->prune_thread);
		pthread_mutex_unlock(&f->lock);
		pthread_join(f->prune_thread, NULL);
	}
}

struct fuse *fuse_new(struct fuse_chan *ch, struct fuse_args *args,
		      const struct fuse_operations *op,
		      size_t op_size, void *user_data)
{
	struct fuse *f;
	struct node *root;
	struct fuse_fs *fs;
	struct fuse_lowlevel_ops llop = fuse_path_ops;

	pthread_mutex_lock(&fuse_context_lock);
	static int builtin_modules_registered = 0;
	/* Have the builtin modules already been registered? */
	if (builtin_modules_registered == 0) {
		/* If not, register them. */
		fuse_register_module("subdir", fuse_module_subdir_factory, NULL);
		fuse_register_module("iconv", fuse_module_iconv_factory, NULL);
		builtin_modules_registered= 1;
	}
	pthread_mutex_unlock(&fuse_context_lock);

	f = (struct fuse *) fuse_calloc(1, sizeof(struct fuse));
	if (f == NULL) {
		fuse_log_err( "fuse: failed to allocate fuse object\n");
		goto out;
	}

	fs = fuse_fs_new(op, op_size, user_data);
	if (!fs)
		goto out_free;

	f->fs = fs;
	f->conf.nopath = fs->op.flag_nopath;

	/* Oh f**k, this is ugly! */
	if (!fs->op.lock) {
		llop.getlk = NULL;
		llop.setlk = NULL;
	}

	f->conf.entry_timeout = 1.0;
	f->conf.attr_timeout = 1.0;
	f->conf.negative_timeout = 0.0;
	f->conf.intr_signal = FUSE_DEFAULT_INTR_SIGNAL;

	f->pagesize = getpagesize();
	init_list_head(&f->partial_slabs);
	init_list_head(&f->full_slabs);
	init_list_head(&f->lru_table);

	if (fuse_opt_parse(args, &f->conf, fuse_lib_opts,
			   fuse_lib_opt_proc) == -1)
		goto out_free_fs;

	if (f->conf.modules) {
		char *module;
		char *next;

		for (module = f->conf.modules; module; module = next) {
			char *p;
			for (p = module; *p && *p != ':'; p++);
			next = *p ? p + 1 : NULL;
			*p = '\0';
			if (module[0] &&
			    fuse_push_module(f, module, args) == -1)
				goto out_free_fs;
		}
	}

	if (!f->conf.ac_attr_timeout_set)
		f->conf.ac_attr_timeout = f->conf.attr_timeout;

#if defined(__FreeBSD__) || defined(__NetBSD__)
	/*
	 * In FreeBSD, we always use these settings as inode numbers
	 * are needed to make getcwd(3) work.
	 */
	f->conf.readdir_ino = 1;
#endif

	f->se = fuse_lowlevel_new(args, &llop, sizeof(llop), f);
	if (f->se == NULL) {
		if (f->conf.help)
			fuse_lib_help_modules();
		goto out_free_fs;
	}

	fuse_session_add_chan(f->se, ch);

	if (f->conf.debug) {
		fuse_log_debug( "nopath: %i\n", f->conf.nopath);
	}

	/* Trace topmost layer by default */
	f->fs->debug = f->conf.debug;
	f->ctr = 0;
	f->generation = 0;
	if (node_table_init(&f->name_table) == -1)
		goto out_free_session;

	if (node_table_init(&f->id_table) == -1)
		goto out_free_name_table;

	fuse_mutex_init(&f->lock);

	root = alloc_node(&f->conf);
	if (root == NULL) {
		fuse_log_err( "fuse: memory allocation failed\n");
		goto out_free_id_table;
	}
	if (lru_enabled(&f->conf)) {
		struct node_lru *lnode = node_lru(root);
		init_list_head(&lnode->lru);
	}

	strcpy(root->inline_name, "/");
	root->name = root->inline_name;

	if (f->conf.intr &&
	    fuse_init_intr_signal(f->conf.intr_signal,
				  &f->intr_installed) == -1)
		goto out_free_root;

	root->parent = NULL;
	root->nodeid = FUSE_ROOT_ID;
	inc_nlookup(root);
	hash_id(f, root);

	return f;

out_free_root:
	fuse_free(root);
out_free_id_table:
	fuse_free(f->id_table.array);
out_free_name_table:
	fuse_free(f->name_table.array);
out_free_session:
	fuse_session_destroy(f->se);
out_free_fs:
	if (f->fs->m)
		fuse_put_module(f->fs->m);
	fuse_free(f->fs);
	fuse_free(f->conf.modules);
out_free:
	fuse_free(f);
out:
	return NULL;
}

void fuse_destroy(struct fuse *f)
{
	size_t i;

	if (f->conf.intr && f->intr_installed)
		fuse_restore_intr_signal(f->conf.intr_signal);

	if (f->fs) {
		fuse_create_context(f);

		for (i = 0; i < f->id_table.size; i++) {
			struct node *node;

			for (node = f->id_table.array[i]; node != NULL;
			     node = node->id_next) {
				if (node->is_hidden) {
					char *path;
					if (try_get_path(f, node->nodeid, NULL, &path, NULL, false) == 0) {
						fuse_fs_unlink(NULL, f->fs, path);
						fuse_free(path);
					}
				}
			}
		}
	}
	for (i = 0; i < f->id_table.size; i++) {
		struct node *node;
		struct node *next;

		for (node = f->id_table.array[i]; node != NULL; node = next) {
			next = node->id_next;
			free_node(f, node);
			f->id_table.use--;
		}
	}
	assert(list_empty(&f->partial_slabs));
	assert(list_empty(&f->full_slabs));

	fuse_free(f->id_table.array);
	fuse_free(f->name_table.array);
	pthread_mutex_destroy(&f->lock);
	fuse_session_destroy(f->se);
	fuse_free(f->conf.modules);
	fuse_free(f);
}




struct fuse_dh *get_dirhandle(const struct fuse_file_info *llfi,struct fuse_file_info *fi)
{
    struct fuse_dh *dh = (struct fuse_dh *) (uintptr_t) llfi->fh;
    memset(fi, 0, sizeof(struct fuse_file_info));
    fi->fh = dh->fh;
    return dh;
}

