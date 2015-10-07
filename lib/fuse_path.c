#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "fuse_path.h"
#include "fuse_prv.h"

int try_get_path( struct fuse *f, fuse_ino_t nodeid, const char *name, char **path, struct node **wnodep, bool need_lock )
{
    unsigned bufsize = 256;
    char *buf;
    char *s;
    struct node *node;
    struct node *wnode = NULL;
    int err;

    *path = NULL;

    err = -ENOMEM;
    buf = fuse_malloc(bufsize);
    if (buf == NULL)
        goto out_err;

    s = buf + bufsize - 1;
    *s = '\0';

    if (name != NULL) {
        s = add_name(&buf, &bufsize, s, name);
        err = -ENOMEM;
        if (s == NULL)
            goto out_free;
    }

    if (wnodep) {
        assert(need_lock);
        wnode = lookup_node(f, nodeid, name);
        if (wnode) {
            if (wnode->treelock != 0) {
                if (wnode->treelock > 0)
                    wnode->treelock += TREELOCK_WAIT_OFFSET;
                err = -EAGAIN;
                goto out_free;
            }
            wnode->treelock = TREELOCK_WRITE;
        }
    }

    for (node = get_node(f, nodeid); node->nodeid != FUSE_ROOT_ID;
        node = node->parent) {
            err = -ENOENT;
            if (node->name == NULL || node->parent == NULL)
                goto out_unlock;

            err = -ENOMEM;
            s = add_name(&buf, &bufsize, s, node->name);
            if (s == NULL)
                goto out_unlock;

            if (need_lock) {
                err = -EAGAIN;
                if (node->treelock < 0)
                    goto out_unlock;

                node->treelock++;
            }
    }

    if (s[0])
        memmove(buf, s, bufsize - (s - buf));
    else
        strcpy(buf, "/");

    *path = buf;
    if (wnodep)
        *wnodep = wnode;

    return 0;

out_unlock:
    if (need_lock)
        unlock_path(f, nodeid, wnode, node);
out_free:
    fuse_free(buf);

out_err:
    return err;
}

char * add_name( char **buf, unsigned *bufsize, char *s, const char *name )
{
    size_t len = strlen(name);

    if (s - len <= *buf) {
        unsigned pathlen = *bufsize - (s - *buf);
        unsigned newbufsize = *bufsize;
        char *newbuf;

        while (newbufsize < pathlen + len + 1) {
            if (newbufsize >= 0x80000000)
                newbufsize = 0xffffffff;
            else
                newbufsize *= 2;
        }

        newbuf = fuse_realloc(*buf, newbufsize);
        if (newbuf == NULL)
            return NULL;

        *buf = newbuf;
        s = newbuf + newbufsize - pathlen;
        memmove(s, newbuf + *bufsize - pathlen, pathlen);
        *bufsize = newbufsize;
    }
    s -= len;
    strncpy(s, name, len);
    s--;
    *s = '/';

    return s;
}

void unlock_path( struct fuse *f, fuse_ino_t nodeid, struct node *wnode, struct node *end )
{
    struct node *node;

    if (wnode) {
        assert(wnode->treelock == TREELOCK_WRITE);
        wnode->treelock = 0;
    }

    for (node = get_node(f, nodeid);
        node != end && node->nodeid != FUSE_ROOT_ID; node = node->parent) {
            assert(node->treelock != 0);
            assert(node->treelock != TREELOCK_WAIT_OFFSET);
            assert(node->treelock != TREELOCK_WRITE);
            node->treelock--;
            if (node->treelock == TREELOCK_WAIT_OFFSET)
                node->treelock = 0;
    }
}

void free_path2( struct fuse *f, fuse_ino_t nodeid1, fuse_ino_t nodeid2, struct node *wnode1, struct node *wnode2, char *path1, char *path2 )
{
    pthread_mutex_lock(&f->lock);
    unlock_path(f, nodeid1, wnode1, NULL);
    unlock_path(f, nodeid2, wnode2, NULL);
    wake_up_queued(f);
    pthread_mutex_unlock(&f->lock);
    fuse_free(path1);
    fuse_free(path2);
}

void free_path( struct fuse *f, fuse_ino_t nodeid, char *path )
{
    if (path)
        free_path_wrlock(f, nodeid, NULL, path);
}

void free_path_wrlock( struct fuse *f, fuse_ino_t nodeid, struct node *wnode, char *path )
{
    pthread_mutex_lock(&f->lock);
    unlock_path(f, nodeid, wnode, NULL);
    if (f->lockq)
        wake_up_queued(f);
    pthread_mutex_unlock(&f->lock);
    fuse_free(path);
}

void wake_up_queued( struct fuse *f )
{
    struct lock_queue_element *qe;

    for (qe = f->lockq; qe != NULL; qe = qe->next)
        queue_element_wakeup(f, qe);
}

int get_path2( struct fuse *f, fuse_ino_t nodeid1, const char *name1, fuse_ino_t nodeid2, const char *name2, char **path1, char **path2, struct node **wnode1, struct node **wnode2 )
{
    int err;

    pthread_mutex_lock(&f->lock);
    err = try_get_path2(f, nodeid1, name1, nodeid2, name2,
        path1, path2, wnode1, wnode2);
    if (err == -EAGAIN) {
        struct lock_queue_element qe = {
            .nodeid1 = nodeid1,
            .name1 = name1,
            .path1 = path1,
            .wnode1 = wnode1,
            .nodeid2 = nodeid2,
            .name2 = name2,
            .path2 = path2,
            .wnode2 = wnode2,
        };

        debug_path(f, "QUEUE PATH1", nodeid1, name1, !!wnode1);
        debug_path(f, "      PATH2", nodeid2, name2, !!wnode2);
        err = wait_path(f, &qe);
        debug_path(f, "DEQUEUE PATH1", nodeid1, name1, !!wnode1);
        debug_path(f, "        PATH2", nodeid2, name2, !!wnode2);
    }
    pthread_mutex_unlock(&f->lock);

    return err;
}

int try_get_path2( struct fuse *f, fuse_ino_t nodeid1, const char *name1, fuse_ino_t nodeid2, const char *name2, char **path1, char **path2, struct node **wnode1, struct node **wnode2 )
{
    int err;

    /* FIXME: locking two paths needs deadlock checking */
    err = try_get_path(f, nodeid1, name1, path1, wnode1, true);
    if (!err) {
        err = try_get_path(f, nodeid2, name2, path2, wnode2, true);
        if (err) {
            struct node *wn1 = wnode1 ? *wnode1 : NULL;

            unlock_path(f, nodeid1, wn1, NULL);
            fuse_free(*path1);
        }
    }
    return err;
}

int get_path_nullok( struct fuse *f, fuse_ino_t nodeid, char **path )
{
    int err = 0;

    if (f->conf.nopath) {
        *path = NULL;
    } else {
        err = get_path_common(f, nodeid, NULL, path, NULL);
        if (err == -ENOENT)
            err = 0;
    }

    return err;
}

int get_path_common( struct fuse *f, fuse_ino_t nodeid, const char *name, char **path, struct node **wnode )
{
    int err;

    pthread_mutex_lock(&f->lock);
    err = try_get_path(f, nodeid, name, path, wnode, true);
    if (err == -EAGAIN) {
        struct lock_queue_element qe = {
            .nodeid1 = nodeid,
            .name1 = name,
            .path1 = path,
            .wnode1 = wnode,
        };
        debug_path(f, "QUEUE PATH", nodeid, name, !!wnode);
        err = wait_path(f, &qe);
        debug_path(f, "DEQUEUE PATH", nodeid, name, !!wnode);
    }
    pthread_mutex_unlock(&f->lock);

    return err;
}

int wait_path( struct fuse *f, struct lock_queue_element *qe )
{
    queue_path(f, qe);

    do {
        pthread_cond_wait(&qe->cond, &f->lock);
    } while (!qe->done);

    dequeue_path(f, qe);

    return qe->err;
}

void queue_path( struct fuse *f, struct lock_queue_element *qe )
{
    struct lock_queue_element **qp;

    qe->done = false;
    qe->first_locked = false;
    qe->second_locked = false;
    pthread_cond_init(&qe->cond, NULL);
    qe->next = NULL;
    for (qp = &f->lockq; *qp != NULL; qp = &(*qp)->next);
    *qp = qe;
}

void dequeue_path( struct fuse *f, struct lock_queue_element *qe )
{
    struct lock_queue_element **qp;

    pthread_cond_destroy(&qe->cond);
    for (qp = &f->lockq; *qp != qe; qp = &(*qp)->next);
    *qp = qe->next;
}

void debug_path( struct fuse *f, const char *msg, fuse_ino_t nodeid, const char *name, bool wr )
{
    if (f->conf.debug) {
        struct node *wnode = NULL;

        if (wr)
            wnode = lookup_node(f, nodeid, name);

        if (wnode) {
            fprintf(stderr, "%s %llu (w)\n",
                msg, (unsigned long long) wnode->nodeid);
        } else {
            fprintf(stderr, "%s %llu\n",
                msg, (unsigned long long) nodeid);
        }
    }
}

int get_path_name( struct fuse *f, fuse_ino_t nodeid, const char *name, char **path )
{
    return get_path_common(f, nodeid, name, path, NULL);
}

int get_path_wrlock( struct fuse *f, fuse_ino_t nodeid, const char *name, char **path, struct node **wnode )
{
    return get_path_common(f, nodeid, name, path, wnode);
}

int get_path( struct fuse *f, fuse_ino_t nodeid, char **path )
{
    return get_path_common(f, nodeid, NULL, path, NULL);
}
