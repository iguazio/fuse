#include <string.h>
#include "fuse_lock.h"
#include "fuse_prv.h"
#include "fuse_req.h"
#include "fuse_path.h"
#include "fuse_interrupt.h"

void flock_to_lock( struct flock *flock, struct lock *lock )
{
    memset(lock, 0, sizeof(struct lock));
    lock->type = flock->l_type;
    lock->start = flock->l_start;
    lock->end =
        flock->l_len ? flock->l_start + flock->l_len - 1 : OFFSET_MAX;
    lock->pid = flock->l_pid;
}

void lock_to_flock( struct lock *lock, struct flock *flock )
{
    flock->l_type = lock->type;
    flock->l_start = lock->start;
    flock->l_len =
        (lock->end == OFFSET_MAX) ? 0 : lock->end - lock->start + 1;
    flock->l_pid = lock->pid;
}

int fuse_lock_common( struct fuse_fsm* fsm __attribute__((unused)), fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, struct flock *lock, int cmd )
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = get_path_nullok(f, ino, &path);
    if (!err) {
        struct fuse_intr_data d;
        fuse_prepare_interrupt(f, req, &d);
        err = fuse_fs_lock(fsm, f->fs, path, fi, cmd, lock);
        fuse_finish_interrupt(f, req, &d);
        free_path(f, ino, path);
    }
    return err;
}

void insert_lock( struct lock **pos, struct lock *lock )
{
    lock->next = *pos;
    *pos = lock;
}

void delete_lock( struct lock **lockp )
{
    struct lock *l = *lockp;
    *lockp = l->next;
    free(l);
}

struct lock * locks_conflict( struct node *node, const struct lock *lock )
{
    struct lock *l;

    for (l = node->locks; l; l = l->next)
        if (l->owner != lock->owner &&
            lock->start <= l->end && l->start <= lock->end &&
            (l->type == F_WRLCK || lock->type == F_WRLCK))
            break;

    return l;
}

int locks_insert( struct node *node, struct lock *lock )
{
    struct lock **lp;
    struct lock *newl1 = NULL;
    struct lock *newl2 = NULL;

    if (lock->type != F_UNLCK || lock->start != 0 ||
        lock->end != OFFSET_MAX) {
            newl1 = malloc(sizeof(struct lock));
            newl2 = malloc(sizeof(struct lock));

            if (!newl1 || !newl2) {
                free(newl1);
                free(newl2);
                return -ENOLCK;
            }
    }

    for (lp = &node->locks; *lp;) {
        struct lock *l = *lp;
        if (l->owner != lock->owner)
            goto skip;

        if (lock->type == l->type) {
            if (l->end < lock->start - 1)
                goto skip;
            if (lock->end < l->start - 1)
                break;
            if (l->start <= lock->start && lock->end <= l->end)
                goto out;
            if (l->start < lock->start)
                lock->start = l->start;
            if (lock->end < l->end)
                lock->end = l->end;
            goto delete;
        } else {
            if (l->end < lock->start)
                goto skip;
            if (lock->end < l->start)
                break;
            if (lock->start <= l->start && l->end <= lock->end)
                goto delete;
            if (l->end <= lock->end) {
                l->end = lock->start - 1;
                goto skip;
            }
            if (lock->start <= l->start) {
                l->start = lock->end + 1;
                break;
            }
            *newl2 = *l;
            newl2->start = lock->end + 1;
            l->end = lock->start - 1;
            insert_lock(&l->next, newl2);
            newl2 = NULL;
        }
skip:
        lp = &l->next;
        continue;

        delete:
        delete_lock(lp);
    }
    if (lock->type != F_UNLCK) {
        *newl1 = *lock;
        insert_lock(lp, newl1);
        newl1 = NULL;
    }
out:
    free(newl1);
    free(newl2);
    return 0;
}
