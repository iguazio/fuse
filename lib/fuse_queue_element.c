#include "fuse_queue_element.h"
#include "fuse_prv.h"

void queue_element_wakeup( struct fuse *f, struct lock_queue_element *qe )
{
    int err;
    bool first = (qe == f->lockq);

    if (!qe->path1) {
        /* Just waiting for it to be unlocked */
        if (get_node(f, qe->nodeid1)->treelock == 0)
            pthread_cond_signal(&qe->cond);

        return;
    }

    if (!qe->first_locked) {
        err = try_get_path(f, qe->nodeid1, qe->name1, qe->path1,
            qe->wnode1, true);
        if (!err)
            qe->first_locked = true;
        else if (err != -EAGAIN)
            goto err_unlock;
    }
    if (!qe->second_locked && qe->path2) {
        err = try_get_path(f, qe->nodeid2, qe->name2, qe->path2,
            qe->wnode2, true);
        if (!err)
            qe->second_locked = true;
        else if (err != -EAGAIN)
            goto err_unlock;
    }

    if (qe->first_locked && (qe->second_locked || !qe->path2)) {
        err = 0;
        goto done;
    }

    /*
    * Only let the first element be partially locked otherwise there could
    * be a deadlock.
    *
    * But do allow the first element to be partially locked to prevent
    * starvation.
    */
    if (!first)
        queue_element_unlock(f, qe);

    /* keep trying */
    return;

err_unlock:
    queue_element_unlock(f, qe);
done:
    qe->err = err;
    qe->done = true;
    pthread_cond_signal(&qe->cond);
}

void queue_element_unlock( struct fuse *f, struct lock_queue_element *qe )
{
    struct node *wnode;

    if (qe->first_locked) {
        wnode = qe->wnode1 ? *qe->wnode1 : NULL;
        unlock_path(f, qe->nodeid1, wnode, NULL);
        qe->first_locked = false;
    }
    if (qe->second_locked) {
        wnode = qe->wnode2 ? *qe->wnode2 : NULL;
        unlock_path(f, qe->nodeid2, wnode, NULL);
        qe->second_locked = false;
    }
}
