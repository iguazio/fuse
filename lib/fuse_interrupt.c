#include "fuse_interrupt.h"
#include "fuse_prv.h"
#include "fuse_req.h"

void fuse_do_prepare_interrupt( fuse_req_t req, struct fuse_intr_data *d )
{
    d->id = pthread_self();
    pthread_cond_init(&d->cond, NULL);
    d->finished = 0;
    fuse_req_interrupt_func(req, fuse_interrupt, d);
}

void fuse_do_finish_interrupt( struct fuse *f, fuse_req_t req, struct fuse_intr_data *d )
{
    pthread_mutex_lock(&f->lock);
    d->finished = 1;
    pthread_cond_broadcast(&d->cond);
    pthread_mutex_unlock(&f->lock);
    fuse_req_interrupt_func(req, NULL, NULL);
    pthread_cond_destroy(&d->cond);
}

void fuse_finish_interrupt( struct fuse *f, fuse_req_t req, struct fuse_intr_data *d )
{
    if (f->conf.intr)
        fuse_do_finish_interrupt(f, req, d);
}

void fuse_prepare_interrupt( struct fuse *f, fuse_req_t req, struct fuse_intr_data *d )
{
    if (f->conf.intr)
        fuse_do_prepare_interrupt(req, d);
}

void fuse_interrupt( fuse_req_t req, void *d_ )
{
    struct fuse_intr_data *d = d_;
    struct fuse *f = req_fuse(req);

    if (d->id == pthread_self())
        return;

    pthread_mutex_lock(&f->lock);
    while (!d->finished) {
        struct timeval now;
        struct timespec timeout;

        pthread_kill(d->id, f->conf.intr_signal);
        gettimeofday(&now, NULL);
        timeout.tv_sec = now.tv_sec + 1;
        timeout.tv_nsec = now.tv_usec * 1000;
        pthread_cond_timedwait(&d->cond, &f->lock, &timeout);
    }
    pthread_mutex_unlock(&f->lock);
}

void fuse_intr_sighandler( int sig )
{
    (void) sig;
    /* Nothing to do */
}
