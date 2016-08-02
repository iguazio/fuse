#include "fuse_lib_context.h"
#include "fuse_log.h"

pthread_key_t fuse_context_key;
pthread_mutex_t fuse_context_lock = PTHREAD_MUTEX_INITIALIZER;
int fuse_context_ref;

struct fuse_context_i * fuse_create_context( struct fuse *f )
{
    struct fuse_context_i *c = fuse_get_context_internal();
    if (c == NULL) {
        c = (struct fuse_context_i *)
            fuse_calloc(1, sizeof(struct fuse_context_i));
        if (c == NULL) {
            /* This is hard to deal with properly, so just
            abort.  If memory is so low that the
            context cannot be allocated, there's not
            much hope for the filesystem anyway */
            fuse_log_err( "fuse: failed to allocate thread specific data\n");
            abort();
        }
        pthread_setspecific(fuse_context_key, c);
    } else {
        memset(c, 0, sizeof(*c));
    }
    c->ctx.fuse = f;

    return c;
}

struct fuse_context_i * fuse_get_context_internal( void )
{
    return (struct fuse_context_i *) pthread_getspecific(fuse_context_key);
}

void fuse_freecontext( void *data )
{
    fuse_free(data);
}

int fuse_create_context_key( void )
{
    int err = 0;
    pthread_mutex_lock(&fuse_context_lock);
    if (!fuse_context_ref) {
        err = pthread_key_create(&fuse_context_key, fuse_freecontext);
        if (err) {
            fuse_log_err( "fuse: failed to create thread specific key: %s\n",
                strerror(err));
            pthread_mutex_unlock(&fuse_context_lock);
            return -1;
        }
    }
    fuse_context_ref++;
    pthread_mutex_unlock(&fuse_context_lock);
    return 0;
}

void fuse_delete_context_key( void )
{
    pthread_mutex_lock(&fuse_context_lock);
    fuse_context_ref--;
    if (!fuse_context_ref) {
        fuse_free(pthread_getspecific(fuse_context_key));
        pthread_key_delete(fuse_context_key);
    }
    pthread_mutex_unlock(&fuse_context_lock);
}
