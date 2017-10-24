#include "fuse_lib_context.h"
#include "fuse_log.h"

pthread_mutex_t fuse_context_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread struct fuse_context_i ctx = {};
struct fuse_context_i * fuse_create_context( struct fuse *f )
{
    ctx.ctx.fuse = f;
    return &ctx;
}

struct fuse_context_i * fuse_get_context_internal( void )
{
    return &ctx;
}

void fuse_freecontext( void *data )
{
    (void)data;
}

 