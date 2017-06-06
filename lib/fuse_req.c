#include "fuse_req.h"

struct fuse * req_fuse( fuse_req_t req )
{
    return (struct fuse *) fuse_req_userdata(req);
}

struct fuse * req_fuse_prepare( fuse_req_t req )
{
    struct fuse_context_i *c = fuse_create_context(req_fuse(req));
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    c->req = req;
    c->ctx.uid = ctx->uid;
    c->ctx.gid = ctx->gid;
    c->ctx.pid = ctx->pid;
    c->ctx.umask = ctx->umask;
    return c->ctx.fuse;
}
