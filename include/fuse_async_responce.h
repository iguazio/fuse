#pragma once
#include <sys/stat.h>
#include "fuse_lowlevel.h"
#include "fuse_kernel.h"

struct fuse_async_responce{
    fuse_ino_t ino;
    fuse_req_t req;
    struct fuse *f;
    enum fuse_opcode opcode;
    struct fuse_dh *dh;
    void *cmd_req;
};



void fuse_async_add_pending(struct fuse_dh *dh, struct fuse* f, fuse_req_t req, fuse_ino_t ino,
		enum fuse_opcode opcode);
/*
{

	ig_async_responces->req = req;
	ig_async_responces->ino = ino;
	ig_async_responces->f = f;
	ig_async_responces->async_request = fuse_get_context()->async_request;
	ig_async_responces->opcode = opcode;

}*/




