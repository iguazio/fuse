#pragma once
#include <sys/stat.h>
#include "dptr_list.h"
#include "fuse_lowlevel.h"
#include "fuse_kernel.h"

struct ig_async_responce{
    fuse_ino_t ino;
    fuse_req_t* req;
    struct fuse *f;
    void *cmd_req;
    enum fuse_opcode opcode;
};

void fuse_lib_add_pending(struct fuse* f, fuse_req_t req, fuse_ino_t ino,
		enum fuse_opcode opcode);
/*
{

	ig_async_responces->req = req;
	ig_async_responces->ino = ino;
	ig_async_responces->f = f;
	ig_async_responces->async_request = fuse_get_context()->async_request;
	ig_async_responces->opcode = opcode;

}*/




