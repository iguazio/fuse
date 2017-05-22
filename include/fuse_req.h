#pragma once
#include "fuse_lib_context.h"
#include "fuse_lowlevel.h"

struct fuse *req_fuse(fuse_req_t req);
struct fuse *req_fuse_prepare(fuse_req_t req);
