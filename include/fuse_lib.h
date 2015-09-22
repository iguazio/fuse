#pragma once
#include "fuse_fsm.h"
#include "fuse_fs.h"
#include "fuse_interrupt.h"
#include "fuse_prv.h"
#include "fuse_req.h"
#include "fuse_path.h"
#include "fuse_fs.h"

void fuse_lib_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void fuse_lib_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *llfi);
void fuse_lib_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *llfi);
void fuse_lib_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);

void fuse_lib_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void fuse_lib_read(fuse_req_t req, fuse_ino_t ino, size_t size,off_t off, struct fuse_file_info *fi);
