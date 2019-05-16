#pragma once
#include "fuse_fs.h"
#include "fuse_interrupt.h"
#include "fuse_prv.h"
#include "fuse_req.h"
#include "fuse_path.h"
#include "fuse_fs.h"

void fuse_lib_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void fuse_lib_access(fuse_req_t req, fuse_ino_t ino, int mask);
void fuse_lib_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *llfi);
void fuse_lib_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *llfi);
void fuse_lib_lookup(fuse_req_t req, fuse_ino_t parent, const char *name);

void fuse_lib_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void fuse_lib_read(fuse_req_t req, fuse_ino_t ino, size_t size,off_t off, struct fuse_file_info *fi);
void fuse_lib_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi);
void fuse_lib_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *att, int val, struct fuse_file_info *fi);
void fuse_lib_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi);
void fuse_lib_write_buf(fuse_req_t req, fuse_ino_t ino,struct fuse_bufvec *buf, off_t off, struct fuse_file_info *fi);
void fuse_lib_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode);
void fuse_lib_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name);
void fuse_lib_unlink(fuse_req_t req, fuse_ino_t parent, const char *name);
void fuse_lib_rename(fuse_req_t req, fuse_ino_t olddir,
                     const char *oldname, fuse_ino_t newdir,
                     const char *newname, unsigned int flags);
void fuse_lib_readlink(fuse_req_t req, fuse_ino_t ino);
void fuse_lib_symlink(fuse_req_t req, const char *linkname, fuse_ino_t parent, const char *name);


