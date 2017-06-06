#pragma once
int lookup_path(struct fuse_fsm *parent, struct fuse *f, fuse_ino_t nodeid, const char *name, const char *path, struct fuse_entry_param *e, struct fuse_file_info *fi );
