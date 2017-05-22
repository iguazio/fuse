#pragma once
struct fuse;
size_t id_hash(struct fuse *f, fuse_ino_t ino);
