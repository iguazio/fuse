#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include "fuse_log.h"

#include "fuse_fs.h"

//From fuse.c
void fuse_put_module(struct fuse_module *m);

int fuse_fs_getattr( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct stat *buf )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.getattr) {
        if (fs->debug)
            fuse_log_debug( "getattr %s\n", path);

        return fs->op.getattr(fsm, path, buf);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_fgetattr( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct stat *buf, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.fgetattr) {
        if (fs->debug)
            fuse_log_debug( "fgetattr[%llu] %s\n",
            (unsigned long long) fi->fh, path);

        return fs->op.fgetattr(fsm, path, buf, fi);
    } else if (path && fs->op.getattr) {
        if (fs->debug)
            fuse_log_debug( "getattr %s\n", path);

        return fs->op.getattr(fsm, path, buf);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_rename( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *oldpath, const char *newpath, unsigned int flags )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.rename) {
        if (fs->debug)
            fuse_log_debug( "rename %s %s 0x%x\n", oldpath, newpath,
            flags);

        return fs->op.rename(fsm, oldpath, newpath, flags);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_unlink( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.unlink) {
        if (fs->debug)
            fuse_log_debug( "unlink %s\n", path);

        return fs->op.unlink(fsm, path);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_rmdir( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.rmdir) {
        if (fs->debug)
            fuse_log_debug( "rmdir %s\n", path);

        return fs->op.rmdir(fsm, path);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_symlink( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *linkname, const char *path )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.symlink) {
        if (fs->debug)
            fuse_log_debug( "symlink %s %s\n", linkname, path);

        return fs->op.symlink(fsm, linkname, path);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_link( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *oldpath, const char *newpath )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.link) {
        if (fs->debug)
            fuse_log_debug( "link %s %s\n", oldpath, newpath);

        return fs->op.link(fsm, oldpath, newpath);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_release( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.release) {
        if (fs->debug)
            fuse_log_debug( "release%s[%llu] flags: 0x%x\n",
            fi->flush ? "+flush" : "",
            (unsigned long long) fi->fh, fi->flags);

        return fs->op.release(fsm, path, fi);
    } else {
        return 0;
    }
}

int fuse_fs_opendir( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.opendir) {
        int err;

        if (fs->debug)
            fuse_log_debug( "opendir flags: 0x%x %s\n", fi->flags,
            path);

        err = fs->op.opendir(fsm, path, fi);

        if (fs->debug && !err)
            fuse_log_debug( "   opendir[%llu] flags: 0x%x %s\n",
            (unsigned long long) fi->fh, fi->flags, path);

        return err;
    } else {
        return 0;
    }
}

int fuse_fs_open( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.open) {
        int err;

        if (fs->debug)
            fuse_log_debug( "open flags: 0x%x %s\n", fi->flags,
            path);

        err = fs->op.open(fsm, path, fi);

        if (fs->debug && !err)
            fuse_log_debug( "   open[%llu] flags: 0x%x %s\n",
            (unsigned long long) fi->fh, fi->flags, path);

        return err;
    } else {
        return 0;
    }
}

int fuse_fs_read_buf( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_bufvec **bufp, size_t size, off_t off, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.read || fs->op.read_buf) {
        int res;

        if (fs->debug)
            fuse_log_debug(
            "read[%llu] %zu bytes from %llu flags: 0x%x\n",
            (unsigned long long) fi->fh,
            size, (unsigned long long) off, fi->flags);

        if (fs->op.read_buf) {
            res = fs->op.read_buf(fsm, path, bufp, size, off, fi);
        } else {
            struct fuse_bufvec *buf;
            void *mem;

            buf = fuse_malloc(sizeof(struct fuse_bufvec));
            if (buf == NULL)
                return -ENOMEM;

            mem = fuse_malloc(size);
            if (mem == NULL) {
                fuse_free(buf);
                return -ENOMEM;
            }
            *buf = FUSE_BUFVEC_INIT(size);
            buf->buf[0].mem = mem;
            *bufp = buf;

            res = fs->op.read(fsm, path, mem, size, off, fi);
            if (res >= 0)
                buf->buf[0].size = res;
        }

        if (fs->debug && res >= 0)
            fuse_log_debug( "   read[%llu] %zu bytes from %llu\n",
            (unsigned long long) fi->fh,
            fuse_buf_size(*bufp),
            (unsigned long long) off);
        if (res >= 0 && fuse_buf_size(*bufp) > (int) size)
            fuse_log_err( "fuse: read too many bytes\n");

        if (res < 0)
            return res;

        return 0;
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_read( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, char *mem, size_t size, off_t off, struct fuse_file_info *fi )
{
    int res;
    struct fuse_bufvec *buf = NULL;

    res = fuse_fs_read_buf(fsm, fs, path, &buf, size, off, fi);
    if (res == 0) {
        struct fuse_bufvec dst = FUSE_BUFVEC_INIT(size);

        dst.buf[0].mem = mem;
        res = fuse_buf_copy(&dst, buf, 0);
    }
    fuse_buf_free(buf);

    return res;}

int fuse_fs_write_buf( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_bufvec *buf, off_t off, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.write_buf || fs->op.write) {
        int res;
        size_t size = fuse_buf_size(buf);

        assert(buf->idx == 0 && buf->off == 0);
        if (fs->debug)
            fuse_log_debug(
            "write%s[%llu] %zu bytes to %llu flags: 0x%x\n",
            fi->writepage ? "page" : "",
            (unsigned long long) fi->fh,
            size,
            (unsigned long long) off,
            fi->flags);

        if (fs->op.write_buf) {
            res = fs->op.write_buf(fsm, path, buf, off, fi);
        } else {
            void *mem = NULL;
            struct fuse_buf *flatbuf;
            struct fuse_bufvec tmp = FUSE_BUFVEC_INIT(size);

            if (buf->count == 1 &&
                !(buf->buf[0].flags & FUSE_BUF_IS_FD)) {
                    flatbuf = &buf->buf[0];
            } else {
                res = -ENOMEM;
                mem = fuse_malloc(size);
                if (mem == NULL)
                    goto out;

                tmp.buf[0].mem = mem;
                res = fuse_buf_copy(&tmp, buf, 0);
                if (res <= 0)
                    goto out_free;

                tmp.buf[0].size = res;
                flatbuf = &tmp.buf[0];
            }

            res = fs->op.write(fsm, path, flatbuf->mem, flatbuf->size,
                off, fi);
out_free:
            fuse_free(mem);
        }
out:
        if (fs->debug && res >= 0)
            fuse_log_debug( "   write%s[%llu] %u bytes to %llu\n",
            fi->writepage ? "page" : "",
            (unsigned long long) fi->fh, res,
            (unsigned long long) off);
        if (res > (int) size)
            fuse_log_err( "fuse: wrote too many bytes\n");

        return res;
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_write( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, const char *mem, size_t size, off_t off, struct fuse_file_info *fi )
{
    struct fuse_bufvec bufv = FUSE_BUFVEC_INIT(size);

    bufv.buf[0].mem = (void *) mem;

    return fuse_fs_write_buf(fsm, fs, path, &bufv, off, fi);
}

int fuse_fs_fsync( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, int datasync, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.fsync) {
        if (fs->debug)
            fuse_log_debug( "fsync[%llu] datasync: %i\n",
            (unsigned long long) fi->fh, datasync);

        return fs->op.fsync(fsm, path, datasync, fi);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_fsyncdir( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, int datasync, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.fsyncdir) {
        if (fs->debug)
            fuse_log_debug( "fsyncdir[%llu] datasync: %i\n",
            (unsigned long long) fi->fh, datasync);

        return fs->op.fsyncdir(fsm, path, datasync, fi);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_flush( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.flush) {
        if (fs->debug)
            fuse_log_debug( "flush[%llu]\n",
            (unsigned long long) fi->fh);

        return fs->op.flush(fsm, path, fi);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_statfs( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct statvfs *buf )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.statfs) {
        if (fs->debug)
            fuse_log_debug( "statfs %s\n", path);

        return fs->op.statfs(fsm, path, buf);
    } else {
        buf->f_namemax = 255;
        buf->f_bsize = 512;
        return 0;
    }
}

int fuse_fs_releasedir( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.releasedir) {
        if (fs->debug)
            fuse_log_debug( "releasedir[%llu] flags: 0x%x\n",
            (unsigned long long) fi->fh, fi->flags);

        return fs->op.releasedir(fsm, path, fi);
    } else {
        return 0;
    }
}

int fuse_fs_readdir( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, void *buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags flags )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.readdir) {
        if (fs->debug) {
            fuse_log_debug( "readdir%s[%llu] from %llu\n",
                (flags & FUSE_READDIR_PLUS) ? "plus" : "",
                (unsigned long long) fi->fh,
                (unsigned long long) off);
        }

        return fs->op.readdir(fsm, path, buf, filler, off, fi, flags);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_create( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, mode_t mode, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.create) {
        int err;

        if (fs->debug)
            fuse_log_debug(
            "create flags: 0x%x %s 0%o umask=0%03o\n",
            fi->flags, path, mode,
            fuse_get_context()->umask);

        err = fs->op.create(fsm, path, mode, fi);

        if (fs->debug && !err)
            fuse_log_debug( "   create[%llu] flags: 0x%x %s\n",
            (unsigned long long) fi->fh, fi->flags, path);

        return err;
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_lock( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_file_info *fi, int cmd, struct flock *lock )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.lock) {
        if (fs->debug)
            fuse_log_debug( "lock[%llu] %s %s start: %llu len: %llu pid: %llu\n",
            (unsigned long long) fi->fh,
            (cmd == F_GETLK ? "F_GETLK" :
            (cmd == F_SETLK ? "F_SETLK" :
            (cmd == F_SETLKW ? "F_SETLKW" : "???"))),
            (lock->l_type == F_RDLCK ? "F_RDLCK" :
            (lock->l_type == F_WRLCK ? "F_WRLCK" :
            (lock->l_type == F_UNLCK ? "F_UNLCK" :
            "???"))),
            (unsigned long long) lock->l_start,
            (unsigned long long) lock->l_len,
            (unsigned long long) lock->l_pid);

        return fs->op.lock(fsm, path, fi, cmd, lock);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_flock( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_file_info *fi, int op )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.flock) {
        if (fs->debug) {
            int xop = op & ~LOCK_NB;

            fuse_log_debug( "lock[%llu] %s%s\n",
                (unsigned long long) fi->fh,
                xop == LOCK_SH ? "LOCK_SH" :
                (xop == LOCK_EX ? "LOCK_EX" :
                (xop == LOCK_UN ? "LOCK_UN" : "???")),
                (op & LOCK_NB) ? "|LOCK_NB" : "");
        }
        return fs->op.flock(fsm, path, fi, op);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_chown( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, uid_t uid, gid_t gid )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.chown) {
        if (fs->debug)
            fuse_log_debug( "chown %s %lu %lu\n", path,
            (unsigned long) uid, (unsigned long) gid);

        return fs->op.chown(fsm, path, uid, gid);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_truncate( struct fuse_fsm* fsm __attribute__((unused)),struct fuse_fs *fs, const char *path, off_t size )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.truncate) {
        if (fs->debug)
            fuse_log_debug( "truncate %s %llu\n", path,
            (unsigned long long) size);

        return fs->op.truncate(fsm, path, size);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_ftruncate(struct fuse_fsm* fsm __attribute__((unused)),struct fuse_fs *fs, const char *path, off_t size, struct fuse_file_info *fi)
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.ftruncate) {
        if (fs->debug)
            fuse_log_debug( "ftruncate[%llu] %llu\n",
            (unsigned long long) fi->fh,
            (unsigned long long) size);

        return fs->op.ftruncate(fsm, path, size, fi);
    } else if (path && fs->op.truncate) {
        if (fs->debug)
            fuse_log_debug( "truncate %s %llu\n", path,
            (unsigned long long) size);

        return fs->op.truncate(fsm, path, size);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_utimens( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, const struct timespec tv[2] )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.utimens) {
        if (fs->debug)
            fuse_log_debug( "utimens %s %li.%09lu %li.%09lu\n",
            path, tv[0].tv_sec, tv[0].tv_nsec,
            tv[1].tv_sec, tv[1].tv_nsec);

        return fs->op.utimens(fsm, path, tv);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_access( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, int mask )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.access) {
        if (fs->debug)
            fuse_log_debug( "access %s 0%o\n", path, mask);

        return fs->op.access(fsm, path, mask);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_readlink( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, char *buf, size_t len )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.readlink) {
        if (fs->debug)
            fuse_log_debug( "readlink %s %lu\n", path,
            (unsigned long) len);

        return fs->op.readlink(fsm, path, buf, len);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_mknod( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, mode_t mode, dev_t rdev )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.mknod) {
        if (fs->debug)
            fuse_log_debug( "mknod %s 0%o 0x%llx umask=0%03o\n",
            path, mode, (unsigned long long) rdev,
            fuse_get_context()->umask);

        return fs->op.mknod(fsm, path, mode, rdev);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_mkdir( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, mode_t mode )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.mkdir) {
        if (fs->debug)
            fuse_log_debug( "mkdir %s 0%o umask=0%03o\n",
            path, mode, fuse_get_context()->umask);

        return fs->op.mkdir(fsm, path, mode);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_setxattr( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, const char *name, const char *value, size_t size, int flags )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.setxattr) {
        if (fs->debug)
            fuse_log_debug( "setxattr %s %s %lu 0x%x\n",
            path, name, (unsigned long) size, flags);

        return fs->op.setxattr(fsm, path, name, value, size, flags);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_getxattr( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, const char *name, char *value, size_t size )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.getxattr) {
        if (fs->debug)
            fuse_log_debug( "getxattr %s %s %lu\n",
            path, name, (unsigned long) size);

        return fs->op.getxattr(fsm, path, name, value, size);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_listxattr( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, char *list, size_t size )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.listxattr) {
        if (fs->debug)
            fuse_log_debug( "listxattr %s %lu\n",
            path, (unsigned long) size);

        return fs->op.listxattr(fsm, path, list, size);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_bmap( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, size_t blocksize, uint64_t *idx )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.bmap) {
        if (fs->debug)
            fuse_log_debug( "bmap %s blocksize: %lu index: %llu\n",
            path, (unsigned long) blocksize,
            (unsigned long long) *idx);

        return fs->op.bmap(fsm, path, blocksize, idx);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_removexattr( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, const char *name )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.removexattr) {
        if (fs->debug)
            fuse_log_debug( "removexattr %s %s\n", path, name);

        return fs->op.removexattr(fsm, path, name);
    } else {
        return -ENOSYS;
    }
}

int fuse_fs_ioctl( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, int cmd, void *arg, struct fuse_file_info *fi, unsigned int flags, void *data )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.ioctl) {
        if (fs->debug)
            fuse_log_debug( "ioctl[%llu] 0x%x flags: 0x%x\n",
            (unsigned long long) fi->fh, cmd, flags);

        return fs->op.ioctl(fsm, path, cmd, arg, fi, flags, data);
    } else
        return -ENOSYS;
}

int fuse_fs_poll( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, struct fuse_file_info *fi, struct fuse_pollhandle *ph, unsigned *reventsp )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.poll) {
        int res;

        if (fs->debug)
            fuse_log_debug( "poll[%llu] ph: %p, events 0x%x\n",
            (unsigned long long) fi->fh, ph,
            fi->poll_events);

        res = fs->op.poll(fsm, path, fi, ph, reventsp);

        if (fs->debug && !res)
            fuse_log_debug( "   poll[%llu] revents: 0x%x\n",
            (unsigned long long) fi->fh, *reventsp);

        return res;
    } else
        return -ENOSYS;
}

int fuse_fs_fallocate( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.fallocate) {
        if (fs->debug)
            fuse_log_debug( "fallocate %s mode %x, offset: %llu, length: %llu\n",
            path,
            mode,
            (unsigned long long) offset,
            (unsigned long long) length);

        return fs->op.fallocate(fsm, path, mode, offset, length, fi);
    } else
        return -ENOSYS;
}


void fuse_fs_init(struct fuse_fs *fs, struct fuse_conn_info *conn)
{
    fuse_get_context()->private_data = fs->user_data;
    if (!fs->op.write_buf)
        conn->want &= ~FUSE_CAP_SPLICE_READ;
    if (!fs->op.lock)
        conn->want &= ~FUSE_CAP_POSIX_LOCKS;
    if (!fs->op.flock)
        conn->want &= ~FUSE_CAP_FLOCK_LOCKS;
    if (fs->op.init)
        fs->user_data = fs->op.init(conn);
}

void fuse_fs_destroy(struct fuse_fs *fs)
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.destroy)
        fs->op.destroy(fs->user_data);
    if (fs->m)
        fuse_put_module(fs->m);
    fuse_free(fs);
}
int fuse_fs_chmod( struct fuse_fsm* fsm __attribute__((unused)), struct fuse_fs *fs, const char *path, mode_t mode )
{
    fuse_get_context()->private_data = fs->user_data;
    if (fs->op.chmod)
        return fs->op.chmod(fsm, path, mode);
    else
        return -ENOSYS;
}
