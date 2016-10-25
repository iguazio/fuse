#include "fuse.h"
#include "fuse_lib_context.h"
#include "fuse_prv.h"
#include "fuse_req.h"
#include "fuse_path.h"
#include "fuse_interrupt.h"
#include "fuse_misc.h"
#include "fuse_lock.h"
#include "fuse_fs.h"
#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
#include "fuse_log.h"

#include <errno.h>
#include <sys/file.h>

static void fuse_lib_init(void *data, struct fuse_conn_info *conn)
{
    struct fuse *f = (struct fuse *) data;

    fuse_create_context(f);
    conn->want |= FUSE_CAP_EXPORT_SUPPORT;
    fuse_fs_init(f->fs, conn);
}


static void fuse_lib_destroy(void *data)
{
    struct fuse *f = (struct fuse *) data;

    fuse_create_context(f);
    fuse_fs_destroy(f->fs);
    f->fs = NULL;
}

static void do_forget(struct fuse *f, fuse_ino_t ino, uint64_t nlookup)
{
    if (f->conf.debug)
        fuse_log_debug( "FORGET %llu/%llu\n", (unsigned long long)ino,
        (unsigned long long) nlookup);
    forget_node(f, ino, nlookup);
}

static void fuse_lib_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    do_forget(req_fuse(req), ino, nlookup);
    fuse_reply_none(req);
}

static void fuse_lib_forget_multi(fuse_req_t req, size_t count,
struct fuse_forget_data *forgets)
{
    struct fuse *f = req_fuse(req);
    size_t i;

    for (i = 0; i < count; i++)
        do_forget(f, forgets[i].ino, forgets[i].nlookup);

    fuse_reply_none(req);
}

static void fuse_lib_readlink(fuse_req_t req, fuse_ino_t ino)
{
    struct fuse *f = req_fuse_prepare(req);
    char linkname[PATH_MAX + 1];
    char *path;
    int err;

    err = get_path(f, ino, &path);
    if (!err) {
        struct fuse_intr_data d;
        fuse_prepare_interrupt(f, req, &d);
        err = fuse_fs_readlink(NULL, f->fs, path, linkname, sizeof(linkname));
        fuse_finish_interrupt(f, req, &d);
        free_path(f, ino, path);
    }
    // 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
    // 		fuse_async_add_pending(NULL,f, req, ino, FUSE_READLINK);
    //         return;
    //     }
    if (!err) {
        linkname[PATH_MAX] = '\0';
        fuse_reply_readlink(req, linkname);
    } else
        reply_err(req, err);
}

/*FixMe: should be separate host callback*/
static void fuse_lib_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
                           mode_t mode, dev_t rdev)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *path;
    int err;

    err = get_path_name(f, parent, name, &path);
    if (!err) {
        struct fuse_intr_data d;

        fuse_prepare_interrupt(f, req, &d);
        err = -ENOSYS;
        if (S_ISREG(mode)) {
            struct fuse_file_info fi;

            memset(&fi, 0, sizeof(fi));
            fi.flags = O_CREAT | O_EXCL | O_WRONLY;
            err = fuse_fs_create(NULL, f->fs, path, mode, &fi);
            if (!err) {
                err = lookup_path(NULL,f, parent, name, path, &e,
                    &fi);
                fuse_fs_release(NULL, f->fs, path, &fi);
            }
        }
        if (err == -ENOSYS) {
            err = fuse_fs_mknod(NULL, f->fs, path, mode, rdev);
            if (!err)
                err = lookup_path(NULL, f, parent, name, path, &e,
                NULL);
        }
        fuse_finish_interrupt(f, req, &d);
        free_path(f, parent, path);
    }
    reply_entry(req, &e, err);
}



static void fuse_lib_symlink(fuse_req_t req, const char *linkname,
                             fuse_ino_t parent, const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *path;
    int err;

    err = get_path_name(f, parent, name, &path);
    if (!err) {
        struct fuse_intr_data d;

        fuse_prepare_interrupt(f, req, &d);
        err = fuse_fs_symlink(NULL, f->fs, linkname, path);
        if (!err)
            err = lookup_path(NULL, f, parent, name, path, &e, NULL);
        fuse_finish_interrupt(f, req, &d);
        free_path(f, parent, path);
    }
    // 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
    // 		fuse_async_add_pending(NULL,f, req, 0, FUSE_SYMLINK);
    //         return;
    //     }
    reply_entry(req, &e, err);
}


static void fuse_lib_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
                          const char *newname)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_entry_param e;
    char *oldpath;
    char *newpath;
    int err;

    err = get_path2(f, ino, NULL, newparent, newname,
        &oldpath, &newpath, NULL, NULL);
    if (!err) {
        struct fuse_intr_data d;

        fuse_prepare_interrupt(f, req, &d);
        err = fuse_fs_link(NULL, f->fs, oldpath, newpath);
        if (!err && err != FUSE_LIB_ERROR_PENDING_REQ)
            err = lookup_path(NULL, f, newparent, newname, newpath,
            &e, NULL);
        fuse_finish_interrupt(f, req, &d);
        free_path2(f, ino, newparent, NULL, NULL, oldpath, newpath);
    }
    // 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
    // 		fuse_async_add_pending(NULL,f, req, ino, FUSE_LINK);
    //         return;
    //     }
    reply_entry(req, &e, err);
}




static void fuse_lib_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
			   struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path_nullok(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;

		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_fsync(NULL, f->fs, path, datasync, fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_FSYNC);
//         return;
//     }
	reply_err(req, err);
}

static void fuse_lib_opendir(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *llfi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	struct fuse_dh *dh;
	struct fuse_file_info fi;
	char *path;
	int err;

	dh = (struct fuse_dh *) fuse_malloc(sizeof(struct fuse_dh));
	if (dh == NULL) {
		reply_err(req, -ENOMEM);
		return;
	}
	memset(dh, 0, sizeof(struct fuse_dh));
	dh->fuse = f;
	dh->contents = NULL;
	dh->first = NULL;
	dh->len = 0;
	dh->filled = 0;
	dh->nodeid = ino;
	fuse_mutex_init(&dh->lock);

	llfi->fh = (uintptr_t) dh;

	memset(&fi, 0, sizeof(fi));
	fi.flags = llfi->flags;

	err = get_path(f, ino, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_opendir(NULL, f->fs, path, &fi);
		fuse_finish_interrupt(f, req, &d);
		dh->fh = fi.fh;
	}
// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_READDIR);
// 		pthread_mutex_destroy(&dh->lock);
// 		free_path(f, ino, path);
//         return;
//     }

	if (!err) {
		if (fuse_reply_open(req, llfi) == -ENOENT) {
			/* The opendir syscall was interrupted, so it
			   must be cancelled */
			fuse_fs_releasedir(NULL, f->fs, path, &fi);
			pthread_mutex_destroy(&dh->lock);
			fuse_free(dh);
		}
	} else {
		reply_err(req, err);
		pthread_mutex_destroy(&dh->lock);
		fuse_free(dh);
	}
	free_path(f, ino, path);
}

static void fuse_lib_releasedir(fuse_req_t req, fuse_ino_t ino,
				struct fuse_file_info *llfi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	struct fuse_file_info fi;
	struct fuse_dh *dh = get_dirhandle(llfi, &fi);
	char *path;

	get_path_nullok(f, ino, &path);

	fuse_prepare_interrupt(f, req, &d);
	fuse_fs_releasedir(NULL, f->fs, path, &fi);
	fuse_finish_interrupt(f, req, &d);
	free_path(f, ino, path);

	pthread_mutex_lock(&dh->lock);
	pthread_mutex_unlock(&dh->lock);
	pthread_mutex_destroy(&dh->lock);
	free_direntries(dh->first);
	fuse_free(dh->contents);
	fuse_free(dh);
// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_RELEASEDIR);
//         return;
//     }
	reply_err(req, 0);
}

static void fuse_lib_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
			      struct fuse_file_info *llfi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_file_info fi;
	char *path;
	int err;

	get_dirhandle(llfi, &fi);

	err = get_path_nullok(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_fsyncdir(NULL, f->fs, path, datasync, &fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_FSYNCDIR);
//         return;
//     }
	reply_err(req, err);
}

static void fuse_lib_statfs(fuse_req_t req, fuse_ino_t ino)
{
	struct fuse *f = req_fuse_prepare(req);
	struct statvfs buf;
	char *path = NULL;
	int err = 0;

	memset(&buf, 0, sizeof(buf));
	if (ino)
		err = get_path(f, ino, &path);

	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_statfs(NULL, f->fs, path ? path : "/", &buf);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}

// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_STATFS);
//         return;
//     }
	if (!err)
		fuse_reply_statfs(req, &buf);
	else
		reply_err(req, err);
}

static void fuse_lib_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
			      const char *value, size_t size, int flags)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_setxattr(NULL, f->fs, path, name, value, size, flags);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_SETXATTR);
//         return;
//     }

	reply_err(req, err);
}

static int common_getxattr(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
                           const char *name, char *value, size_t size)
{
    int err;
    char *path;

    err = get_path(f, ino, &path);
    if (!err) {
        struct fuse_intr_data d;
        fuse_prepare_interrupt(f, req, &d);
        err = fuse_fs_getxattr(NULL, f->fs, path, name, value, size);
        fuse_finish_interrupt(f, req, &d);
        free_path(f, ino, path);
    }
    return err;
}

static int common_listxattr(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
                            char *list, size_t size)
{
    char *path;
    int err;

    err = get_path(f, ino, &path);
    if (!err) {
        struct fuse_intr_data d;
        fuse_prepare_interrupt(f, req, &d);
        err = fuse_fs_listxattr(NULL, f->fs, path, list, size);
        fuse_finish_interrupt(f, req, &d);
        free_path(f, ino, path);
    }
    return err;
}


static void fuse_lib_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                              size_t size)
{
    struct fuse *f = req_fuse_prepare(req);
    int res;
    char *value = NULL;
    if (size) {
        char *value = (char *) fuse_malloc(size);
        if (value == NULL) {
            reply_err(req, -ENOMEM);
            return;
        }
    }

    res = common_getxattr(f, req, ino, name, value, size);
    // 	if (res == FUSE_LIB_ERROR_PENDING_REQ){
    // 		fuse_async_add_pending(NULL,f, req, ino, FUSE_GETXATTR);
    // 		if (value)
    // 			fuse_free(value);
    //         return;
    //     }

    if (size && res > 0)
        fuse_reply_buf(req, value, res);
    else if(!size && res >= 0)
        fuse_reply_xattr(req, res);
    else
        reply_err(req, res);

    if (value)
        fuse_free(value);
}

static void fuse_lib_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
    struct fuse *f = req_fuse_prepare(req);
    int res;
    char *list = NULL;
    if (size) {
        list = (char *) fuse_malloc(size);
        if (list == NULL) {
            reply_err(req, -ENOMEM);
            return;
        }
    }
    res = common_listxattr(f, req, ino, list, size);
    // 	if (res == FUSE_LIB_ERROR_PENDING_REQ){
    // 		fuse_async_add_pending(NULL,f, req, ino, FUSE_LISTXATTR);
    // 		if (list)
    // 			fuse_free(list);
    //         return;
    //     }

    if (size && res > 0)
        fuse_reply_buf(req, list, res);
    else if(!size && res >= 0)
        fuse_reply_xattr(req, res);
    else
        reply_err(req, res);

    if (size)
        fuse_free(list);

}

static void fuse_lib_removexattr(fuse_req_t req, fuse_ino_t ino,
                                 const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = get_path(f, ino, &path);
    if (!err) {
        struct fuse_intr_data d;
        fuse_prepare_interrupt(f, req, &d);
        err = fuse_fs_removexattr(NULL, f->fs, path, name);
        fuse_finish_interrupt(f, req, &d);
        free_path(f, ino, path);
    }
    // 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
    // 		fuse_async_add_pending(NULL,f, req, ino, FUSE_REMOVEXATTR);
    //         return;
    //     }
    reply_err(req, err);
}
int fuse_flush_common(struct fuse *f, fuse_req_t req, fuse_ino_t ino,
			     const char *path, struct fuse_file_info *fi)
{
	struct fuse_intr_data d;
	struct flock lock;
	struct lock l;
	int err;
	int errlock;

	fuse_prepare_interrupt(f, req, &d);
	memset(&lock, 0, sizeof(lock));
	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	err = fuse_fs_flush(NULL, f->fs, path, fi);
	errlock = fuse_fs_lock(NULL, f->fs, path, fi, F_SETLK, &lock);
	fuse_finish_interrupt(f, req, &d);

	if (errlock != -ENOSYS) {
		flock_to_lock(&lock, &l);
		l.owner = fi->lock_owner;
		pthread_mutex_lock(&f->lock);
		locks_insert(get_node(f, ino), &l);
		pthread_mutex_unlock(&f->lock);

		/* if op.lock() is defined FLUSH is needed regardless
		   of op.flush() */
		if (err == -ENOSYS)
			err = 0;
	}
	return err;
}



// static void fuse_lib_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
// {
//     struct fuse *f = req_fuse_prepare(req);
//     struct fuse_intr_data d;
//     char *path;
//     int err = 0;
// 
//     get_path_nullok(f, ino, &path);
//     if (fi->flush) {
//         err = fuse_flush_common(f, req, ino, path, fi);
//         if (err == -ENOSYS)
//             err = 0;
//     }
// 
//     fuse_prepare_interrupt(f, req, &d);
//     fuse_do_release(f, ino, path, fi);
//     fuse_finish_interrupt(f, req, &d);
//     free_path(f, ino, path);
// 
//     // 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
//     // 		fuse_async_add_pending(NULL,f, req, ino, FUSE_RELEASE);
//     //         return;
//     //     }
//     reply_err(req, err);
// }

static void fuse_lib_flush(fuse_req_t req, fuse_ino_t ino,
struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    get_path_nullok(f, ino, &path);
    err = fuse_flush_common(f, req, ino, path, fi);
    free_path(f, ino, path);

    reply_err(req, err);
}

/*FixMe: looks messy*/
static void fuse_lib_getlk(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, struct flock *lock)
{
	int err;
	struct lock l;
	struct lock *conflict;
	struct fuse *f = req_fuse(req);

	flock_to_lock(lock, &l);
	l.owner = fi->lock_owner;
	pthread_mutex_lock(&f->lock);
	conflict = locks_conflict(get_node(f, ino), &l);
	if (conflict)
		lock_to_flock(conflict, lock);
	pthread_mutex_unlock(&f->lock);
	if (!conflict)
		err = fuse_lock_common(NULL, req, ino, fi, lock, F_GETLK);
	else
		err = 0;

	if (!err)
		fuse_reply_lock(req, lock);
	else
		reply_err(req, err);
}
/*FixMe: looks messy*/
static void fuse_lib_setlk(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, struct flock *lock,
			   int sleep)
{
	int err = fuse_lock_common(NULL, req, ino, fi, lock,
				   sleep ? F_SETLKW : F_SETLK);
	if (!err) {
		struct fuse *f = req_fuse(req);
		struct lock l;
		flock_to_lock(lock, &l);
		l.owner = fi->lock_owner;
		pthread_mutex_lock(&f->lock);
		locks_insert(get_node(f, ino), &l);
		pthread_mutex_unlock(&f->lock);
	}
	reply_err(req, err);
}
static void fuse_lib_flock(fuse_req_t req, fuse_ino_t ino,
			   struct fuse_file_info *fi, int op)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path_nullok(f, ino, &path);
	if (err == 0) {
		struct fuse_intr_data d;
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_flock(NULL, f->fs, path, fi, op);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
/*FixMe: uses from setctl()
	if (err == FUSE_LIB_ERROR_PENDING_REQ){
		fuse_lib_add_pending(f, req, ino, FUSE_FLOCK);
        return;
    }
*/
	reply_err(req, err);
}

static void fuse_lib_bmap(fuse_req_t req, fuse_ino_t ino, size_t blocksize,
			  uint64_t idx)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path;
	int err;

	err = get_path(f, ino, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_bmap(NULL, f->fs, path, blocksize, &idx);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_BMAP);
//         return;
//     }
	if (!err)
		fuse_reply_bmap(req, idx);
	else
		reply_err(req, err);
}

static void fuse_lib_ioctl(fuse_req_t req, fuse_ino_t ino, int cmd, void *arg,
			   struct fuse_file_info *llfi, unsigned int flags,
			   const void *in_buf, size_t in_bufsz,
			   size_t out_bufsz)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	struct fuse_file_info fi;
	char *path, *out_buf = NULL;
	int err;

	err = -EPERM;
	if (flags & FUSE_IOCTL_UNRESTRICTED)
		goto err;

	if (flags & FUSE_IOCTL_DIR)
		get_dirhandle(llfi, &fi);
	else
		fi = *llfi;

	if (out_bufsz) {
		err = -ENOMEM;
		out_buf = fuse_malloc(out_bufsz);
		if (!out_buf)
			goto err;
	}

	assert(!in_bufsz || !out_bufsz || in_bufsz == out_bufsz);
	if (out_buf)
		memcpy(out_buf, in_buf, in_bufsz);

	err = get_path_nullok(f, ino, &path);
	if (err)
		goto err;

	fuse_prepare_interrupt(f, req, &d);

	err = fuse_fs_ioctl(NULL, f->fs, path, cmd, arg, &fi, flags,
			    out_buf ?: (void *)in_buf);

	fuse_finish_interrupt(f, req, &d);
	free_path(f, ino, path);
// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_IOCTL);
// 		fuse_free(out_buf);
//         return;
//     }

	fuse_reply_ioctl(req, err, out_buf, out_bufsz);
	goto out;
err:
	reply_err(req, err);
out:
	fuse_free(out_buf);
}

static void fuse_lib_poll(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi, struct fuse_pollhandle *ph)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path;
	int err;
	unsigned revents = 0;

	err = get_path_nullok(f, ino, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_poll(NULL, f->fs, path, fi, ph, &revents);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_POLL);
//         return;
//     }
	if (!err)
		fuse_reply_poll(req, revents);
	else
		reply_err(req, err);
}

static void fuse_lib_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
		off_t offset, off_t length, struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	struct fuse_intr_data d;
	char *path;
	int err;

	err = get_path_nullok(f, ino, &path);
	if (!err) {
		fuse_prepare_interrupt(f, req, &d);
		err = fuse_fs_fallocate(NULL, f->fs, path, mode, offset, length, fi);
		fuse_finish_interrupt(f, req, &d);
		free_path(f, ino, path);
	}
// 	if (err == FUSE_LIB_ERROR_PENDING_REQ){
// 		fuse_async_add_pending(NULL,f, req, ino, FUSE_FALLOCATE);
//         return;
//     }
	reply_err(req, err);
}


struct fuse_lowlevel_ops fuse_path_ops = {
    .init = fuse_lib_init,
    .destroy = fuse_lib_destroy,
    .lookup = fuse_lib_lookup,
    .forget = fuse_lib_forget,
    .forget_multi = fuse_lib_forget_multi,
    .getattr = fuse_lib_getattr,
    .setattr = fuse_lib_setattr,
    .access = fuse_lib_access,
    .readlink = fuse_lib_readlink,
    .mknod = fuse_lib_mknod,
    .mkdir = fuse_lib_mkdir,
    .unlink = fuse_lib_unlink,
    .rmdir = fuse_lib_rmdir,
    .symlink = fuse_lib_symlink,
    .rename = fuse_lib_rename,
    .link = fuse_lib_link,
    .create = fuse_lib_create,
    .open = fuse_lib_open,
    .read = fuse_lib_read,
    .write_buf = fuse_lib_write_buf,
    .flush = fuse_lib_flush,
    .release = fuse_lib_release,
    .fsync = fuse_lib_fsync,
    .opendir = fuse_lib_opendir,
    .readdir = fuse_lib_readdir,
    .readdirplus = fuse_lib_readdirplus,
    .releasedir = fuse_lib_releasedir,
    .fsyncdir = fuse_lib_fsyncdir,
    .statfs = fuse_lib_statfs,
    .setxattr = fuse_lib_setxattr,
    .getxattr = fuse_lib_getxattr,
    .listxattr = fuse_lib_listxattr,
    .removexattr = fuse_lib_removexattr,
    .getlk = fuse_lib_getlk,
    .setlk = fuse_lib_setlk,
    .flock = fuse_lib_flock,
    .bmap = fuse_lib_bmap,
    .ioctl = fuse_lib_ioctl,
    .poll = fuse_lib_poll,
    .fallocate = fuse_lib_fallocate,
};
