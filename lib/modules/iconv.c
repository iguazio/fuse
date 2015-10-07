/*
  fuse iconv module: file name charset conversion
  Copyright (C) 2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#define FUSE_USE_VERSION 30

#include <config.h>

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <iconv.h>
#include <pthread.h>
#include <locale.h>
#include <langinfo.h>

struct iconv {
	struct fuse_fs *next;
	pthread_mutex_t lock;
	char *from_code;
	char *to_code;
	iconv_t tofs;
	iconv_t fromfs;
};

struct iconv_dh {
	struct iconv *ic;
	void *prev_buf;
	fuse_fill_dir_t prev_filler;
};

static struct iconv *iconv_get(void)
{
	return fuse_get_context()->private_data;
}

static int iconv_convpath(struct iconv *ic, const char *path, char **newpathp,
			  int fromfs)
{
	size_t pathlen;
	size_t newpathlen;
	char *newpath;
	size_t plen;
	char *p;
	size_t res;
	int err;

	if (path == NULL) {
		*newpathp = NULL;
		return 0;
	}

	pathlen = strlen(path);
	newpathlen = pathlen * 4;
	newpath = fuse_malloc(newpathlen + 1);
	if (!newpath)
		return -ENOMEM;

	plen = newpathlen;
	p = newpath;
	pthread_mutex_lock(&ic->lock);
	do {
		res = iconv(fromfs ? ic->fromfs : ic->tofs, (char **) &path,
			    &pathlen, &p, &plen);
		if (res == (size_t) -1) {
			char *tmp;
			size_t inc;

			err = -EILSEQ;
			if (errno != E2BIG)
				goto err;

			inc = (pathlen + 1) * 4;
			newpathlen += inc;
			tmp = fuse_realloc(newpath, newpathlen + 1);
			err = -ENOMEM;
			if (!tmp)
				goto err;

			p = tmp + (p - newpath);
			plen += inc;
			newpath = tmp;
		}
	} while (res == (size_t) -1);
	pthread_mutex_unlock(&ic->lock);
	*p = '\0';
	*newpathp = newpath;
	return 0;

err:
	iconv(fromfs ? ic->fromfs : ic->tofs, NULL, NULL, NULL, NULL);
	pthread_mutex_unlock(&ic->lock);
	fuse_free(newpath);
	return err;
}

static int iconv_getattr(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct stat *stbuf)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_getattr(fsm, ic->next, newpath, stbuf);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_fgetattr(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct stat *stbuf,
			  struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_fgetattr(fsm, ic->next, newpath, stbuf, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_access(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, int mask)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_access(fsm, ic->next, newpath, mask);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_readlink(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, char *buf, size_t size)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_readlink(fsm, ic->next, newpath, buf, size);
		if (!err) {
			char *newlink;
			err = iconv_convpath(ic, buf, &newlink, 1);
			if (!err) {
				strncpy(buf, newlink, size - 1);
				buf[size - 1] = '\0';
				fuse_free(newlink);
			}
		}
		fuse_free(newpath);
	}
	return err;
}

static int iconv_opendir(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_opendir(fsm, ic->next, newpath, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_dir_fill(void *buf, const char *name,
			  const struct stat *stbuf, off_t off,
			  enum fuse_fill_dir_flags flags)
{
	struct iconv_dh *dh = buf;
	char *newname;
	int res = 0;
	if (iconv_convpath(dh->ic, name, &newname, 1) == 0) {
		res = dh->prev_filler(dh->prev_buf, newname, stbuf, off, flags);
		fuse_free(newname);
	}
	return res;
}

static int iconv_readdir(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, void *buf, fuse_fill_dir_t filler __attribute__ ((unused)),
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		struct iconv_dh dh;
		dh.ic = ic;
		dh.prev_buf = buf;
		dh.prev_filler = iconv_dir_fill;
		err = fuse_fs_readdir(fsm, ic->next, newpath, &dh, filler,
				      offset, fi, flags);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_releasedir(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_releasedir(fsm, ic->next, newpath, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_mknod(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, mode_t mode, dev_t rdev)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_mknod(fsm, ic->next, newpath, mode, rdev);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_mkdir(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, mode_t mode)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_mkdir(fsm, ic->next, newpath, mode);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_unlink(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_unlink(fsm, ic->next, newpath);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_rmdir(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_rmdir(fsm, ic->next, newpath);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_symlink(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *from, const char *to)
{
	struct iconv *ic = iconv_get();
	char *newfrom;
	char *newto;
	int err = iconv_convpath(ic, from, &newfrom, 0);
	if (!err) {
		err = iconv_convpath(ic, to, &newto, 0);
		if (!err) {
			err = fuse_fs_symlink(fsm, ic->next, newfrom, newto);
			fuse_free(newto);
		}
		fuse_free(newfrom);
	}
	return err;
}

static int iconv_rename(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *from, const char *to, unsigned int flags)
{
	struct iconv *ic = iconv_get();
	char *newfrom;
	char *newto;
	int err = iconv_convpath(ic, from, &newfrom, 0);
	if (!err) {
		err = iconv_convpath(ic, to, &newto, 0);
		if (!err) {
			err = fuse_fs_rename(fsm, ic->next, newfrom, newto, flags);
			fuse_free(newto);
		}
		fuse_free(newfrom);
	}
	return err;
}

static int iconv_link(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *from, const char *to)
{
	struct iconv *ic = iconv_get();
	char *newfrom;
	char *newto;
	int err = iconv_convpath(ic, from, &newfrom, 0);
	if (!err) {
		err = iconv_convpath(ic, to, &newto, 0);
		if (!err) {
			err = fuse_fs_link(fsm, ic->next, newfrom, newto);
			fuse_free(newto);
		}
		fuse_free(newfrom);
	}
	return err;
}

static int iconv_chmod(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, mode_t mode)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_chmod(fsm, ic->next, newpath, mode);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_chown(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, uid_t uid, gid_t gid)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_chown(fsm, ic->next, newpath, uid, gid);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_truncate(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, off_t size)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_truncate(fsm, ic->next, newpath, size);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_ftruncate(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, off_t size,
			   struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_ftruncate(fsm, ic->next, newpath, size, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_utimens(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, const struct timespec ts[2])
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_utimens(fsm, ic->next, newpath, ts);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_create(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, mode_t mode,
			struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_create(fsm, ic->next, newpath, mode, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_open_file(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_open(fsm, ic->next, newpath, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_read_buf(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct fuse_bufvec **bufp,
			  size_t size, off_t offset, struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_read_buf(fsm, ic->next, newpath, bufp, size, offset, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_write_buf(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct fuse_bufvec *buf,
			   off_t offset, struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_write_buf(fsm, ic->next, newpath, buf, offset, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_statfs(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct statvfs *stbuf)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_statfs(fsm, ic->next, newpath, stbuf);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_flush(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_flush(fsm, ic->next, newpath, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_release(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_release(fsm, ic->next, newpath, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_fsync(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, int isdatasync,
		       struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_fsync(fsm, ic->next, newpath, isdatasync, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_fsyncdir(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, int isdatasync,
			  struct fuse_file_info *fi)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_fsyncdir(fsm, ic->next, newpath, isdatasync, fi);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_setxattr(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, const char *name,
			  const char *value, size_t size, int flags)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_setxattr(fsm, ic->next, newpath, name, value, size,
				       flags);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_getxattr(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, const char *name, char *value,
			  size_t size)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_getxattr(fsm, ic->next, newpath, name, value, size);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_listxattr(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, char *list, size_t size)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_listxattr(fsm, ic->next, newpath, list, size);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_removexattr(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, const char *name)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_removexattr(fsm, ic->next, newpath, name);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_lock(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct fuse_file_info *fi, int cmd,
		      struct flock *lock)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_lock(fsm, ic->next, newpath, fi, cmd, lock);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_flock(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, struct fuse_file_info *fi, int op)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_flock(fsm, ic->next, newpath, fi, op);
		fuse_free(newpath);
	}
	return err;
}

static int iconv_bmap(struct fuse_fsm* fsm __attribute__ ((unused)),  const char *path, size_t blocksize, uint64_t *idx)
{
	struct iconv *ic = iconv_get();
	char *newpath;
	int err = iconv_convpath(ic, path, &newpath, 0);
	if (!err) {
		err = fuse_fs_bmap(fsm, ic->next, newpath, blocksize, idx);
		fuse_free(newpath);
	}
	return err;
}

static void *iconv_init( struct fuse_conn_info *conn)
{
	struct iconv *ic = iconv_get();
	fuse_fs_init(ic->next, conn);
	return ic;
}

static void iconv_destroy(void *data)
{
	struct iconv *ic = data;
	fuse_fs_destroy(ic->next);
	iconv_close(ic->tofs);
	iconv_close(ic->fromfs);
	pthread_mutex_destroy(&ic->lock);
	fuse_free(ic->from_code);
	fuse_free(ic->to_code);
	fuse_free(ic);
}

static const struct fuse_operations iconv_oper = {
	.destroy	= iconv_destroy,
	.init		= iconv_init,
	.getattr	= iconv_getattr,
	.fgetattr	= iconv_fgetattr,
	.access		= iconv_access,
	.readlink	= iconv_readlink,
	.opendir	= iconv_opendir,
	.readdir	= iconv_readdir,
	.releasedir	= iconv_releasedir,
	.mknod		= iconv_mknod,
	.mkdir		= iconv_mkdir,
	.symlink	= iconv_symlink,
	.unlink		= iconv_unlink,
	.rmdir		= iconv_rmdir,
	.rename		= iconv_rename,
	.link		= iconv_link,
	.chmod		= iconv_chmod,
	.chown		= iconv_chown,
	.truncate	= iconv_truncate,
	.ftruncate	= iconv_ftruncate,
	.utimens	= iconv_utimens,
	.create		= iconv_create,
	.open		= iconv_open_file,
	.read_buf	= iconv_read_buf,
	.write_buf	= iconv_write_buf,
	.statfs		= iconv_statfs,
	.flush		= iconv_flush,
	.release	= iconv_release,
	.fsync		= iconv_fsync,
	.fsyncdir	= iconv_fsyncdir,
	.setxattr	= iconv_setxattr,
	.getxattr	= iconv_getxattr,
	.listxattr	= iconv_listxattr,
	.removexattr	= iconv_removexattr,
	.lock		= iconv_lock,
	.flock		= iconv_flock,
	.bmap		= iconv_bmap,

	.flag_nopath = 1,
};

static const struct fuse_opt iconv_opts[] = {
	FUSE_OPT_KEY("-h", 0),
	FUSE_OPT_KEY("--help", 0),
	{ "from_code=%s", offsetof(struct iconv, from_code), 0 },
	{ "to_code=%s", offsetof(struct iconv, to_code), 1 },
	FUSE_OPT_END
};

static void iconv_help(void)
{
	char *old = fuse_strdup(setlocale(LC_CTYPE, ""));
	char *charmap = fuse_strdup(nl_langinfo(CODESET));
	setlocale(LC_CTYPE, old);
	fuse_free(old);
	printf(
"    -o from_code=CHARSET   original encoding of file names (default: UTF-8)\n"
"    -o to_code=CHARSET	    new encoding of the file names (default: %s)\n",
		charmap);
	fuse_free(charmap);
}

static int iconv_opt_proc(void *data, const char *arg, int key,
			  struct fuse_args *outargs)
{
	(void) data; (void) arg; (void) outargs;

	if (!key) {
		iconv_help();
		return -1;
	}

	return 1;
}

static struct fuse_fs *iconv_new(struct fuse_args *args,
				 struct fuse_fs *next[])
{
	struct fuse_fs *fs;
	struct iconv *ic;
	char *old = NULL;
	const char *from;
	const char *to;

	ic = fuse_calloc(1, sizeof(struct iconv));
	if (ic == NULL) {
		fprintf(stderr, "fuse-iconv: memory allocation failed\n");
		return NULL;
	}

	if (fuse_opt_parse(args, ic, iconv_opts, iconv_opt_proc) == -1)
		goto out_free;

	if (!next[0] || next[1]) {
		fprintf(stderr, "fuse-iconv: exactly one next filesystem required\n");
		goto out_free;
	}

	from = ic->from_code ? ic->from_code : "UTF-8";
	to = ic->to_code ? ic->to_code : "";
	/* FIXME: detect charset equivalence? */
	if (!to[0])
		old = fuse_strdup(setlocale(LC_CTYPE, ""));
	ic->tofs = iconv_open(from, to);
	if (ic->tofs == (iconv_t) -1) {
		fprintf(stderr, "fuse-iconv: cannot convert from %s to %s\n",
			to, from);
		goto out_free;
	}
	ic->fromfs = iconv_open(to, from);
	if (ic->tofs == (iconv_t) -1) {
		fprintf(stderr, "fuse-iconv: cannot convert from %s to %s\n",
			from, to);
		goto out_iconv_close_to;
	}
	if (old) {
		setlocale(LC_CTYPE, old);
		fuse_free(old);
	}

	ic->next = next[0];
	fs = fuse_fs_new(&iconv_oper, sizeof(iconv_oper), ic);
	if (!fs)
		goto out_iconv_close_from;

	return fs;

out_iconv_close_from:
	iconv_close(ic->fromfs);
out_iconv_close_to:
	iconv_close(ic->tofs);
out_free:
	fuse_free(ic->from_code);
	fuse_free(ic->to_code);
	fuse_free(ic);
	if (old) {
		setlocale(LC_CTYPE, old);
		fuse_free(old);
	}
	return NULL;
}

FUSE_REGISTER_MODULE(iconv, iconv_new);
