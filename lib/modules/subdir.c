/*
  fuse subdir module: offset paths with a base directory
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

struct subdir {
	char *base;
	size_t baselen;
	int rellinks;
	struct fuse_fs *next;
};

static struct subdir *subdir_get(void)
{
	return fuse_get_context()->private_data;
}

static int subdir_addpath(struct subdir *d, const char *path, char **newpathp)
{
	char *newpath = NULL;

	if (path != NULL) {
		unsigned newlen = d->baselen + strlen(path);

		newpath = malloc(newlen + 2);
		if (!newpath)
			return -ENOMEM;

		if (path[0] == '/')
			path++;
		strcpy(newpath, d->base);
		strcpy(newpath + d->baselen, path);
		if (!newpath[0])
			strcpy(newpath, ".");
	}
	*newpathp = newpath;

	return 0;
}

static int subdir_getattr( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct stat *stbuf)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_getattr(fsm, d->next, newpath, stbuf);
		free(newpath);
	}
	return err;
}

static int subdir_fgetattr( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_fgetattr(fsm, d->next, newpath, stbuf, fi);
		free(newpath);
	}
	return err;
}

static int subdir_access( struct fuse_fsm* fsm __attribute__((unused)), const char *path, int mask)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_access(fsm, d->next, newpath, mask);
		free(newpath);
	}
	return err;
}


static int count_components(const char *p)
{
	int ctr;

	for (; *p == '/'; p++);
	for (ctr = 0; *p; ctr++) {
		for (; *p && *p != '/'; p++);
		for (; *p == '/'; p++);
	}
	return ctr;
}

static void strip_common(const char **sp, const char **tp)
{
	const char *s = *sp;
	const char *t = *tp;
	do {
		for (; *s == '/'; s++);
		for (; *t == '/'; t++);
		*tp = t;
		*sp = s;
		for (; *s == *t && *s && *s != '/'; s++, t++);
	} while ((*s == *t && *s) || (!*s && *t == '/') || (*s == '/' && !*t));
}

static void transform_symlink(struct subdir *d, const char *path,
			      char *buf, size_t size)
{
	const char *l = buf;
	size_t llen;
	char *s;
	int dotdots;
	int i;

	if (l[0] != '/' || d->base[0] != '/')
		return;

	strip_common(&l, &path);
	if (l - buf < (long) d->baselen)
		return;

	dotdots = count_components(path);
	if (!dotdots)
		return;
	dotdots--;

	llen = strlen(l);
	if (dotdots * 3 + llen + 2 > size)
		return;

	s = buf + dotdots * 3;
	if (llen)
		memmove(s, l, llen + 1);
	else if (!dotdots)
		strcpy(s, ".");
	else
		*s = '\0';

	for (s = buf, i = 0; i < dotdots; i++, s += 3)
		memcpy(s, "../", 3);
}


static int subdir_readlink( struct fuse_fsm* fsm __attribute__((unused)), const char *path, char *buf, size_t size)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_readlink(fsm, d->next, newpath, buf, size);
		if (!err && d->rellinks)
			transform_symlink(d, newpath, buf, size);
		free(newpath);
	}
	return err;
}

static int subdir_opendir( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_opendir(fsm, d->next, newpath, fi);
		free(newpath);
	}
	return err;
}

static int subdir_readdir( struct fuse_fsm* fsm __attribute__((unused)), const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags )
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_readdir(fsm, d->next, newpath, buf, filler, offset,
				      fi, flags);
		free(newpath);
	}
	return err;
}

static int subdir_releasedir( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_releasedir(fsm, d->next, newpath, fi);
		free(newpath);
	}
	return err;
}

static int subdir_mknod( struct fuse_fsm* fsm __attribute__((unused)),const char *path, mode_t mode, dev_t rdev)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_mknod(fsm, d->next, newpath, mode, rdev);
		free(newpath);
	}
	return err;
}

static int subdir_mkdir( struct fuse_fsm* fsm __attribute__((unused)), const char *path, mode_t mode)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_mkdir(fsm, d->next, newpath, mode);
		free(newpath);
	}
	return err;
}

static int subdir_unlink( struct fuse_fsm* fsm __attribute__((unused)),const char *path)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_unlink(fsm, d->next, newpath);
		free(newpath);
	}
	return err;
}

static int subdir_rmdir( struct fuse_fsm* fsm __attribute__((unused)),const char *path)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_rmdir(fsm, d->next, newpath);
		free(newpath);
	}
	return err;
}

static int subdir_symlink( struct fuse_fsm* fsm __attribute__((unused)),const char *from, const char *path)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_symlink(fsm, d->next, from, newpath);
		free(newpath);
	}
	return err;
}

static int subdir_rename( struct fuse_fsm* fsm __attribute__((unused)), const char *from, const char *to, unsigned int flags)
{
	struct subdir *d = subdir_get();
	char *newfrom;
	char *newto;
	int err = subdir_addpath(d, from, &newfrom);
	if (!err) {
		err = subdir_addpath(d, to, &newto);
		if (!err) {
			err = fuse_fs_rename(fsm, d->next, newfrom, newto, flags);
			free(newto);
		}
		free(newfrom);
	}
	return err;
}

static int subdir_link( struct fuse_fsm* fsm __attribute__((unused)), const char *from, const char *to)
{
	struct subdir *d = subdir_get();
	char *newfrom;
	char *newto;
	int err = subdir_addpath(d, from, &newfrom);
	if (!err) {
		err = subdir_addpath(d, to, &newto);
		if (!err) {
			err = fuse_fs_link(fsm, d->next, newfrom, newto);
			free(newto);
		}
		free(newfrom);
	}
	return err;
}

static int subdir_chmod( struct fuse_fsm* fsm __attribute__((unused)), const char *path, mode_t mode)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_chmod(fsm, d->next, newpath, mode);
		free(newpath);
	}
	return err;
}

static int subdir_chown( struct fuse_fsm* fsm __attribute__((unused)), const char *path, uid_t uid, gid_t gid)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_chown(fsm, d->next, newpath, uid, gid);
		free(newpath);
	}
	return err;
}

static int subdir_truncate( struct fuse_fsm* fsm __attribute__((unused)), const char *path, off_t size)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_truncate(fsm, d->next, newpath, size);
		free(newpath);
	}
	return err;
}

static int subdir_ftruncate(struct fuse_fsm* fsm __attribute__((unused)), const char *path, off_t size,
			    struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_ftruncate(fsm, d->next, newpath, size, fi);
		free(newpath);
	}
	return err;
}

static int subdir_utimens( struct fuse_fsm* fsm __attribute__((unused)), const char *path, const struct timespec ts[2])
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_utimens(fsm, d->next, newpath, ts);
		free(newpath);
	}
	return err;
}

static int subdir_create( struct fuse_fsm* fsm __attribute__((unused)), const char *path, mode_t mode, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_create(fsm, d->next, newpath, mode, fi);
		free(newpath);
	}
	return err;
}

static int subdir_open( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_open(fsm, d->next, newpath, fi);
		free(newpath);
	}
	return err;
}

static int subdir_read_buf( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct fuse_bufvec **bufp, size_t size, off_t offset, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_read_buf(fsm, d->next, newpath, bufp, size, offset, fi);
		free(newpath);
	}
	return err;
}

static int subdir_write_buf( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct fuse_bufvec *buf, off_t offset, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_write_buf(fsm, d->next, newpath, buf, offset, fi);
		free(newpath);
	}
	return err;
}

static int subdir_statfs( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct statvfs *stbuf)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_statfs(fsm, d->next, newpath, stbuf);
		free(newpath);
	}
	return err;
}

static int subdir_flush( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_flush(fsm, d->next, newpath, fi);
		free(newpath);
	}
	return err;
}

static int subdir_release( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_release(fsm, d->next, newpath, fi);
		free(newpath);
	}
	return err;
}

static int subdir_fsync( struct fuse_fsm* fsm __attribute__((unused)), const char *path, int isdatasync, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_fsync(fsm, d->next, newpath, isdatasync, fi);
		free(newpath);
	}
	return err;
}

static int subdir_fsyncdir( struct fuse_fsm* fsm __attribute__((unused)), const char *path, int isdatasync, struct fuse_file_info *fi)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_fsyncdir(fsm, d->next, newpath, isdatasync, fi);
		free(newpath);
	}
	return err;
}

static int subdir_setxattr( struct fuse_fsm* fsm __attribute__((unused)), const char *path, const char *name, const char *value, size_t size, int flags)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_setxattr(fsm, d->next, newpath, name, value, size,
				       flags);
		free(newpath);
	}
	return err;
}

static int subdir_getxattr( struct fuse_fsm* fsm __attribute__((unused)), const char *path, const char *name, char *value, size_t size)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_getxattr(fsm, d->next, newpath, name, value, size);
		free(newpath);
	}
	return err;
}

static int subdir_listxattr( struct fuse_fsm* fsm __attribute__((unused)),const char *path, char *list, size_t size)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_listxattr(fsm, d->next, newpath, list, size);
		free(newpath);
	}
	return err;
}

static int subdir_removexattr( struct fuse_fsm* fsm __attribute__((unused)), const char *path, const char *name)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_removexattr(fsm, d->next, newpath, name);
		free(newpath);
	}
	return err;
}

static int subdir_lock( struct fuse_fsm* fsm __attribute__((unused)),const char *path, struct fuse_file_info *fi, int cmd, struct flock *lock)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_lock(fsm, d->next, newpath, fi, cmd, lock);
		free(newpath);
	}
	return err;
}

static int subdir_flock( struct fuse_fsm* fsm __attribute__((unused)), const char *path, struct fuse_file_info *fi, int op)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_flock(fsm, d->next, newpath, fi, op);
		free(newpath);
	}
	return err;
}

static int subdir_bmap(struct fuse_fsm* fsm __attribute__((unused)), const char *path, size_t blocksize, uint64_t *idx)
{
	struct subdir *d = subdir_get();
	char *newpath;
	int err = subdir_addpath(d, path, &newpath);
	if (!err) {
		err = fuse_fs_bmap(fsm, d->next, newpath, blocksize, idx);
		free(newpath);
	}
	return err;
}

static void *subdir_init(struct fuse_conn_info *conn)
{
	struct subdir *d = subdir_get();
	fuse_fs_init(d->next, conn);
	return d;
}

static void subdir_destroy(void *data)
{
	struct subdir *d = data;
	fuse_fs_destroy(d->next);
	free(d->base);
	free(d);
}

static const struct fuse_operations subdir_oper = {
	.destroy	= subdir_destroy,
	.init		= subdir_init,
	.getattr	= subdir_getattr,
	.fgetattr	= subdir_fgetattr,
	.access		= subdir_access,
	.readlink	= subdir_readlink,
	.opendir	= subdir_opendir,
	.readdir	= subdir_readdir,
	.releasedir	= subdir_releasedir,
	.mknod		= subdir_mknod,
	.mkdir		= subdir_mkdir,
	.symlink	= subdir_symlink,
	.unlink		= subdir_unlink,
	.rmdir		= subdir_rmdir,
	.rename		= subdir_rename,
	.link		= subdir_link,
	.chmod		= subdir_chmod,
	.chown		= subdir_chown,
	.truncate	= subdir_truncate,
	.ftruncate	= subdir_ftruncate,
	.utimens	= subdir_utimens,
	.create		= subdir_create,
	.open		= subdir_open,
	.read_buf	= subdir_read_buf,
	.write_buf	= subdir_write_buf,
	.statfs		= subdir_statfs,
	.flush		= subdir_flush,
	.release	= subdir_release,
	.fsync		= subdir_fsync,
	.fsyncdir	= subdir_fsyncdir,
	.setxattr	= subdir_setxattr,
	.getxattr	= subdir_getxattr,
	.listxattr	= subdir_listxattr,
	.removexattr	= subdir_removexattr,
	.lock		= subdir_lock,
	.flock		= subdir_flock,
	.bmap		= subdir_bmap,

	.flag_nopath = 1,
};

static const struct fuse_opt subdir_opts[] = {
	FUSE_OPT_KEY("-h", 0),
	FUSE_OPT_KEY("--help", 0),
	{ "subdir=%s", offsetof(struct subdir, base), 0 },
	{ "rellinks", offsetof(struct subdir, rellinks), 1 },
	{ "norellinks", offsetof(struct subdir, rellinks), 0 },
	FUSE_OPT_END
};

static void subdir_help(void)
{
	printf(
"    -o subdir=DIR	    prepend this directory to all paths (mandatory)\n"
"    -o [no]rellinks	    transform absolute symlinks to relative\n");
}

static int subdir_opt_proc(void *data, const char *arg, int key,
			   struct fuse_args *outargs)
{
	(void) data; (void) arg; (void) outargs;

	if (!key) {
		subdir_help();
		return -1;
	}

	return 1;
}

static struct fuse_fs *subdir_new(struct fuse_args *args,
				  struct fuse_fs *next[])
{
	struct fuse_fs *fs;
	struct subdir *d;

	d = calloc(1, sizeof(struct subdir));
	if (d == NULL) {
		fprintf(stderr, "fuse-subdir: memory allocation failed\n");
		return NULL;
	}

	if (fuse_opt_parse(args, d, subdir_opts, subdir_opt_proc) == -1)
		goto out_free;

	if (!next[0] || next[1]) {
		fprintf(stderr, "fuse-subdir: exactly one next filesystem required\n");
		goto out_free;
	}

	if (!d->base) {
		fprintf(stderr, "fuse-subdir: missing 'subdir' option\n");
		goto out_free;
	}

	if (d->base[0] && d->base[strlen(d->base)-1] != '/') {
		char *tmp = realloc(d->base, strlen(d->base) + 2);
		if (!tmp) {
			fprintf(stderr, "fuse-subdir: memory allocation failed\n");
			goto out_free;
		}
		d->base = tmp;
		strcat(d->base, "/");
	}
	d->baselen = strlen(d->base);
	d->next = next[0];
	fs = fuse_fs_new(&subdir_oper, sizeof(subdir_oper), d);
	if (!fs)
		goto out_free;
	return fs;

out_free:
	free(d->base);
	free(d);
	return NULL;
}

FUSE_REGISTER_MODULE(subdir, subdir_new);
