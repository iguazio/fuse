/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

#include "config.h"
#include "fuse_i.h"
#include "fuse_misc.h"
#include "fuse_opt.h"
#include "fuse_lowlevel.h"
#include "fuse_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/param.h>

enum  {
	KEY_HELP,
	KEY_HELP_NOHEADER,
	KEY_VERSION,
};

struct helper_opts {
	int singlethread;
	int foreground;
	int nodefault_subtype;
	char *mountpoint;
};

#define FUSE_HELPER_OPT(t, p) { t, offsetof(struct helper_opts, p), 1 }

static const struct fuse_opt fuse_helper_opts[] = {
	FUSE_HELPER_OPT("-d",		foreground),
	FUSE_HELPER_OPT("debug",	foreground),
	FUSE_HELPER_OPT("-f",		foreground),
	FUSE_HELPER_OPT("-s",		singlethread),
	FUSE_HELPER_OPT("fsname=",	nodefault_subtype),
	FUSE_HELPER_OPT("subtype=",	nodefault_subtype),

	FUSE_OPT_KEY("-h",		KEY_HELP),
	FUSE_OPT_KEY("--help",		KEY_HELP),
	FUSE_OPT_KEY("-ho",		KEY_HELP_NOHEADER),
	FUSE_OPT_KEY("-V",		KEY_VERSION),
	FUSE_OPT_KEY("--version",	KEY_VERSION),
	FUSE_OPT_KEY("-d",		FUSE_OPT_KEY_KEEP),
	FUSE_OPT_KEY("debug",		FUSE_OPT_KEY_KEEP),
	FUSE_OPT_KEY("fsname=",		FUSE_OPT_KEY_KEEP),
	FUSE_OPT_KEY("subtype=",	FUSE_OPT_KEY_KEEP),
	FUSE_OPT_END
};

static void usage(const char *progname)
{
    fuse_log_err("usage: %s mountpoint [options]\n\n", progname);
    fuse_log_err("general options:\n"
	       "    -o opt,[opt...]        mount options\n"
	       "    -h   --help            print help\n"
	       "    -V   --version         print version\n"
	       "\n");
}

static void helper_help(void)
{
    fuse_log_err("FUSE options:\n"
	       "    -d   -o debug          enable debug output (implies -f)\n"
	       "    -f                     foreground operation\n"
	       "    -s                     disable multi-threaded operation\n"
	       "\n");
}

static void helper_version(void)
{
    fuse_log_err("FUSE library version: %s\n", PACKAGE_VERSION);
}

static int fuse_helper_opt_proc(void *data, const char *arg, int key,
				struct fuse_args *outargs)
{
	struct helper_opts *hopts = data;

	switch (key) {
	case KEY_HELP:
		usage(outargs->argv[0]);
		/* fall through */

	case KEY_HELP_NOHEADER:
		helper_help();
		return fuse_opt_add_arg(outargs, "-h");

	case KEY_VERSION:
		helper_version();
		return 1;

	case FUSE_OPT_KEY_NONOPT:
		if (!hopts->mountpoint) {
			char mountpoint[PATH_MAX];
			if (realpath(arg, mountpoint) == NULL) {
				fuse_log_err(
					"fuse: bad mount point `%s': %s\n",
					arg, strerror(errno));
				return -1;
			}
			return fuse_opt_add_opt(&hopts->mountpoint, mountpoint);
		} else {
			fuse_log_err( "fuse: invalid argument `%s'\n", arg);
			return -1;
		}

	default:
		return 1;
	}
}

static int add_default_subtype(const char *progname, struct fuse_args *args)
{
	int res;
	char *subtype_opt;
	const char *basename = strrchr(progname, '/');
	if (basename == NULL)
		basename = progname;
	else if (basename[1] != '\0')
		basename++;

	subtype_opt = (char *) fuse_malloc(strlen(basename) + 64);
	if (subtype_opt == NULL) {
		fuse_log_err( "fuse: memory allocation failed\n");
		return -1;
	}
	sprintf(subtype_opt, "-osubtype=%s", basename);
	res = fuse_opt_add_arg(args, subtype_opt);
	fuse_free(subtype_opt);
	return res;
}

int fuse_parse_cmdline(struct fuse_args *args, char **mountpoint,
		       int *multithreaded, int *foreground)
{
	int res;
	struct helper_opts hopts;

	memset(&hopts, 0, sizeof(hopts));
	res = fuse_opt_parse(args, &hopts, fuse_helper_opts,
			     fuse_helper_opt_proc);
	if (res == -1)
		return -1;

	if (!hopts.nodefault_subtype) {
		res = add_default_subtype(args->argv[0], args);
		if (res == -1)
			goto err;
	}
	if (mountpoint)
		*mountpoint = hopts.mountpoint;
	else
		fuse_free(hopts.mountpoint);

	if (multithreaded)
		*multithreaded = !hopts.singlethread;
	if (foreground)
		*foreground = hopts.foreground;
	return 0;

err:
	fuse_free(hopts.mountpoint);
	return -1;
}

int fuse_daemonize(int foreground)
{
	if (!foreground) {
		int nullfd;

		/*
		 * demonize current process by forking it and killing the
		 * parent.  This makes current process as a child of 'init'.
		 */
		switch(fork()) {
		case -1:
			perror("fuse_daemonize: fork");
			return -1;
		case 0:
			break;
		default:
			_exit(0);
		}

		if (setsid() == -1) {
			perror("fuse_daemonize: setsid");
			return -1;
		}

		(void) chdir("/");

		nullfd = open("/dev/null", O_RDWR, 0);
		if (nullfd != -1) {
			(void) dup2(nullfd, 0);
			(void) dup2(nullfd, 1);
			(void) dup2(nullfd, 2);
			if (nullfd > 2)
				close(nullfd);
		}
	} else {
		(void) chdir("/");
	}
	return 0;
}

struct fuse_chan *fuse_mount(const char *mountpoint, struct fuse_args *args)
{
	struct fuse_chan *ch;
	int fd;
	int fusermount_pid = -1;

	/*
	 * Make sure file descriptors 0, 1 and 2 are open, otherwise chaos
	 * would ensue.
	 */
	do {
		fd = open("/dev/null", O_RDWR);
		if (fd > 2)
			close(fd);
	} while (fd >= 0 && fd <= 2);

	fd = fuse_kern_mount(mountpoint, args, &fusermount_pid);
	if (fd == -1)
		return NULL;

	ch = fuse_chan_new(fd);
	if (!ch)
		fuse_kern_unmount(mountpoint, fd, fusermount_pid);
	else
		fuse_chan_set_fusermount_pid(ch, fusermount_pid);

	return ch;
}

void fuse_unmount(const char *mountpoint, struct fuse_chan *ch)
{
	if (mountpoint) {
		int fd = ch ? fuse_chan_clearfd(ch) : -1;
		fuse_kern_unmount(mountpoint, fd, fuse_chan_fusermount_pid(ch));
		if (ch)
			fuse_chan_destroy(ch);
	}
}

static struct fuse *fuse_setup(int argc, char *argv[],
			const struct fuse_operations *op, size_t op_size,
			char **mountpoint, int *multithreaded, void *user_data)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_chan *ch;
	struct fuse *fuse;
	int foreground;
	int res;

	res = fuse_parse_cmdline(&args, mountpoint, multithreaded, &foreground);
	if (res == -1)
		return NULL;

	ch = fuse_mount(*mountpoint, &args);
	if (!ch) {
		fuse_opt_free_args(&args);
		goto err_free;
	}

	fuse = fuse_new(ch, &args, op, op_size, user_data);
	fuse_opt_free_args(&args);
	if (fuse == NULL)
		goto err_unmount;

	res = fuse_daemonize(foreground);
	if (res == -1)
		goto err_unmount;

	res = fuse_set_signal_handlers(fuse_get_session(fuse));
	if (res == -1)
		goto err_unmount;

	return fuse;

err_unmount:
	fuse_unmount(*mountpoint, ch);
	if (fuse)
		fuse_destroy(fuse);
err_free:
	fuse_free(*mountpoint);
	return NULL;
}

static void fuse_teardown(struct fuse *fuse, char *mountpoint)
{
	struct fuse_session *se = fuse_get_session(fuse);
	struct fuse_chan *ch = fuse_session_chan(se);
	fuse_remove_signal_handlers(se);
	fuse_unmount(mountpoint, ch);
	fuse_destroy(fuse);
	fuse_free(mountpoint);
}

int fuse_main_real(int argc, char *argv[], const struct fuse_operations *op,
		   size_t op_size, void *user_data)
{
	struct fuse *fuse;
	char *mountpoint;
	int multithreaded;
	int res;

	fuse = fuse_setup(argc, argv, op, op_size, &mountpoint,
			  &multithreaded, user_data);
	if (fuse == NULL)
		return 1;

	if (multithreaded)
		res = fuse_loop_mt(fuse);
	else
		res = fuse_loop(fuse);

	fuse_teardown(fuse, mountpoint);
	if (res == -1)
		return 1;

	return 0;
}

int fuse_main_real_async(int argc, char *argv[], const struct fuse_operations *op,
                   size_t op_size, void *user_data,int fd, fuse_async_get_msg_t callback_on_new_msg, void* callback_payload)
{
    struct fuse *fuse;
    char *mountpoint;
    int multithreaded;
    int res;

    fuse = fuse_setup(argc, argv, op, op_size, &mountpoint,
        &multithreaded, user_data);
    if (fuse == NULL)
        return 1;
    
    res = fuse_loop_async(fuse,fd, callback_on_new_msg, callback_payload);

    fuse_teardown(fuse, mountpoint);

    if (res == -1)
        return 1;

    return 0;
}


int fuse_version(void)
{
	return FUSE_VERSION;
}

const char *fuse_pkgversion(void)
{
	return PACKAGE_VERSION;
}
