## Process this file with automake to produce Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/include -DFUSERMOUNT_DIR=\"$(bindir)\" \
 -D_REENTRANT -DFUSE_USE_VERSION=30

lib_LTLIBRARIES = libfuse3.la

if BSD
mount_source = mount_bsd.c
else
mount_source = mount.c mount_util.c mount_util.h
endif

if ICONV
iconv_source = modules/iconv.c
else
iconv_source =
endif

libfuse3_la_SOURCES = 		\
	fuse_mem.c \
	fuse_log.c \
  	fuse_lib_getxattr.c \
	hide_node.c \
	fuse_lib_rename.c \
	fuse_lib_unlink.c \
	fuse_lib_rmdir.c \
	fuse_lib_mkdir.c \
	fuse_lib_write_buf.c \
  fuse_lib_create.c \
	fuse_lib_setattr.c \
	fuse_lib_release.c \
	fuse_lib_open.c \
	fuse_lib_read.c \
	fuse_lib_lookup.c \
	fuse_lib_lookup_path.c \
	fuse_lib_getattr.c \
	fuse_lib_access.c \
	fuse_lib_readdir.c \
	fuse_fsm.c			\
	fuse_interrupt.c			\
	fuse_lock.c  \
	fuse_module.c  \
	fuse_node.c  \
	fuse_path.c  \
	fuse_queue_element.c\
	fuse_lib_context.c \
	fuse_id_hash.c \
	fuse_req.c \ 
	fuse_list.c \ 
	fuse_fs.c			\
	fuse_lib.c			\
	fuse.c			\
	fuse_i.h		\
	fuse_loop.c		\
	fuse_loop_async.c	\
	fuse_loop_mt.c		\
	fuse_lowlevel.c		\
	fuse_misc.h		\
	fuse_mt.c		\
	fuse_opt.c		\
	fuse_session.c		\
	fuse_signals.c		\
	buffer.c		\
	cuse_lowlevel.c		\
	helper.c		\
	modules/subdir.c	\
	$(iconv_source)		\
	$(mount_source)

libfuse3_la_LDFLAGS = -pthread @libfuse_libs@ -version-number 0:0:0 \
	-Wl,--version-script,$(srcdir)/fuse_versionscript

if NETBSD
libfuse3_la_LIBADD = -lperfuse -lpuffs
endif

EXTRA_DIST = fuse_versionscript
