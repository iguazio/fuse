#pragma  once
#include "fuse_lib_context.h"
/* Defined by FUSE_REGISTER_MODULE() in lib/modules/subdir.c and iconv.c.  */
struct fusemod_so {
    void *handle;
    int ctr;
};

extern struct fuse_module *fuse_modules;

int fuse_register_module(const char *name,fuse_module_factory_t factory,struct fusemod_so *so);
int fuse_load_so_module(const char *module);
struct fuse_module *fuse_find_module(const char *module);
struct fuse_module *fuse_get_module(const char *module);
void fuse_put_module(struct fuse_module *m);


