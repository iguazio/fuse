#include <dlfcn.h>
#include <assert.h>
#include "fuse_module.h"
#include "fuse_i.h"

fuse_module_factory_t fuse_module_subdir_factory;
fuse_module_factory_t fuse_module_iconv_factory;
struct fuse_module *fuse_modules = NULL;

int fuse_register_module( const char *name, fuse_module_factory_t factory, struct fusemod_so *so )
{
    struct fuse_module *mod;

    mod = calloc(1, sizeof(struct fuse_module));
    if (!mod) {
        fprintf(stderr, "fuse: failed to allocate module\n");
        return -1;
    }
    mod->name = strdup(name);
    if (!mod->name) {
        fprintf(stderr, "fuse: failed to allocate module name\n");
        free(mod);
        return -1;
    }
    mod->factory = factory;
    mod->ctr = 0;
    mod->so = so;
    if (mod->so)
        mod->so->ctr++;
    mod->next = fuse_modules;
    fuse_modules = mod;

    return 0;
}

int fuse_load_so_module( const char *module )
{
    int ret = -1;
    char *tmp;
    struct fusemod_so *so;
    fuse_module_factory_t factory;

    tmp = malloc(strlen(module) + 64);
    if (!tmp) {
        fprintf(stderr, "fuse: memory allocation failed\n");
        return -1;
    }
    sprintf(tmp, "libfusemod_%s.so", module);
    so = calloc(1, sizeof(struct fusemod_so));
    if (!so) {
        fprintf(stderr, "fuse: failed to allocate module so\n");
        goto out;
    }

    so->handle = dlopen(tmp, RTLD_NOW);
    if (so->handle == NULL) {
        fprintf(stderr, "fuse: dlopen(%s) failed: %s\n",
            tmp, dlerror());
        goto out_free_so;
    }

    sprintf(tmp, "fuse_module_%s_factory", module);
    factory = dlsym(so->handle, tmp);
    if (factory == NULL) {
        fprintf(stderr, "fuse: symbol <%s> not found in module: %s\n",
            tmp, dlerror());
        goto out_dlclose;
    }
    ret = fuse_register_module(module, factory, so);
    if (ret)
        goto out_dlclose;

out:
    free(tmp);
    return ret;

out_dlclose:
    dlclose(so->handle);
out_free_so:
    free(so);
    goto out;
}

struct fuse_module * fuse_get_module( const char *module )
{
    struct fuse_module *m;

    pthread_mutex_lock(&fuse_context_lock);
    m = fuse_find_module(module);
    if (!m) {
        int err = fuse_load_so_module(module);
        if (!err)
            m = fuse_find_module(module);
    }
    pthread_mutex_unlock(&fuse_context_lock);
    return m;
}

void fuse_put_module( struct fuse_module *m )
{
    pthread_mutex_lock(&fuse_context_lock);
    assert(m->ctr > 0);
    m->ctr--;
    if (!m->ctr && m->so) {
        struct fusemod_so *so = m->so;
        assert(so->ctr > 0);
        so->ctr--;
        if (!so->ctr) {
            struct fuse_module **mp;
            for (mp = &fuse_modules; *mp;) {
                if ((*mp)->so == so)
                    *mp = (*mp)->next;
                else
                    mp = &(*mp)->next;
            }
            dlclose(so->handle);
            free(so);
        }
    }
    pthread_mutex_unlock(&fuse_context_lock);
}

struct fuse_module * fuse_find_module( const char *module )
{
    struct fuse_module *m;
    for (m = fuse_modules; m; m = m->next) {
        if (strcmp(module, m->name) == 0) {
            m->ctr++;
            break;
        }
    }
    return m;
}
