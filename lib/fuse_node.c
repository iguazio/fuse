#include <stdlib.h>
#include <errno.h>
#include "fuse_node.h"
#include "fuse_log.h"


void node_add_filehandle(struct node *n, uint64_t fh)
{
    if (n->fh == NULL) {
        if (n->open_count != 0) {
            fuse_log_err("add_node_filehandle expected open_count be 0, n->open_count=%u\n", n->open_count);
            return ;
        }
        n->fh = fuse_malloc(sizeof(uint64_t));
    }
    else {
        if (n->open_count == 0) {
            fuse_log_err("add_node_filehandle expected open_count larger then 0, n->open_count=%u\n", n->open_count);
            return ;
        }
        n->fh = fuse_realloc(n->fh, (sizeof(uint64_t) * (n->open_count + 1)));
    }
    n->fh[n->open_count] = fh;
    n->open_count++;
}


void node_remove_filehandle(struct node *n, uint64_t fh)
{
    if ((n->fh == NULL) || (n->open_count == 0)) {
        fuse_log_err("add_remove_filehandle expecting n->fh not null (%p) and n->open_count %d not 0\n",n->fh, n->open_count);
        return;
    }
    for (int i = 0; i < n->open_count; i++) {
        if (n->fh[i] == fh) {
            n->fh[i] = n->fh[n->open_count - 1];
            if (n->open_count == 1) {
                fuse_free(n->fh);
                n->fh = NULL;
            }else
                n->fh = fuse_realloc(n->fh, (sizeof(uint64_t) * (n->open_count - 1)));
            --n->open_count;
            return;
        }
    }
    --n->open_count;
    fuse_log_err("add_remove_filehandle handle %u not found,n->open_count=%d \n", fh, n->open_count);
}

struct node_lru * node_lru( struct node *node )
{
    return (struct node_lru *) node;
}

size_t get_node_size( struct fuse_config *f )
{
    if (lru_enabled(f))
        return sizeof(struct node_lru);
    else
        return sizeof(struct node);
}


// FixMe: I added it to simplify
// #undef FUSE_NODE_SLAB

#ifdef FUSE_NODE_SLAB
static struct node_slab *list_to_slab(struct list_head *head)
{
    return (struct node_slab *) head;
}

static struct node_slab *node_to_slab(struct fuse *f, struct node *node)
{
    return (struct node_slab *) (((uintptr_t) node) & ~((uintptr_t) f->pagesize - 1));
}

static int alloc_slab(struct fuse *f)
{
    void *mem;
    struct node_slab *slab;
    char *start;
    size_t num;
    size_t i;
    size_t node_size = get_node_size(&f->conf);

    mem = mmap(NULL, f->pagesize, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED)
        return -1;

    slab = mem;
    init_list_head(&slab->freelist);
    slab->used = 0;
    num = (f->pagesize - sizeof(struct node_slab)) / node_size;

    start = (char *) mem + f->pagesize - num * node_size;
    for (i = 0; i < num; i++) {
        struct list_head *n;

        n = (struct list_head *) (start + i * node_size);
        list_add_tail(n, &slab->freelist);
    }
    list_add_tail(&slab->list, &f->partial_slabs);

    return 0;
}

static struct node *alloc_node(struct fuse *f)
{
    struct node_slab *slab;
    struct list_head *node;

    if (list_empty(&f->partial_slabs)) {
        int res = alloc_slab(f);
        if (res != 0)
            return NULL;
    }
    slab = list_to_slab(f->partial_slabs.next);
    slab->used++;
    node = slab->freelist.next;
    list_del(node);
    if (list_empty(&slab->freelist)) {
        list_del(&slab->list);
        list_add_tail(&slab->list, &f->full_slabs);
    }
    memset(node, 0, sizeof(struct node));

    return (struct node *) node;
}

static void free_slab(struct fuse *f, struct node_slab *slab)
{
    int res;

    list_del(&slab->list);
    res = munmap(slab, f->pagesize);
    if (res == -1)
        fuse_log_err( "fuse warning: munmap(%p) failed\n", slab);
}

static void free_node_mem(struct fuse *f, struct node *node)
{
    struct node_slab *slab = node_to_slab(f, node);
    struct list_head *n = (struct list_head *) node;

    slab->used--;
    if (slab->used) {
        if (list_empty(&slab->freelist)) {
            list_del(&slab->list);
            list_add_tail(&slab->list, &f->partial_slabs);
        }
        list_add_head(n, &slab->freelist);
    } else {
        free_slab(f, slab);
    }
}
#else

struct node * alloc_node( struct fuse_config *f )
{
    return (struct node *) fuse_calloc(1, get_node_size(f));
}

void free_node_mem( struct fuse *f, struct node *node )
{
    (void) f;
    fuse_free(node);
}

#endif
