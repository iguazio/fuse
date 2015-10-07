#include "fuse_mem.h"

//#define PRINTOUT  printf
#define PRINTOUT(...)  

struct mem_descriptor{
    int line;
    const char* file;
    struct list_head node;
    char *data[0];
};

static struct list_head mem_allocs = {&mem_allocs,&mem_allocs};
static int ref_cntr = 0;

void* _fuse_malloc( size_t size,int line,const char* file )
{
    struct mem_descriptor *ptr = (struct mem_descriptor*)malloc(size + sizeof(struct mem_descriptor));
    ptr->line = line;
    ptr->file = file;
    list_add_head( &ptr->node, &mem_allocs);
    PRINTOUT("+%p\n",ptr->data);
    ref_cntr++;
    return (void*)ptr->data;
}

void* _fuse_calloc( size_t nmenb,size_t size,int line,const char* file )
{
    struct mem_descriptor *ptr = (struct mem_descriptor*)calloc(nmenb,size + sizeof(struct mem_descriptor));
    ptr->line = line;
    ptr->file = file;
    list_add_head( &ptr->node, &mem_allocs);
    ref_cntr++;
    PRINTOUT("+%p\n",ptr->data);
    return (void*)ptr->data;
}

void* _fuse_realloc( void *oldptr, size_t newsize,int line,const char* file )
{
    struct mem_descriptor *old_mptr;
    struct mem_descriptor *ptr;
    if (oldptr){
        old_mptr = (struct mem_descriptor *)(oldptr);
        old_mptr--;
        list_del(&old_mptr->node);
        ptr = (struct mem_descriptor*)realloc(old_mptr , newsize + sizeof(struct mem_descriptor));
        PRINTOUT("=%p->%p\n",old_mptr->data,ptr->data);

    }else{
        ref_cntr++;
        ptr = (struct mem_descriptor*)realloc(oldptr , newsize + sizeof(struct mem_descriptor));
        PRINTOUT("+%p\n",ptr->data);
    }
    ptr->line = line;
    ptr->file = file;
    list_add_head( &ptr->node, &mem_allocs);
    return (void*)ptr->data;
}

void _fuse_free( void *oldptr ,int line,const char* file )
{
    (void)line;
    (void)file;

    if (oldptr){
        struct mem_descriptor *old_mptr = (struct mem_descriptor *)(oldptr);
        old_mptr--;
        list_del(&old_mptr->node);
        ref_cntr--;
        PRINTOUT("-%p\n",old_mptr->data);
        free(old_mptr);
    }
}

char* _fuse_strdup( const char *str,int line,const char* file )
{
    struct mem_descriptor *ptr = (struct mem_descriptor*)malloc(sizeof(struct mem_descriptor) + strlen(str) + 1);
    ptr->line = line;
    ptr->file = file;
    list_add_head( &ptr->node, &mem_allocs);
    strcpy((char*)ptr->data,str);
    ref_cntr++;
    return (char*)ptr->data;
}

void fuse_mem_dump( void )
{
    struct mem_descriptor *desc;
    struct list_head *curr, *next;
    (void)desc;

    for (curr = mem_allocs.next; curr != &mem_allocs; curr = next) {
        next = curr->next;
        desc = list_entry(curr, struct mem_descriptor, node);
        PRINTOUT("%p %s(%d)\n",desc->data,desc->file,desc->line);
    }
}

int fuse_mem_cntr( void )
{
    struct list_head *curr, *next;
    int i = 0;
    for (curr = mem_allocs.next; curr != &mem_allocs; curr = next) {
        next = curr->next;
        i++;
    }
    return i;
}
