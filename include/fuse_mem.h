#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

//#define DEBUG_MALLOC

void* _fuse_malloc(size_t size,int line,const char* file);
void* _fuse_calloc(size_t nmenb,size_t size,int line,const char* file);
void* _fuse_realloc(void *oldptr, size_t newsize,int line,const char* file);
void  _fuse_free(void *oldptr,int line,const char* file );
char* _fuse_strdup(const char *str,int line,const char* file);

void  fuse_mem_verify(void);

#ifdef DEBUG_MALLOC
    #define fuse_malloc(size) _fuse_malloc(size,__LINE__,__FILE__)
    #define fuse_calloc(nmenb,size) _fuse_calloc(nmenb,size,__LINE__,__FILE__)
    #define fuse_realloc(ptr,size) _fuse_realloc(ptr,size,__LINE__,__FILE__)
    #define fuse_free(ptr) _fuse_free(ptr,__LINE__,__FILE__)
    #define fuse_strdup(ptr) _fuse_strdup(ptr,__LINE__,__FILE__)
#else
    #define fuse_malloc(size) malloc(size)
    #define fuse_calloc(nmenb,size) calloc(nmenb,size)
    #define fuse_realloc(ptr,size) realloc(ptr,size)
    #define fuse_free(ptr) free(ptr)
    #define fuse_strdup(ptr) strdup(ptr)
#endif
