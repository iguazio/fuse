#pragma once
#include <sys/stat.h>
struct ig_async_responce{
    void (*release)(struct ig_async_responce* responce);
    fuse_ino_t ino;
    int return_code;
    fuse_req_t* req;
    union {
        struct stat *getattr_resp;
    }data;
};