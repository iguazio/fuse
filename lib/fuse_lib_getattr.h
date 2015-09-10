#pragma once

#pragma GCC diagnostic ignored "-Wunused-parameter"
// #pragma GCC diagnostic ignored "-Wmissing-declarations"

#include "fuse_fsm.h"
/*/////////////////////////////////////////////////////////////////////////
                states
events          CREATED         FGETS_SENT          GETS_SENT         DESTROYED    
                -------         ---------           ---------         ---------
send_fget       FGETS_SENT(f1)  NONE                NONE            
send_get        GETS_SENT(f2)   NONE                NONE            
ok              SUCCEDED(f3)    SUCCEDED(f3)        SUCCEDED(f3)      
error           FAILED(f3)      FAILED(f3)          FAILED(f3)        
/////////////////////////////////////////////////////////////////////////*/


struct fsm_getattr_data{
    struct stat buf;
    char *path;
    struct fuse * f;
    struct fuse_file_info *fi;
    fuse_ino_t ino;
    int err;
    fuse_req_t req;
};

static void f1(const char * from,const char * to,void *data){
    struct fsm_getattr_data *dt = (struct fsm_getattr_data *)data;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(dt->f, dt->req, &d);
    dt->err = fuse_fs_fgetattr(dt->f->fs, dt->path, &dt->buf, dt->fi);
    fuse_finish_interrupt(dt->f, dt->req, &d);
}

static void f2(const char * from,const char * to,void *data){
    struct fsm_getattr_data *dt = (struct fsm_getattr_data *)data;
    struct fuse_intr_data d;
    fuse_prepare_interrupt(dt->f, dt->req, &d);
    dt->err = fuse_fs_getattr(dt->f->fs, dt->path, &dt->buf);
    fuse_finish_interrupt(dt->f, dt->req, &d);
}

static void f3(const char * from,const char * to,void *data){
    struct fsm_getattr_data *dt = (struct fsm_getattr_data *)data;
    struct node *node;

    pthread_mutex_lock(&dt->f->lock);
    node = get_node(dt->f, dt->ino);
    if (node->is_hidden && dt->buf.st_nlink > 0)
        dt->buf.st_nlink--;
    if (dt->f->conf.auto_cache)
        update_stat(node, &dt->buf);
    pthread_mutex_unlock(&dt->f->lock);
    set_stat(dt->f, dt->ino, &dt->buf);
    fuse_reply_attr(dt->req, &dt->buf, dt->f->conf.attr_timeout);
}


static void f4(const char * from,const char * to,void *data){
    struct fsm_getattr_data *dt = (struct fsm_getattr_data *)data;
    reply_err(dt->req, dt->err);
}

FUSE_FSM_EVENTS(GETATTR,"send_fget","send_get","ok","error")
FUSE_FSM_STATES(GETATTR,        "CREATED",        "FGETS_SENT",   "GETS_SENT"       ,   "DESTROYED")
FUSE_FSM_ENTRY(/*"send_fget"*/ {"FGETS_SENT",f1}, NONE             ,   NONE         ,   NONE)           
FUSE_FSM_ENTRY(/*"send_get"*/  {"GETS_SENT",f2},  NONE             ,   NONE         ,   NONE)           
FUSE_FSM_ENTRY(/*"ok"*/        {"DESTROYED",f3},  {"DESTROYED",f3} ,{"DESTROYED",f3},   NONE)           
FUSE_FSM_LAST (/*"error"*/     {"DESTROYED",f4},  {"DESTROYED",f4} ,{"DESTROYED",f4},   NONE)           




static void fuse_lib_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct fuse_fsm *new_fsm = NULL;
    FUSE_FSM_ALLOC(GETATTR,new_fsm,struct fsm_getattr_data);
    struct fsm_getattr_data *dt = (struct fsm_getattr_data*)new_fsm->data;

    struct fuse *f = req_fuse_prepare(req);

    dt->f = f;
    dt->fi = fi;
    dt->ino = ino;
    dt->req = req;
    
    int err;
    
    if (fi != NULL && f->fs->op.fgetattr)
        err = get_path_nullok(f, ino, &dt->path);
    else
        err = get_path(f, ino, &dt->path);

    if (err)
        fuse_fsm_run(new_fsm, "error");
    else{
        fuse_fsm_run(new_fsm, (fi)? "send_fget" : "send_get");
        err = dt->err;
    }
    
    free_path(f, ino, dt->path);

    if (dt->err == FUSE_LIB_ERROR_PENDING_REQ)
        fuse_async_add_pending(new_fsm);
    else
        fuse_fsm_run(new_fsm, dt->err ? "error" : "ok");

    if (!strcmp(fuse_fsm_cur_state(new_fsm),"DESTROYED"))
        FUSE_FSM_FREE(new_fsm);
}
