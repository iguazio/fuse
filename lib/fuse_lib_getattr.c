#include "fuse_lib.h"

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
    struct fuse_intr_data d;
    char *path;
    struct fuse * f;
    struct fuse_file_info fi;
    int has_fi;
    fuse_ino_t ino;
    fuse_req_t req;
};


static const char* f1(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_getattr_data *dt = (struct fsm_getattr_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err;
    if (dt->has_fi)
        err = fuse_fs_fgetattr(fsm, dt->f->fs, dt->path, &dt->buf, &dt->fi);
    else
        err = fuse_fs_getattr(fsm, dt->f->fs, dt->path, &dt->buf);

    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return NULL;
    fuse_fsm_set_err(fsm,err);
    return (err)?"error":"ok";
}


static const char* f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_getattr_data *dt = (struct fsm_getattr_data *)data;
    struct node *node;

    pthread_mutex_lock(&dt->f->lock);
    node = get_node(dt->f, dt->ino);
    if (node->is_hidden && dt->buf.st_nlink > 0)
        dt->buf.st_nlink--;
    if (dt->f->conf.auto_cache)
        update_stat(node, &dt->buf);
    pthread_mutex_unlock(&dt->f->lock);

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    set_stat(dt->f, dt->ino, &dt->buf);
    fuse_reply_attr(dt->req, &dt->buf, dt->f->conf.attr_timeout);
    free_path(dt->f, dt->ino, dt->path);
	return NULL;
}


static const char* f4(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_getattr_data *dt = (struct fsm_getattr_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
    free_path(dt->f, dt->ino, dt->path);
	return NULL;
}

FUSE_FSM_EVENTS(GETATTR,"ok","error")
FUSE_FSM_STATES(GETATTR,                "CREATED",   "GETS"    ,"DONE")
FUSE_FSM_ENTRY(GETATTR,/*"ok"*/         {"GETS",f1},  {"DONE",f3},FUSE_FSM_BAD)           
FUSE_FSM_LAST (GETATTR,/*"error"*/      {"DONE",f4},  {"DONE",f4},FUSE_FSM_BAD)       




void fuse_lib_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct fuse_fsm *new_fsm = NULL;
    FUSE_FSM_ALLOC(GETATTR,new_fsm,struct fsm_getattr_data);
    struct fsm_getattr_data *dt = (struct fsm_getattr_data*)new_fsm->data;
    int err;
    struct fuse *f = req_fuse_prepare(req);
    
    if (fi != NULL && f->fs->op.fgetattr)
        err = get_path_nullok(f, ino, &dt->path);
    else
        err = get_path(f, ino, &dt->path);
    
    if (!err) {
        dt->f = f;
        dt->has_fi = (fi != NULL);
        if (dt->has_fi)
            dt->fi = *fi;
        dt->ino = ino;
        dt->req = req;
        fuse_fsm_run(new_fsm, "ok");
        if (!strcmp(fuse_fsm_cur_state(new_fsm),"DONE"))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, err);
}
