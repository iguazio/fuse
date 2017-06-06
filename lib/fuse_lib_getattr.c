#include "fuse_lib.h"
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
    struct fuse_intr_data d;
    char *path;
    struct fuse * f;
    struct fuse_file_info fi;
    int has_fi;
    fuse_ino_t ino;
    fuse_req_t req;
};


static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_getattr_data *dt = (struct fsm_getattr_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err;
    if (dt->has_fi)
        err = fuse_fs_fgetattr(fsm, dt->f->fs, dt->path, &dt->buf, &dt->fi);
    else
        err = fuse_fs_getattr(fsm, dt->f->fs, dt->path, &dt->buf);

    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm,err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}


static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
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
	return FUSE_FSM_EVENT_NONE;
}


static struct fuse_fsm_event f4(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_getattr_data *dt = (struct fsm_getattr_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
    free_path(dt->f, dt->ino, dt->path);
	return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(GETATTR,FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(GETATTR,                "CREATED",   "GETS"    ,"DONE")
FUSE_FSM_ENTRY(GETATTR,/*FUSE_FSM_EVENT_OK*/         {"GETS",f1},  {"DONE",f3},FUSE_FSM_BAD)           
FUSE_FSM_LAST (GETATTR,/*FUSE_FSM_EVENT_ERROR*/      {"DONE",f4},  {"DONE",f4},FUSE_FSM_BAD)       




void fuse_lib_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    int err;
    struct fuse *f = req_fuse_prepare(req);
    char *path;

    
    if (fi != NULL && f->fs->op.fgetattr)
        err = get_path_nullok(f, ino, &path);
    else
        err = get_path(f, ino, &path);
    
    if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(GETATTR, new_fsm, struct fsm_getattr_data);
        struct fsm_getattr_data *dt = (struct fsm_getattr_data*)new_fsm->data;

        dt->f = f;
        dt->has_fi = (fi != NULL);
        if (dt->has_fi)
            dt->fi = *fi;
        dt->ino = ino;
        dt->req = req;
        dt->path = path;
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, err);
}
