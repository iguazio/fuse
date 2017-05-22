#include "fuse_lib.h"
#include "fuse_fsm.h"

struct fsm_access_data{
    struct fuse_intr_data d;
    char *path;
    int mask;
    struct fuse * f;
    fuse_ino_t ino;
    fuse_req_t req;
};


static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_access_data *dt = (struct fsm_access_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err;

    err = fuse_fs_access(fsm, dt->f->fs, dt->path, dt->mask);

    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm,err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}


static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_access_data  *dt = (struct fsm_access_data *)data;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    reply_err(dt->req, 0);
    free_path(dt->f, dt->ino, dt->path);
	return FUSE_FSM_EVENT_NONE;
}


static struct fuse_fsm_event f4(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_access_data *dt = (struct fsm_access_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
    free_path(dt->f, dt->ino, dt->path);
	return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(ACCESS,FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(ACCESS,                              "CREATED",   "ACCESS"    ,"DONE")
FUSE_FSM_ENTRY(ACCESS,/*FUSE_FSM_EVENT_OK*/         {"ACCESS",f1},  {"DONE",f3},FUSE_FSM_BAD)           
FUSE_FSM_LAST (ACCESS,/*FUSE_FSM_EVENT_ERROR*/      {"DONE",f4},  {"DONE",f4},FUSE_FSM_BAD)       

void fuse_lib_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
    int err;
    struct fuse *f = req_fuse_prepare(req);
    char *path;

    
    err = get_path(f, ino, &path);
    
    if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(ACCESS, new_fsm, struct fsm_access_data);
        struct fsm_access_data *dt = (struct fsm_access_data*)new_fsm->data;

        dt->f = f;
        dt->mask = mask;
        dt->ino = ino;
        dt->req = req;
        dt->path = path;
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, err);
}
