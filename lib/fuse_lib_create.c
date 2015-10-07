#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"

struct fsm_create_data {
	struct node *node;
    struct fuse_intr_data d;
	char *path;
    const char *name;
    int mode;
	struct fuse * f;
	struct fuse_file_info fi;
	fuse_ino_t parent;
	fuse_req_t req;
    struct fuse_entry_param e;

};


//Send create request
static const char * f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
	struct fsm_create_data *dt = (struct fsm_create_data *)data;
	fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
	int err = fuse_fs_create(fsm, dt->f->fs, dt->path,dt->mode, &dt->fi);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return NULL;
    fuse_fsm_set_err(fsm, err);
    return (err)?"error":"ok";
}


//Send lookup
static const char* f2(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
	struct fsm_create_data *dt = (struct fsm_create_data *)data;
    int err = lookup_path(fsm, dt->f, dt->parent, dt->name, dt->path, &dt->e, &dt->fi);
    if (err == FUSE_LIB_ERROR_PENDING_REQ){
        return NULL;
    }
    fuse_fsm_set_err(fsm, err);
    return NULL;//lookup_path() triggers "ok" or "error" events , so no need to return event ID
}


//Do nothing
static const char* f4(struct fuse_fsm* fsm __attribute__((unused)), void *data __attribute__((unused))) {
    return NULL;
}

//send release request
static const char* f5(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_create_data *dt = (struct fsm_create_data *)data;
    int err = fuse_fs_release(fsm, dt->f->fs, dt->path, &dt->fi);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return NULL;
    fuse_fsm_set_err(fsm, err);
    return (err)?"error":"ok";
}
//Check lookup results
static const char* f6(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_create_data *dt = (struct fsm_create_data *)data;
    int err = 0;
    if (!S_ISREG(dt->e.attr.st_mode))
        err = -EIO;
    fuse_fsm_set_err(fsm, err);
    return (err)?"error":"ok";
}


//Success.Send replay_create
static const char* f10(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_create_data *dt = (struct fsm_create_data *)data;
    if (dt->f->conf.direct_io)
        dt->fi.direct_io = 1;
    if (dt->f->conf.kernel_cache)
        dt->fi.keep_cache = 1;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);

	pthread_mutex_lock(&dt->f->lock);
	get_node(dt->f, dt->e.ino)->open_count++;
	pthread_mutex_unlock(&dt->f->lock);
    free_path(dt->f, dt->parent, dt->path);
	if (fuse_reply_create(dt->req, &dt->e, &dt->fi) == -ENOENT)
        return "error";
    return "ok";
}

//reply error
static const char* f13(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_create_data *dt = (struct fsm_create_data *)data;
    if (dt->e.ino != 0)
        forget_node(dt->f, dt->e.ino, 1);
    int err = fuse_fsm_get_err(fsm);
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->parent, dt->path);
    reply_err(dt->req, err);
    return NULL;
}


//f1 - send fuse_fs_create request
//f2 - send lookup request
//f4 - do nothing
//f5 - send release request
//f6 - check lookup results
//f10 - Replay to the driver - create_success
//f13 - Replay to the driver - "error"

FUSE_FSM_EVENTS(CREATE, "ok", "error")
FUSE_FSM_STATES(CREATE,   "START",         "CRT"      ,     "LKP"    ,"LKP_OK"       ,"RPLY_OK"       ,"RLS"       , "RPLY_ERR"  ,"DONE")
FUSE_FSM_ENTRY(/*ok*/	{"CRT",f1}     ,{"LKP",f2}  ,{"LKP_OK",f6} ,{"RPLY_OK",f10},{"DONE",f4}     ,{"DONE",f13}, {"DONE",f4}, NONE)
FUSE_FSM_LAST(/*error*/{"RPLY_ERR",f13},{"DONE",f13},{"RLS",f5}    ,{"RLS",f5}     ,{"RPLY_ERR",f5} ,{"DONE",f13}, {"DONE",f4},NONE)





void fuse_lib_create(fuse_req_t req, fuse_ino_t parent,
			    const char *name, mode_t mode,
			    struct fuse_file_info *fi)
{
	struct fuse *f = req_fuse_prepare(req);
	char *path;
	int err;

	err = get_path_name(f, parent, name, &path);
	if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(CREATE, new_fsm, struct fsm_create_data);
        struct fsm_create_data *dt = (struct fsm_create_data*)new_fsm->data;

        dt->f = f;
        dt->fi = *fi;
        dt->parent = parent;
        dt->req = req;
        dt->path = path;
        dt->name = name;
        dt->mode = mode;

        fuse_fsm_run(new_fsm, "ok");
        if (!strcmp(fuse_fsm_cur_state(new_fsm),"DONE"))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, err);
}
