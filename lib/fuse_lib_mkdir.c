#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
struct fsm_mkdir_data {
    const char *path;
    const char *name;
    struct fuse * f;
    fuse_ino_t parent;
    int mode;
    fuse_req_t req;
    struct fuse_entry_param e;
    struct fuse_intr_data d;
};

/*Send request to the fs*/
static const char* f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_mkdir_data *dt = (struct fsm_mkdir_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_mkdir(fsm, dt->f->fs, dt->path, dt->mode);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return NULL;
    fuse_fsm_set_err(fsm, err);
    return (err)?"error":"ok";
}

//Send lookup
static const char* f2(struct fuse_fsm* fsm, void *data) {
    struct fsm_mkdir_data *dt = (struct fsm_mkdir_data *)data;
    int err = lookup_path(fsm, dt->f, dt->parent, dt->name, dt->path, &dt->e, NULL);
    if (err == FUSE_LIB_ERROR_PENDING_REQ){
        return NULL;
    }
    fuse_fsm_set_err(fsm, err);
    return NULL;//lookup_path() triggers "ok" or "error" events , so no need to return event ID
}

static const char* f10(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_mkdir_data *dt = (struct fsm_mkdir_data *)data;
    int err = fuse_fsm_get_err(fsm);

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->parent, (char*)dt->path);
    reply_entry(dt->req, &dt->e, err);
    return NULL;
}

//f1 - send fuse_fs_mkdir
//f2 - send lookup request
//f10 - Replay to the driver - either success or error


FUSE_FSM_EVENTS(MKDIR, "ok", "error")
FUSE_FSM_STATES(MKDIR,   "START",         "MKDIR"    ,"LKP"         ,"DONE")
FUSE_FSM_ENTRY(/*ok*/	 {"MKDIR",f1}     ,{"LKP",f2}  , {"DONE",f10} , NONE)
FUSE_FSM_LAST(/*error*/{"DONE",f10},    {"DONE",f10} , {"DONE",f10} , NONE)

void fuse_lib_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
                           mode_t mode)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;

    err = get_path_name(f, parent, name, &path);
    if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(MKDIR, new_fsm, struct fsm_mkdir_data);
        struct fsm_mkdir_data *dt = (struct fsm_mkdir_data*)new_fsm->data;

        dt->f = f;
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
