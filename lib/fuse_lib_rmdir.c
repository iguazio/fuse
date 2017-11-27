#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
#include "fuse_fsm.h"

struct fsm_rmdir_data {
    const char *path;
    const char *name;
    struct fuse *f;
    struct node *wnode;
    fuse_ino_t parent;
    fuse_req_t req;
    struct fuse_intr_data d;
};

/*Send request to the fs*/
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rmdir_data *dt = (struct fsm_rmdir_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_rmdir(fsm, dt->f->fs, dt->path);
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}


static struct fuse_fsm_event f10(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rmdir_data *dt = (struct fsm_rmdir_data *)data;

    remove_node(dt->f, dt->parent, dt->name);
    free_path_wrlock(dt->f, dt->parent, dt->wnode, (char*)dt->path);
    reply_err(dt->req, 0);
    fuse_free(dt->name);
    fuse_free(dt->path);

    return FUSE_FSM_EVENT_NONE;
}


static struct fuse_fsm_event f13(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rmdir_data *dt = (struct fsm_rmdir_data *)data;
    int err = fuse_fsm_get_err(fsm);
    free_path_wrlock(dt->f, dt->parent, dt->wnode, (char*)dt->path);
    reply_err(dt->req, err);
    fuse_free(dt->name);
    fuse_free(dt->path);
    return FUSE_FSM_EVENT_NONE;
}

//f1 - send fuse_fs_rmdir
//f10 - Replay to the driver - success 
//f13 - Replay to the driver - error


FUSE_FSM_EVENTS(RMDIR, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(RMDIR,           "START",         "RMDIR"     ,"DONE")
FUSE_FSM_ENTRY(RMDIR,/*ok*/	 {"RMDIR",f1}     ,{"DONE",f10} , FUSE_FSM_BAD)
FUSE_FSM_LAST(RMDIR,/*error*/{"DONE",f13},    {"DONE",f13}  , FUSE_FSM_BAD)



void fuse_lib_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    struct node *wnode;
    char *path;
    int err;

    err = get_path_wrlock(f, parent, name, &path, &wnode);

    if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(RMDIR, new_fsm, struct fsm_rmdir_data);
        struct fsm_rmdir_data *dt = (struct fsm_rmdir_data*)new_fsm->data;

        dt->f = f;
        dt->parent = parent;
        dt->req = req;
        dt->path = fuse_strdup(path);
        dt->name = fuse_strdup(name);
        dt->wnode = wnode;

        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm)) {
            fuse_free(dt->name);
            fuse_free(dt->path);
            FUSE_FSM_FREE(new_fsm);
        }
    }else
        reply_err(req, err);
}
