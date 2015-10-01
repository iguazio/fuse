#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
struct fsm_unlink_data {
    const char *path;
    const char *name;
    struct fuse *f;
    struct node *wnode;
    fuse_ino_t parent;
    fuse_req_t req;
    struct fuse_intr_data d;
};

/*Send request to the fs*/
static const char* f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_unlink_data *dt = (struct fsm_unlink_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_unlink(fsm, dt->f->fs, dt->path);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return NULL;
    fuse_fsm_set_err(fsm, err);
    return (err)?"error":"ok";
}


static const char* f10(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_unlink_data *dt = (struct fsm_unlink_data *)data;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    remove_node(dt->f, dt->parent, dt->name);
    free_path_wrlock(dt->f, dt->parent, dt->wnode, (char*)dt->path);
    reply_err(dt->req, 0);

    return NULL;
}


static const char* f13(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_unlink_data *dt = (struct fsm_unlink_data *)data;
    int err = fuse_fsm_get_err(fsm);

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path_wrlock(dt->f, dt->parent, dt->wnode, (char*)dt->path);
    reply_err(dt->req, err);
    return NULL;
}

//f1 - send fuse_fs_unlink
//f10 - Replay to the driver - success 
//f13 - Replay to the driver - error


FUSE_FSM_EVENTS(UNLINK,  "ok", "error")
FUSE_FSM_STATES(UNLINK,   "START",         "RM"     ,"DONE")
FUSE_FSM_ENTRY(/*ok*/	 {"RM",f1}     ,{"DONE",f10} , NONE)
FUSE_FSM_LAST(/*error*/{"DONE",f13},    {"DONE",f13}  , NONE)



void fuse_lib_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    struct node *wnode;
    char *path;
    int err;

    err = get_path_wrlock(f, parent, name, &path, &wnode);

    if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(UNLINK, new_fsm, struct fsm_unlink_data);
        struct fsm_unlink_data *dt = (struct fsm_unlink_data*)new_fsm->data;

        dt->f = f;
        dt->parent = parent;
        dt->req = req;
        dt->path = path;
        dt->name = name;
        dt->wnode = wnode;

        fuse_fsm_run(new_fsm, "ok");
        if (!strcmp(fuse_fsm_cur_state(new_fsm),"DONE"))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, err);
}


