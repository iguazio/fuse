#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
#include "fuse_fsm.h"

struct fsm_symlink_data {
    const char *link_name;
    const char *target_path;
    char *link_path;
    struct fuse * f;
    fuse_ino_t parent;
    fuse_req_t req;
    struct fuse_intr_data d;
    struct fuse_entry_param e;
};

/*Send request to the fs*/
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_symlink_data *dt = (struct fsm_symlink_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_symlink(fsm, dt->f->fs, dt->target_path, dt->link_path);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}
/*send LookUp command*/
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_symlink_data *dt = (struct fsm_symlink_data *)data;
    int err = lookup_path(fsm, dt->f, dt->parent, dt->link_name, dt->link_path, &dt->e, NULL);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

/*Send OK */
static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_symlink_data *dt = (struct fsm_symlink_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->parent, dt->link_path);
    reply_entry(dt->req, &dt->e, 0);
    return FUSE_FSM_EVENT_NONE;
}

/*Send error */
static struct fuse_fsm_event f10(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_symlink_data *dt = (struct fsm_symlink_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->parent, dt->link_path);
    int err = fuse_fsm_get_err(fsm);
    reply_entry(dt->req,&dt->e, err);
    return FUSE_FSM_EVENT_NONE;
}


FUSE_FSM_EVENTS(SYMLINK, FUSE_FSM_EVENT_OK   , FUSE_FSM_EVENT_ERROR)

FUSE_FSM_STATES(SYMLINK,       "CREATED"     , "WRT"        ,     "LKP"   , "DONE")
FUSE_FSM_ENTRY(SYMLINK,/*ok*/    { "WRT",f1 },{ "LKP",f2 }  ,{"DONE",f3}  , FUSE_FSM_BAD)
FUSE_FSM_LAST(SYMLINK, /*error*/{ "DONE",f10},{ "DONE",f10 },{"DONE",f10} , FUSE_FSM_BAD)


void fuse_lib_symlink(fuse_req_t req, const char *target_path, fuse_ino_t parent, const char *link_name)
{

    struct fuse *f = req_fuse_prepare(req);
    int res;
    char *path;

     res = get_path_name(f, parent, link_name, &path);
     if (res == 0) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(SYMLINK, new_fsm, struct fsm_symlink_data);
        struct fsm_symlink_data *dt = (struct fsm_symlink_data*)new_fsm->data;

        dt->target_path = target_path;
        dt->link_name = link_name;
        dt->link_path = path;
        dt->parent = parent;
        dt->f = f;
        dt->req = req;
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
     }
     else {
         struct fuse_entry_param e = {};
         reply_entry(req,&e, res);
     }
}
