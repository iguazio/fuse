#include <libgen.h>
#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
#include "fuse_fsm.h"
#include "fuse_log.h"

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
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_unlink_data *dt = (struct fsm_unlink_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_unlink(fsm, dt->f->fs, dt->path);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}


static struct fuse_fsm_event f10(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_unlink_data *dt = (struct fsm_unlink_data *)data;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    if (dt->wnode->open_count) {
        char hidden_name[NAME_MAX + 16];
        snprintf(hidden_name, sizeof(hidden_name), "?%s.%08X", dt->name, (uint32_t)clock());
        hidden_name[sizeof(hidden_name) - 1] = '\0';
        rename_node(dt->f, dt->parent, dt->name, dt->parent, hidden_name, 1);
        dt->wnode->is_deleted_from_backend = true;
    }else
        remove_node(dt->f, dt->parent, dt->name);
    free_path_wrlock(dt->f, dt->parent, dt->wnode, (char*)dt->path);
    reply_err(dt->req, 0);
    fuse_free((char*)dt->name);

    return FUSE_FSM_EVENT_NONE;
}


static struct fuse_fsm_event f13(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_unlink_data *dt = (struct fsm_unlink_data *)data;
    int err = fuse_fsm_get_err(fsm);

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path_wrlock(dt->f, dt->parent, dt->wnode, (char*)dt->path);
    reply_err(dt->req, err);
    fuse_free((char*)dt->name);
    return FUSE_FSM_EVENT_NONE;
}

//f1 - send fuse_fs_unlink
//f10 - Replay to the driver - success 
//f13 - Replay to the driver - error


FUSE_FSM_EVENTS(UNLINK,  FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(UNLINK,         "START",         "RM"     ,"DONE")
FUSE_FSM_ENTRY(UNLINK,/*ok*/	 {"RM",f1}     ,{"DONE",f10} , FUSE_FSM_BAD)
FUSE_FSM_LAST(UNLINK,/*error*/{"DONE",f13},    {"DONE",f13}  , FUSE_FSM_BAD)



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
        dt->name = fuse_strdup(name);
        dt->wnode = wnode;

        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm)) {
            FUSE_FSM_FREE(new_fsm);
        }
    }else
        reply_err(req, err);
}


