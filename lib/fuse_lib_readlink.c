#include "fuse_lib.h"
#include "fuse_fsm.h"

struct fsm_readlink_data {
    char linkname[PATH_MAX + 1];
    char *path;
    struct fuse * f;
    fuse_req_t req;
    fuse_ino_t ino;
    struct fuse_intr_data d;
};

/*Send request to the fs*/
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_readlink_data *dt = (struct fsm_readlink_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_readlink(fsm, dt->f->fs, dt->path, dt->linkname,sizeof(dt->linkname));
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}
/*Send successfully read data*/
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_readlink_data *dt = (struct fsm_readlink_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    dt->linkname[PATH_MAX] = '\0';
    fuse_reply_readlink(dt->req, dt->linkname);
    free_path(dt->f, dt->ino, dt->path);
    return FUSE_FSM_EVENT_NONE;
}

/*Send error read data*/
static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_readlink_data *dt = (struct fsm_readlink_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
    return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(READLINK, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(READLINK,        "CREATED"  ,     "READ"   , "DONE")
FUSE_FSM_ENTRY(READLINK,/*ok*/ { "READ",f1 }, { "DONE",f2 }, FUSE_FSM_BAD)
FUSE_FSM_LAST(READLINK,/*error*/{"DONE",f3 }, { "DONE",f3 }, FUSE_FSM_BAD)

void fuse_lib_readlink(fuse_req_t req, fuse_ino_t ino)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int res;
    res = get_path(f, ino, &path);
    if (res == 0) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(READLINK, new_fsm, struct fsm_readlink_data);
        struct fsm_readlink_data *dt = (struct fsm_readlink_data*)new_fsm->data;
        dt->ino = ino;
        dt->path = path;
        dt->f = f;
        dt->ino = ino;
        dt->req = req;
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }
    else
        reply_err(req, res);
}
