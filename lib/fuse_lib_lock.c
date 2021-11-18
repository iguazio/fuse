#include <fcntl.h>
#include "fuse_lib.h"
#include "fuse_fsm.h"

struct fsm_lock_data {
    char *path;
	struct flock lock;
	int cmd;
    struct fuse_file_info fi;
    struct fuse * f;
    fuse_ino_t ino;
    fuse_req_t req;
    struct fuse_intr_data d;
};

/*Send request to the fs*/
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_lock_data *dt = (struct fsm_lock_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_lock(fsm, dt->f->fs, dt->path, &dt->fi, dt->cmd, &dt->lock);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}
/*Send successfully read data*/
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_lock_data *dt = (struct fsm_lock_data *)data;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);

	int err = fuse_fsm_get_err(fsm);
	if(dt->cmd == F_GETLK && !err) {
		fuse_reply_lock(dt->req, &dt->lock);
	} else {
		reply_err(dt->req, err);
	}

    return FUSE_FSM_EVENT_NONE;
}

static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_lock_data *dt = (struct fsm_lock_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
    return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(LOCK, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(LOCK,       "CREATED",     "LOCK",         "DONE")
FUSE_FSM_ENTRY(LOCK,/*ok*/{ "LOCK",f1 },    { "DONE",f2 }, FUSE_FSM_BAD)
FUSE_FSM_LAST(LOCK, /*error*/{ "DONE",f3 },{ "DONE",f3 }, FUSE_FSM_BAD)



void fuse_lib_lock(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, struct flock *lock, int cmd)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int res;
    res = get_path_nullok(f, ino, &path);
    if (res == 0) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(LOCK, new_fsm, struct fsm_lock_data);
        struct fsm_lock_data *dt = (struct fsm_lock_data*)new_fsm->data;


        dt->path = path;
        dt->f = f;
        dt->ino = ino;
        dt->fi = *fi;
        dt->req = req;
        dt->lock = *lock;
		dt->cmd = cmd;
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    } else {
        reply_err(req, res);
	}
}

