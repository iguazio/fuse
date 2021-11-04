#include <fcntl.h>
#include "fuse_lib.h"
#include "fuse_fsm.h"

struct fsm_flock_data {
    char *path;
	int op;
    struct fuse_file_info fi;
    struct fuse * f;
    fuse_ino_t ino;
    fuse_req_t req;
    struct fuse_intr_data d;
};

/*Send request to the fs*/
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_flock_data *dt = (struct fsm_flock_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_flock(fsm, dt->f->fs, dt->path, &dt->fi, dt->op);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}
/*Send successfully read data*/
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_flock_data *dt = (struct fsm_flock_data *)data;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);

	int err = fuse_fsm_get_err(fsm);
	fuse_reply_err(dt->req, err);

    return FUSE_FSM_EVENT_NONE;
}


FUSE_FSM_EVENTS(FLOCK, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(FLOCK,       "CREATED",     "FLOCK",         "DONE")
FUSE_FSM_ENTRY(FLOCK,/*ok*/{ "FLOCK",f1 },    { "DONE",f2 }, FUSE_FSM_BAD)
FUSE_FSM_LAST(FLOCK, /*error*/{ "DONE",f2 },{ "DONE",f2 }, FUSE_FSM_BAD)



void fuse_lib_flock(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, int op)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int res;
    res = get_path_nullok(f, ino, &path);
    if (res == 0) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(FLOCK, new_fsm, struct fsm_flock_data);
        struct fsm_flock_data *dt = (struct fsm_flock_data*)new_fsm->data;


        dt->path = path;
        dt->f = f;
        dt->ino = ino;
        dt->fi = *fi;
        dt->req = req;
		dt->op = op;
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    } else {
        reply_err(req, res);
	}
}

