#include "fuse_lib.h"
#include "fuse_fsm.h"

struct fsm_write_data {
    char *path;
    size_t off;
    struct fuse_file_info fi;
    struct fuse * f;
    struct fuse_bufvec buf;
    fuse_ino_t ino;
    fuse_req_t req;
    struct fuse_intr_data d;
};

/*Send request to the fs*/
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_write_data *dt = (struct fsm_write_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_write_buf(fsm, dt->f->fs, dt->path, &dt->buf, dt->off, &dt->fi);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}
/*Send successfully read data*/
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_write_data *dt = (struct fsm_write_data *)data;

    // FixMe:
    // This is an ugly workaround of the fact that the actual size
    // is expected to be return by this function
    // Instead we will return it in the fi structure, since we are working with a copy
    // The right way would be to pass a pointer to actual_size that would be updated in the ig_write_response 
    int size = *((size_t*)(&dt->fi));

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);
    fuse_reply_write(dt->req, size);

    return FUSE_FSM_EVENT_NONE;
}

/*Send error read data*/
static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_write_data *dt = (struct fsm_write_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
    return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(WRITE, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(WRITE,       "CREATED",     "WRT",         "DONE")
FUSE_FSM_ENTRY(WRITE,/*ok*/{ "WRT",f1 },    { "DONE",f2 }, FUSE_FSM_BAD)
FUSE_FSM_LAST(WRITE, /*error*/{ "DONE",f3 },{ "DONE",f3 }, FUSE_FSM_BAD)




void fuse_lib_write_buf(fuse_req_t req, fuse_ino_t ino,struct fuse_bufvec *buf, off_t off, struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int res;

    res = get_path_nullok(f, ino, &path);
    if (res == 0) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(WRITE, new_fsm, struct fsm_write_data);
        struct fsm_write_data *dt = (struct fsm_write_data*)new_fsm->data;


        dt->path = path;
        dt->f = f;
        dt->ino = ino;
        dt->off = off;
        dt->fi = *fi;
        dt->req = req;
        dt->buf = *buf;
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, res);
}

