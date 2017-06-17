
#include "fuse_lib.h"
#include "fuse_fsm.h"

/*/////////////////////////////////////////////////////////////////////////
                states
events          CREATED         FGETS_SENT          GETS_SENT         DESTROYED
                -------         ---------           ---------         ---------
send_fget       FGETS_SENT(f1)  NONE                NONE
send_get        GETS_SENT(f2)   NONE                NONE
ok              SUCCEDED(f3)    SUCCEDED(f3)        SUCCEDED(f3)
error           FAILED(f3)      FAILED(f3)          FAILED(f3)
/////////////////////////////////////////////////////////////////////////*/

struct fsm_getxattr_data{
    struct fuse_intr_data d;
    char *path;
    struct fuse *f;
    fuse_ino_t ino;
    fuse_req_t req;
    const char *name;
    char *value;
    size_t size;
};

static struct fuse_fsm_event fuse_lib_getxattr_f1(struct fuse_fsm* fsm __attribute__((unused)),void *data) {
    struct fsm_getxattr_data *dt = (struct fsm_getxattr_data *)data;
    int err;

    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    err = fuse_fs_getxattr(fsm, dt->f->fs, dt->path, dt->name, dt->value, dt->size);

    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);

    // according to man: getxattrs returns the size of the attr as a positive return value
    return (err < 0) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}


static struct fuse_fsm_event fuse_lib_getxattr_f3(struct fuse_fsm* fsm __attribute__((unused)),void *data) {
    struct fsm_getxattr_data *dt = (struct fsm_getxattr_data *)data;
    int res;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    res = fuse_fsm_get_err(fsm);

    if (dt->size) {
        if (res > 0)
            fuse_reply_buf(dt->req, dt->value, res);
        else
            reply_err(dt->req, res);
    } else {
        if (res >= 0)
            fuse_reply_xattr(dt->req, res);
        else
            reply_err(dt->req, res);
    }

    free_path(dt->f, dt->ino, dt->path);
    if (dt->value)
        free(dt->value);

    return FUSE_FSM_EVENT_NONE;
}

static struct fuse_fsm_event fuse_lib_getxattr_f4(struct fuse_fsm* fsm __attribute__((unused)),void *data) {
    struct fsm_getxattr_data *dt = (struct fsm_getxattr_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
    free_path(dt->f, dt->ino, dt->path);
    if (dt->value)
        free(dt->value);

    return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(GETXATTR,FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(GETXATTR,                "CREATED",   "GETSX"    ,"DONE")
FUSE_FSM_ENTRY(GETXATTR,/*FUSE_FSM_EVENT_OK*/         {"GETSX",fuse_lib_getxattr_f1}, {"DONE",fuse_lib_getxattr_f3}, FUSE_FSM_BAD)
FUSE_FSM_LAST (GETXATTR,/*FUSE_FSM_EVENT_ERROR*/      {"DONE",fuse_lib_getxattr_f4}, {"DONE",fuse_lib_getxattr_f4}, FUSE_FSM_BAD)

void fuse_lib_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
    int err = 0;
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    char *value = NULL;

    if (f->fs->op.getxattr)
        err = get_path(f, ino, &path);

    if (size) {
        value = (char *)malloc(size);
        if (value == NULL) {
            reply_err(req, -ENOMEM);
            return;
        }
    } else {
        value = NULL;
    }

    if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(GETXATTR, new_fsm, struct fsm_getxattr_data);
        struct fsm_getxattr_data *dt = (struct fsm_getxattr_data*)new_fsm->data;

        dt->f = f;
        dt->ino = ino;
        dt->req = req;
        dt->path = path;
        dt->name = name;
        dt->size = size;
        dt->value = value;
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    } else {
        reply_err(req, err);
    }
}
