#include "fuse_lib.h"
#include "fuse_misc.h"
#include "fuse_fsm.h"

struct fsm_setattr_data{
    char *path;
    struct fuse * f;
    struct fuse_file_info fi;
    int has_fi;
    fuse_ino_t ino;
    fuse_req_t req;
    int valid;
    struct stat attr;
    struct fuse_intr_data d;
};


static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_setattr_data *dt = (struct fsm_setattr_data *)data;
    int err = 0;
    if (dt->valid & FUSE_SET_ATTR_MODE)
        err = fuse_fs_chmod(fsm, dt->f->fs, dt->path, dt->attr.st_mode);

    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_setattr_data *dt = (struct fsm_setattr_data *)data;
    int err = 0;
    if ((dt->valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID))) {
        uid_t uid = (dt->valid & FUSE_SET_ATTR_UID) ?
            dt->attr.st_uid : (uid_t) -1;
        gid_t gid = (dt->valid & FUSE_SET_ATTR_GID) ?
            dt->attr.st_gid : (gid_t) -1;
        err = fuse_fs_chown(fsm, dt->f->fs, dt->path, uid, gid);
    }
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_setattr_data *dt = (struct fsm_setattr_data *)data;
    int err = 0;
    if (dt->valid & FUSE_SET_ATTR_SIZE) {
        if (dt->has_fi)
            err = fuse_fs_ftruncate(fsm,dt->f->fs, dt->path, dt->attr.st_size, &dt->fi);
        else
            err = fuse_fs_truncate(fsm,dt->f->fs, dt->path, dt->attr.st_size);
    }
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}
static struct fuse_fsm_event f4(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_setattr_data *dt = (struct fsm_setattr_data *)data;
    int err = 0;

    #if 0 // #ifdef HAVE_UTIMENSAT
    if (!err &&
        (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME))) {
            struct timespec tv[2];

            tv[0].tv_sec = 0;
            tv[1].tv_sec = 0;
            tv[0].tv_nsec = UTIME_OMIT;
            tv[1].tv_nsec = UTIME_OMIT;

            if (valid & FUSE_SET_ATTR_ATIME_NOW)
                tv[0].tv_nsec = UTIME_NOW;
            else if (valid & FUSE_SET_ATTR_ATIME)
                tv[0] = attr->st_atim;

            if (valid & FUSE_SET_ATTR_MTIME_NOW)
                tv[1].tv_nsec = UTIME_NOW;
            else if (valid & FUSE_SET_ATTR_MTIME)
                tv[1] = attr->st_mtim;

            err = fuse_fs_utimens(f->fs, path, tv);
    } else
    #endif
    if ((dt->valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) ==
        (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
            struct timespec tv[2];
            tv[0].tv_sec = dt->attr.st_atime;
            tv[0].tv_nsec = ST_ATIM_NSEC(&dt->attr);
            tv[1].tv_sec = dt->attr.st_mtime;
            tv[1].tv_nsec = ST_MTIM_NSEC(&dt->attr);
            err = fuse_fs_utimens(fsm, dt->f->fs, dt->path, tv);
    }
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}
static struct fuse_fsm_event f5(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_setattr_data *dt = (struct fsm_setattr_data *)data;
    int err = 0;
    if (dt->has_fi)
        err = fuse_fs_fgetattr(fsm, dt->f->fs, dt->path, &dt->attr, &dt->fi);
    else
        err = fuse_fs_getattr(fsm, dt->f->fs, dt->path, &dt->attr);

    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}
//OK
static struct fuse_fsm_event f6(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_setattr_data *dt = (struct fsm_setattr_data *)data;
    if (dt->f->conf.auto_cache) {
        pthread_mutex_lock(&dt->f->lock);
        update_stat(get_node(dt->f, dt->ino), &dt->attr);
        pthread_mutex_unlock(&dt->f->lock);
    }
    set_stat(dt->f, dt->ino, &dt->attr);
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);

    fuse_reply_attr(dt->req, &dt->attr, dt->f->conf.attr_timeout);

    return FUSE_FSM_EVENT_NONE;
}
//error
static struct fuse_fsm_event f10(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_setattr_data *dt = (struct fsm_setattr_data *)data;
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req,err);

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);
    return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(SETATTR,FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(SETATTR,                  "CREATED",   "CHMOD",      "CHOWN"    ,      "TRUNC"    ,      "UTIME"    ,      "GETATTR"    ,"DONE")
FUSE_FSM_ENTRY(SETATTR, /*FUSE_FSM_EVENT_OK*/         {"CHMOD",f1},{"CHOWN",f2}, {"TRUNC",f3},    {"UTIME",f4} ,   {"GETATTR",f5},     {"DONE",f6}   ,FUSE_FSM_BAD  )
FUSE_FSM_LAST (SETATTR, /*FUSE_FSM_EVENT_ERROR*/      {"DONE",f10},{"DONE",f10},{"DONE",f10},     {"DONE",f10},     {"DONE",f10},      {"DONE",f10} ,FUSE_FSM_BAD  )


/*FixMe: should be added as a separate user callback*/
void fuse_lib_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *att,
                             int valid, struct fuse_file_info *fi)
{
    int err = 0;
    struct fuse *f = req_fuse_prepare(req);
    char *path;
 
    if (valid == FUSE_SET_ATTR_SIZE && fi != NULL &&
        f->fs->op.ftruncate && f->fs->op.fgetattr)
        err = get_path_nullok(f, ino, &path);
    else
        err = get_path(f, ino, &path);
    if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(SETATTR,new_fsm,struct fsm_setattr_data);
        struct fsm_setattr_data *dt = (struct fsm_setattr_data*)new_fsm->data;


        dt->f = f;
        dt->ino = ino;
        dt->req = req;
        dt->valid = valid;
        dt->attr = *att;
        dt->has_fi = (fi != NULL);
        if(dt->has_fi)
            dt->fi = *fi;
        dt->path = path;

        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req,err);
}