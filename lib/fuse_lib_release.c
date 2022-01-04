#include "fuse.h"
#include "fuse_lib.h"
#include "fuse_fsm.h"


struct fsm_release_data{
    struct fuse * f;
    struct fuse_file_info fi;
    fuse_ino_t ino;
    char* unlinkpath;
    fuse_req_t req;
    const char* path;
    struct fuse_fsm *self;
    struct fuse_intr_data d;
};


static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_release_data *dt = (struct fsm_release_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_release(fsm, dt->f->fs, dt->path, &dt->fi);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}

//Release OK or ERROR - don't care
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_release_data *dt = (struct fsm_release_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, (char*)dt->path);
    if (dt->unlinkpath)
        free_path(dt->f, dt->ino, dt->unlinkpath);
    if (dt->req)
        reply_err(dt->req,0);

    return FUSE_FSM_EVENT_NONE;
}

//Send unlink
static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_release_data *dt = (struct fsm_release_data *)data;
    fuse_fs_unlink(fsm, dt->f->fs, dt->unlinkpath);
    return FUSE_FSM_EVENT_NONE;
}




FUSE_FSM_EVENTS(RELEASE, FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(RELEASE,           "CREATED",         "RELEASE"  , "DONE")
FUSE_FSM_ENTRY(RELEASE, /*ok*/    {"RELEASE",f1},    {"DONE",f2} , FUSE_FSM_BAD)           
FUSE_FSM_LAST (RELEASE, /*error*/ {"DONE",f2},       {"DONE",f2} , FUSE_FSM_BAD)


FUSE_FSM_EVENTS(RELEASE_UNLINK, FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(RELEASE_UNLINK, "CREATED",         "RELEASE"        , "UNLINK"    , "DONE")
FUSE_FSM_ENTRY(RELEASE_UNLINK,  /*ok*/           {"RELEASE",f1},    {"UNLINK",f3}    , {"DONE",f2} , FUSE_FSM_BAD)           
FUSE_FSM_LAST (RELEASE_UNLINK, /*error*/        {"UNLINK",f3},       {"UNLINK",f3}  , {"DONE",f2} , FUSE_FSM_BAD)


int fuse_do_release(fuse_req_t req, struct fuse *f, fuse_ino_t ino, const char *path, struct fuse_file_info *fi)
{
    struct node *node;
    char *unlinkpath = NULL;    
    //////////////////////////////////////////////////////////////////////////

    int do_unlink = 0;
    pthread_mutex_lock(&f->lock);
    node = get_node(f, ino);
    assert(node->open_count > 0);
    node_remove_filehandle(node, fi->fh);
    if (node->is_hidden && !node->open_count && !node->is_deleted_from_backend) {
        node->is_hidden = 0;
        if (path || f->conf.nopath) {
            if (get_path(f, ino, &unlinkpath) == 0)
                do_unlink = 1;
        }
    }
    pthread_mutex_unlock(&f->lock);
    //////////////////////////////////////////////////////////////////////////
    struct fuse_fsm *new_fsm = NULL;
    if (do_unlink){
        FUSE_FSM_ALLOC(RELEASE_UNLINK, new_fsm, struct fsm_release_data);
    }else{
        FUSE_FSM_ALLOC(RELEASE, new_fsm, struct fsm_release_data);
    }

    struct fsm_release_data *dt = (struct fsm_release_data*)new_fsm->data;
    dt->f = f;
    dt->ino = ino;
    dt->fi = *fi;
    dt->unlinkpath = unlinkpath;
    dt->req = req;
    dt->path = path;
    dt->self = new_fsm;

    fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
    if (fuse_fsm_is_done(new_fsm)){
        FUSE_FSM_FREE(new_fsm);
        return 0;
    }
    return FUSE_LIB_ERROR_PENDING_REQ;
}



void fuse_lib_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err = 0;

    get_path_nullok(f, ino, &path);
    if (fi->flush) {
        err = fuse_flush_common(f, req, ino, path, fi);
        if (err == -ENOSYS)
            err = 0;
    }
    fuse_do_release(req, f, ino, path, fi);
}
