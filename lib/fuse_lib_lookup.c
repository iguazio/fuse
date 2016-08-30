#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
#include "fuse_log.h"


struct fsm_lookup_data{
    struct fuse_fsm *owner;
    struct fuse_intr_data d;
    struct fuse *f;
    fuse_ino_t parent;
    const char *path;
    char *name;
    struct fuse_entry_param e;  
    fuse_req_t req;
    struct node *dot;

};

static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_lookup_data *dt = (struct fsm_lookup_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = lookup_path(dt->owner,dt->f, dt->parent, dt->name, dt->path, &dt->e, NULL);
    if (err == FUSE_LIB_ERROR_PENDING_REQ){
        fuse_fsm_free_on_done(dt->owner,1);
        return FUSE_FSM_EVENT_NONE;
    }
    fuse_fsm_set_err(fsm, err);
    return FUSE_FSM_EVENT_NONE;//lookup_path() triggers FUSE_FSM_EVENT_OK or FUSE_FSM_EVENT_ERROR events , so no need to return event ID

}
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_lookup_data *dt = (struct fsm_lookup_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->parent, (char*)dt->path);
    fuse_free(dt->name);

    reply_entry(dt->req, &dt->e, 0);
    if (dt->dot) {
        pthread_mutex_lock(&dt->f->lock);
        unref_node(dt->f, dt->dot);
        pthread_mutex_unlock(&dt->f->lock);
    }
	return FUSE_FSM_EVENT_NONE;
}

static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_lookup_data *dt = (struct fsm_lookup_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->parent, (char*)dt->path);
    fuse_free(dt->name);
    int err = fuse_fsm_get_err(fsm);
    if (err == -ENOENT && dt->f->conf.negative_timeout != 0.0){
        dt->e.ino = 0;
        dt->e.entry_timeout = dt->f->conf.negative_timeout;
        err = 0;
    }
    reply_err(dt->req, err);
    if (dt->dot) {
        pthread_mutex_lock(&dt->f->lock);
        unref_node(dt->f, dt->dot);
        pthread_mutex_unlock(&dt->f->lock);
    }
	return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(LOOKUP, FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(LOOKUP,         "CREATED",         "LOOK_PATH" , "DONE")
FUSE_FSM_ENTRY(LOOKUP,/*ok*/    {"LOOK_PATH",f1},  {"DONE",f2} , FUSE_FSM_BAD)           
FUSE_FSM_LAST (LOOKUP,/*error*/ {"DONE",f3},       {"DONE",f3} , FUSE_FSM_BAD)


void fuse_lib_lookup(fuse_req_t req, fuse_ino_t parent,
                            const char *name)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int err;
    struct node *dot = NULL;
    struct fuse_entry_param ee;

    if (name[0] == '.' ) {
        int len = strlen(name);
        if (len == 1 || (name[1] == '.' && len == 2)) {
            pthread_mutex_lock(&f->lock);
            if (len == 1) {
                if (f->conf.debug)
                    fuse_log_debug( "LOOKUP-DOT\n");
                dot = get_node_nocheck(f, parent);
                if (dot == NULL) {
                    pthread_mutex_unlock(&f->lock);
                    reply_entry(req, &ee, -ESTALE);
                    return;
                }
                dot->refctr++;
            } else {
                if (f->conf.debug)
                    fuse_log_debug( "LOOKUP-DOTDOT\n");
                parent = get_node(f, parent)->parent->nodeid;
            }
            pthread_mutex_unlock(&f->lock);
            name = NULL;
        }
    }

    err = get_path_name(f, parent, name, &path);
    if (!err) {

        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(LOOKUP,new_fsm,struct fsm_lookup_data);
        struct fsm_lookup_data *dt = (struct fsm_lookup_data*)new_fsm->data;

        dt->f = f;
        dt->parent = parent;
        dt->path = path;
        dt->req = req;
        dt->owner = new_fsm;
        dt->dot = dot;
        dt->name = fuse_strdup(name);


        if (f->conf.debug)
            fuse_log_debug( "LOOKUP %s\n", path);
        
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }else{
        reply_err(req,err);
        if (dot) {
            pthread_mutex_lock(&f->lock);
            unref_node(f, dot);
            pthread_mutex_unlock(&f->lock);
        }
    }
}
