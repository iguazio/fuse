#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

struct fsm_lookup_data{
    struct fuse_fsm *owner;
    struct fuse *f;
    fuse_ino_t parent;
    const char *name;
    const char *path;
    struct fuse_entry_param e;  
    fuse_req_t req;
    int err;
};

static const char* f1(const char * from,const char * to,void *data){
    struct fsm_lookup_data *dt = (struct fsm_lookup_data *)data;
    dt->err = lookup_path(dt->owner,dt->f, dt->parent, dt->name, dt->path, &dt->e, NULL);
	return NULL;

}
static const char* f2(const char * from,const char * to,void *data){
    struct fsm_lookup_data *dt = (struct fsm_lookup_data *)data;
    dt->err = 0;
    reply_entry(dt->req, &dt->e, dt->err);
	return NULL;

}

static const char* f3(const char * from,const char * to,void *data){
    struct fsm_lookup_data *dt = (struct fsm_lookup_data *)data;
    if (dt->err == -ENOENT && dt->f->conf.negative_timeout != 0.0){
        dt->e.ino = 0;
        dt->e.entry_timeout = dt->f->conf.negative_timeout;
        dt->err = 0;
    }
    reply_entry(dt->req, &dt->e, dt->err);
	return NULL;

}

FUSE_FSM_EVENTS(LOOKUP, "lookup","ok","error")
FUSE_FSM_STATES(LOOKUP,  "CREATED",         "LOOK_PATH" , "DONE")
FUSE_FSM_ENTRY(/*lookup*/{"LOOK_PATH",f1},  NONE        , NONE)           
FUSE_FSM_ENTRY(/*ok*/    {"DONE",f2},       {"DONE",f2} , NONE)           
FUSE_FSM_LAST (/*error*/ {"DONE",f3},       {"DONE",f3} , NONE)


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
                    fprintf(stderr, "LOOKUP-DOT\n");
                dot = get_node_nocheck(f, parent);
                if (dot == NULL) {
                    pthread_mutex_unlock(&f->lock);
                    reply_entry(req, &ee, -ESTALE);
                    return;
                }
                dot->refctr++;
            } else {
                if (f->conf.debug)
                    fprintf(stderr, "LOOKUP-DOTDOT\n");
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
        dt->name = name;
        dt->parent = parent;
        dt->path = path;
        dt->req = req;
        dt->owner = new_fsm;


        struct fuse_intr_data d;
        if (f->conf.debug)
            fprintf(stderr, "LOOKUP %s\n", path);
        
        fuse_prepare_interrupt(f, req, &d);
        fuse_fsm_run(new_fsm, "lookup");
        fuse_finish_interrupt(f, req, &d);

        if (!strcmp(fuse_fsm_cur_state(new_fsm),"DONE")){
            fuse_fsm_run(new_fsm, (dt->err)? "error" : "ok");
            FUSE_FSM_FREE(new_fsm);
        }
        err = dt->err;
    }
    free_path(f, parent, path);

    if (dot) {
        pthread_mutex_lock(&f->lock);
        unref_node(f, dot);
        pthread_mutex_unlock(&f->lock);
    }
}
