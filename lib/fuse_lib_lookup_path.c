#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
#include "fuse_log.h"


struct fsm_lookup_path_data{
    struct fuse_fsm *parent;
    struct fuse_entry_param *e;
    const char *path;
    const char *name;
    struct fuse * f;
    struct fuse_file_info fi;
    int has_fi;
    fuse_ino_t nodeid;
};


static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;
    int err;
    if(dt->has_fi)
        err = fuse_fs_fgetattr(fsm, dt->f->fs, dt->path, &dt->e->attr, &dt->fi);
    else
        err = fuse_fs_getattr(fsm, dt->f->fs, dt->path, &dt->e->attr);
    if (err == FUSE_LIB_ERROR_PENDING_REQ){
        return FUSE_FSM_EVENT_NONE;
    }
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}


static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;
    int res = do_lookup(dt->f, dt->nodeid, dt->name, dt->e);
    if (res == 0 && dt->f->conf.debug) {
        fuse_log_debug( "   NODEID: %llu\n",
            (unsigned long long) dt->e->ino);
    }
    if (dt->parent)
        FUSE_FSM_MARK_PENDING(dt->parent, FUSE_FSM_EVENT_OK);
	return FUSE_FSM_EVENT_NONE;
}

static struct fuse_fsm_event f4(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;
    int err = fuse_fsm_get_err(fsm);
    if (dt->parent){
        fuse_fsm_set_err(dt->parent,err);
        FUSE_FSM_MARK_PENDING(dt->parent, FUSE_FSM_EVENT_ERROR);
    }
	return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(LOOKUP_PATH,FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(LOOKUP_PATH,            "CREATED",    "GETS"     ,"DONE")
FUSE_FSM_ENTRY(LOOKUP_PATH, /*FUSE_FSM_EVENT_OK*/  {"GETS",f1},  {"DONE",f3},FUSE_FSM_BAD)           
FUSE_FSM_LAST (LOOKUP_PATH,/*FUSE_FSM_EVENT_ERROR*/{"DONE",f4},  {"DONE",f4},FUSE_FSM_BAD)           




int lookup_path(struct fuse_fsm *parent, 
            struct fuse *f, fuse_ino_t nodeid, const char *name, const char *path, struct fuse_entry_param *e, struct fuse_file_info *fi )
{
    struct fuse_fsm *new_fsm = NULL;
    FUSE_FSM_ALLOC(LOOKUP_PATH,new_fsm,struct fsm_lookup_path_data);
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data*)new_fsm->data;

    memset(e, 0, sizeof(struct fuse_entry_param));

    dt->f = f;
    dt->has_fi = (fi != NULL);
    if(dt->has_fi)
        dt->fi = *fi;
    dt->name = name;
    dt->nodeid = nodeid;
    dt->parent = parent;
    dt->path = path;
    dt->e = e;
    
    fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
    if (fuse_fsm_is_done(new_fsm)){
        int res = fuse_fsm_get_err(new_fsm);
        FUSE_FSM_FREE(new_fsm);
        return res;
    }
    return FUSE_LIB_ERROR_PENDING_REQ;
}


