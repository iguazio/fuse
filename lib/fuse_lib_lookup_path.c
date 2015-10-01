#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"


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


static const char* f1(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;
    int err;
    if(dt->has_fi)
        err = fuse_fs_fgetattr(fsm, dt->f->fs, dt->path, &dt->e->attr, &dt->fi);
    else
        err = fuse_fs_getattr(fsm, dt->f->fs, dt->path, &dt->e->attr);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return NULL;
    fuse_fsm_set_err(fsm, err);
    return (err)?"error":"ok";
}


static const char* f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;

    int res = do_lookup(dt->f, dt->nodeid, dt->name, dt->e);
    if (res == 0 && dt->f->conf.debug) {
        fprintf(stderr, "   NODEID: %llu\n",
            (unsigned long long) dt->e->ino);
    }
    if (dt->parent)
        fuse_fsm_run(dt->parent, "ok");
	return NULL;
}

static const char* f4(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;
    int err = fuse_fsm_get_err(fsm);
    if (dt->parent){
        fuse_fsm_set_err(dt->parent,err);
        fuse_fsm_run(dt->parent, "error");
    }
	return NULL;
}

FUSE_FSM_EVENTS(LOOKUP_PATH,"ok","error")
FUSE_FSM_STATES(LOOKUP_PATH,        "CREATED",    "GETS"     ,"DONE")
FUSE_FSM_ENTRY(/*"ok"*/             {"GETS",f1},  {"DONE",f3},NONE)           
FUSE_FSM_LAST (/*"error"*/          {"DONE",f4},  {"DONE",f4},NONE)           




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
    dt->nodeid = nodeid;
    dt->parent = parent;
    dt->name = name;
    dt->path = path;
    dt->e = e;
    
    fuse_fsm_run(new_fsm, "ok");
    if (!strcmp(fuse_fsm_cur_state(new_fsm),"DONE")){
        FUSE_FSM_FREE(new_fsm);
        return 0;
    }
    return FUSE_LIB_ERROR_PENDING_REQ;
}


