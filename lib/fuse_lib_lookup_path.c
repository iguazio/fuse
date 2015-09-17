#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
/*/////////////////////////////////////////////////////////////////////////
                states
events          CREATED         FGETS_SENT          GETS_SENT         DESTROYED    
                -------         ---------           ---------         ---------
send_fget       FGETS_SENT(f1)  NONE                NONE            
send_get        GETS_SENT(f2)   NONE                NONE            
ok              SUCCEDED(f3)    SUCCEDED(f3)        SUCCEDED(f3)      
error           FAILED(f3)      FAILED(f3)          FAILED(f3)        
/////////////////////////////////////////////////////////////////////////*/


struct fsm_lookup_path_data{
    struct fuse_fsm *parent_fsm;
    struct fuse_fsm *i_am;
    struct fuse_entry_param *e;
    const char *path;
    const char *name;
    struct fuse * f;
    struct fuse_file_info *fi;
    fuse_ino_t nodeid;
    int err;
};

#pragma GCC diagnostic ignored "-Wunused-parameter"

static void f1(const char * from,const char * to,void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;
    dt->err = fuse_fs_fgetattr(dt->f->fs, dt->path, &dt->e->attr, dt->fi);
}

static void f2(const char * from,const char * to,void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;
    dt->err = fuse_fs_getattr(dt->f->fs, dt->path, &dt->e->attr);
}

static void f3(const char * from,const char * to,void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;

    int res = do_lookup(dt->f, dt->nodeid, dt->name, dt->e);
    if (res == 0 && dt->f->conf.debug) {
        fprintf(stderr, "   NODEID: %llu\n",
            (unsigned long long) dt->e->ino);
    }
    if (dt->parent_fsm)
        fuse_fsm_run(dt->parent_fsm, "ok");
}

static void f4(const char * from,const char * to,void *data){
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data *)data;
    if (dt->parent_fsm)
        fuse_fsm_run(dt->parent_fsm, "error");
}

FUSE_FSM_EVENTS(LOOKUP_PATH,"send_fget","send_get","ok","error")
FUSE_FSM_STATES(LOOKUP_PATH,        "CREATED",    "FGETS"     ,"GETS"     ,"DONE")
FUSE_FSM_ENTRY(/*"send_fget"*/      {"FGETS",f1}, NONE        ,NONE       ,NONE)           
FUSE_FSM_ENTRY(/*"send_get"*/       {"GETS",f2},  NONE        ,NONE       ,NONE)           
FUSE_FSM_ENTRY(/*"ok"*/             {"DONE",f3},  {"DONE",f3} ,{"DONE",f3},NONE)           
FUSE_FSM_LAST (/*"error"*/          {"DONE",f4},  {"DONE",f4} ,{"DONE",f4},NONE)           




int lookup_path(struct fuse_fsm *parent, 
            struct fuse *f, fuse_ino_t nodeid, const char *name, const char *path, struct fuse_entry_param *e, struct fuse_file_info *fi )
{
    struct fuse_fsm *new_fsm = NULL;
    FUSE_FSM_ALLOC(LOOKUP_PATH,new_fsm,struct fsm_lookup_path_data);
    struct fsm_lookup_path_data *dt = (struct fsm_lookup_path_data*)new_fsm->data;

    memset(e, 0, sizeof(struct fuse_entry_param));


    dt->f = f;
    dt->fi = fi;
    dt->nodeid = nodeid;
    dt->parent_fsm = parent;
    dt->name = name;
    dt->path = path;
    dt->i_am = new_fsm;
    dt->e = e;
    
    fuse_fsm_run(new_fsm, (fi)? "send_fget" : "send_get");
    if (dt->err == FUSE_LIB_ERROR_PENDING_REQ)
        fuse_async_add_pending(new_fsm);

    if (!strcmp(fuse_fsm_cur_state(new_fsm),"DONE")){
        if(parent)
            fuse_fsm_run(parent, (dt->err)? "error" : "ok");
        FUSE_FSM_FREE(new_fsm);
    }
    return dt->err;
}


