#include "fuse_lib.h"
#include "fuse_lib_lookup_path.h"
struct fsm_rename_data{
    const char *oldpath;
    const char *newpath;
    int flags;
    struct fuse *f;
    struct node *wnode1;
    struct node *wnode2;
    fuse_ino_t olddir;
    const char *oldname;
    fuse_ino_t newdir;
    const char *newname;
    fuse_req_t req;
    struct fuse_intr_data d;
};

/*Send request to the fs*/
static const char* f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_rename(fsm, dt->f->fs, dt->oldpath, dt->newpath, dt->flags);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return NULL;
    fuse_fsm_set_err(fsm, err);
    return (err)?"error":"ok";
}


static const char* f10(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    int err;
    if (dt->flags & RENAME_EXCHANGE) {
        err = exchange_node(dt->f, dt->olddir, dt->oldname,
            dt->newdir, dt->newname);
    } else {
        err = rename_node(dt->f, dt->olddir, dt->oldname,
            dt->newdir, dt->newname, 0);
    }
    free_path2(dt->f, dt->olddir, dt->newdir, dt->wnode1, dt->wnode2,(char*) dt->oldpath, (char*)dt->newpath);
    reply_err(dt->req, err);
    return NULL;
}


static const char* f13(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    int err = fuse_fsm_get_err(fsm);

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path2(dt->f, dt->olddir, dt->newdir, dt->wnode1, dt->wnode2,(char*) dt->oldpath, (char*)dt->newpath);
    reply_err(dt->req, err);
    return NULL;
}



//f1 - send fuse_fs_rename
//f10 - Replay to the driver - success 
//f13 - Replay to the driver - error


FUSE_FSM_EVENTS(RENAME,   "ok", "error")
FUSE_FSM_STATES(RENAME,    "START",         "REN"     ,"DONE")
FUSE_FSM_ENTRY(RENAME,  /*ok*/	    {"REN",f1}     ,{"DONE",f10} , FUSE_FSM_BAD)
FUSE_FSM_LAST(RENAME,   /*error*/{"DONE",f13},    {"DONE",f13}  , FUSE_FSM_BAD)
/*
__attribute__((constructor)) static void fuse_fsm_init_RENAME(void) {
    int i;
    int j;
    int num_of_states = sizeof(fuse_fsm_states_RENAME)/sizeof(char*);
    for (i = 0;i<sizeof(fuse_fsm_transition_table_RENAME)/sizeof(struct fuse_fsm_entry);i++){
        struct fuse_fsm_entry* p = ((struct fuse_fsm_entry*)fuse_fsm_transition_table_RENAME);
        const char *state = ((struct fuse_fsm_entry*)fuse_fsm_transition_table_RENAME)[i].next_state;
        for (j=0; j<num_of_states; j++){
            if (!strcmp(fuse_fsm_states_RENAME[j],state))
                p[i].next_state_id = j;
        }
    }
}
*/

void fuse_lib_rename(fuse_req_t req, fuse_ino_t olddir,
                            const char *oldname, fuse_ino_t newdir,
                            const char *newname, unsigned int flags)
{
    struct fuse *f = req_fuse_prepare(req);
    char *oldpath;
    char *newpath;
    struct node *wnode1;
    struct node *wnode2;
    int err;


    err = get_path2(f, olddir, oldname, newdir, newname,
        &oldpath, &newpath, &wnode1, &wnode2);

    if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(RENAME, new_fsm, struct fsm_rename_data);
        struct fsm_rename_data *dt = (struct fsm_rename_data*)new_fsm->data;



        dt->f = f;
        dt->req = req;
        dt->oldpath = oldpath;
        dt->newpath = newpath;
        dt->wnode1 = wnode1;
        dt->wnode2 = wnode2;
        dt->olddir = olddir;
        dt->oldname = oldname;
        dt->newdir = newdir;
        dt->newname = newname;
        dt->flags = flags;

        if (!f->conf.hard_remove && !(flags & RENAME_EXCHANGE) && is_open(f, newdir, newname))
            err = hide_node(new_fsm, f, newpath, newdir, newname);
        else
            fuse_fsm_run(new_fsm, "ok");

        if (err == FUSE_LIB_ERROR_PENDING_REQ)
            return;

        if (!strcmp(fuse_fsm_cur_state(new_fsm),"DONE"))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, err);

}
