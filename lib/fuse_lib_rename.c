#include "fuse_lib.h"
#include "fuse_misc.h"
#include "fuse_lib_lookup_path.h"
#include "fuse_fsm.h"
#include "fuse_log.h"

struct fsm_rename_data{
    const char *oldpath;
    const char *newpath;
    int flags;
    struct fuse *f;
    struct node *wnode1;
    struct node *wnode2;
    fuse_ino_t olddir;
    char *oldname;
    fuse_ino_t newdir;
    char *newname;
    fuse_req_t req;
    struct fuse_intr_data d;
    int err;
};

#define update_err(_old_err,_fsm) do {if(!(_old_err)) (_old_err) = fuse_fsm_get_err(_fsm); }while(0)

/*Send request to the fs*/
static struct fuse_fsm_event ren(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_rename(fsm, dt->f->fs, dt->oldpath, dt->newpath, dt->flags);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}

extern void print_rename_trace(void);

static struct fuse_fsm_event f10(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    char f10_trace[8][4096];
    int depth1;
    int depth2;
    sprintf_node_parent_trace(f10_trace[0], dt->wnode1,depth1);
    sprintf_node_parent_trace(f10_trace[1], dt->wnode2,depth1);


    sprintf_node_parent_trace(f10_trace[2], get_node(dt->f, dt->olddir),depth1);
    sprintf_node_parent_trace(f10_trace[3], get_node(dt->f, dt->newdir),depth1);

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    int err;
    if (dt->flags & RENAME_EXCHANGE) {
        err = exchange_node(dt->f, dt->olddir, dt->oldname,
            dt->newdir, dt->newname);
    } else {
        err = rename_node(dt->f, dt->olddir, dt->oldname,
            dt->newdir, dt->newname, 0);
    }

    sprintf_node_parent_trace(f10_trace[4], dt->wnode1, depth1);
    sprintf_node_parent_trace(f10_trace[5], dt->wnode2, depth1);

    sprintf_node_parent_trace(f10_trace[6], get_node(dt->f, dt->olddir),depth1);
    sprintf_node_parent_trace(f10_trace[7], get_node(dt->f, dt->newdir),depth2);

    if (depth1 > 255 || depth2 > 255) {
        print_rename_trace();
        for (int i = 0; i < 8; i++) {
            fuse_log_err("rename f10 trace %d - %s\n", i, f10_trace[i]);
        }

    }

    free_path2(dt->f, dt->olddir, dt->newdir, dt->wnode1, dt->wnode2,(char*) dt->oldpath, (char*)dt->newpath);
    fuse_free(dt->newname);
    fuse_free(dt->oldname);
    reply_err(dt->req, err);
    return FUSE_FSM_EVENT_NONE;
}


static struct fuse_fsm_event f13(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    update_err(dt->err, fsm);
    int err = dt->err;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path2(dt->f, dt->olddir, dt->newdir, dt->wnode1, dt->wnode2,(char*) dt->oldpath, (char*)dt->newpath);
    fuse_free(dt->newname);
    fuse_free(dt->oldname);
    reply_err(dt->req, err);
    return FUSE_FSM_EVENT_NONE;
}


FUSE_FSM_EVENTS(RENAME, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)

//f10 - Replay to the driver - success 
//f13 - Replay to the driver - error

FUSE_FSM_STATES(RENAME,         "START"     , "REN"      , "DONE")
FUSE_FSM_ENTRY(RENAME,/*ok*/	{"REN",ren} ,{"DONE",f10}, FUSE_FSM_BAD)
FUSE_FSM_LAST(RENAME, /*error*/ {"DONE",f13},{"DONE",f13}, FUSE_FSM_BAD)

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
        dt->oldname = fuse_strdup(oldname);
        dt->newdir = newdir;
        dt->newname = fuse_strdup(newname);
        dt->flags = flags;

        if (!f->conf.hard_remove && !(flags & RENAME_EXCHANGE) && is_open(f, newdir, newname))
            err = hide_node(new_fsm, f, newpath, newdir, newname);
        else
            fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);

        if (err == FUSE_LIB_ERROR_PENDING_REQ)
            return;

        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, err);

}
