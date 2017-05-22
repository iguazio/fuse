#include "fuse_lib.h"
#include "fuse_fsm.h"

struct fsm_hide_node_data{
    struct fuse_fsm *parent;
    struct stat buf;
    fuse_ino_t dir;
    char newname[64];

    struct fuse * f;
    char *newpath;
    const char *oldpath;
    const char *oldname;
};


static struct fuse_fsm_event f1(struct fuse_fsm* fsm,void *data){
    struct fsm_hide_node_data *dt = (struct fsm_hide_node_data *)data;
    int err;

    err = fuse_fs_getattr(fsm, dt->f->fs, dt->newpath, &dt->buf);
    if (err == FUSE_LIB_ERROR_PENDING_REQ){
        return FUSE_FSM_EVENT_NONE;
    }
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR: FUSE_FSM_EVENT_OK;
}
 
static struct fuse_fsm_event f11(struct fuse_fsm* fsm,void *data){
    struct fsm_hide_node_data *dt = (struct fsm_hide_node_data *)data;
    int err = fuse_fsm_get_err(fsm);
    if (err == -ENOENT){
        err = fuse_fs_rename(fsm, dt->f->fs, dt->oldpath, dt->newpath, 0);
        if (err == FUSE_LIB_ERROR_PENDING_REQ)
            return FUSE_FSM_EVENT_NONE;
        fuse_fsm_set_err(fsm, 0);
    }else
        err = -EBUSY;
        
    fuse_fsm_set_err(fsm, err);
    return (err)? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_hide_node_data *dt = (struct fsm_hide_node_data *)data;
    int err;

    err = rename_node(dt->f, dt->dir, dt->oldname, dt->dir, dt->newname, 1);
    if(dt->newpath)
        fuse_free(dt->newpath);
    FUSE_FSM_MARK_PENDING(dt->parent, (err)? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK);
    return FUSE_FSM_EVENT_NONE;
}

static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_hide_node_data *dt = (struct fsm_hide_node_data *)data;
    if(dt->newpath)
        fuse_free(dt->newpath);
    FUSE_FSM_MARK_PENDING(dt->parent, FUSE_FSM_EVENT_ERROR);
    return FUSE_FSM_EVENT_NONE;
}

//f1 - try to make a new filename by checking it does not exists
//f11 - in case does not exists - rename it
//f2 - rename succeeded - feed parent fsm with FUSE_FSM_EVENT_OK event
//f3 - rename succeeded - feed parent fsm with FUSE_FSM_EVENT_ERROR event


FUSE_FSM_EVENTS(HIDE_NODE,FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(HIDE_NODE,          "CREATED",       "CHK_EXST"     ,"REN"      ,"DONE")
FUSE_FSM_ENTRY(HIDE_NODE,/*FUSE_FSM_EVENT_OK*/  {"CHK_EXST",f1}, {"REN",f11}    ,{"DONE",f2},FUSE_FSM_BAD)           
FUSE_FSM_LAST(HIDE_NODE,/*FUSE_FSM_EVENT_ERROR*/ {"DONE",f3},     {"REN",f11}    ,{"DONE",f3},FUSE_FSM_BAD)           



/*
static char * hidden_name( struct fuse_fsm* parent , struct fuse *f, fuse_ino_t dir, const char *oldname, char *newname, size_t bufsize )
{
    struct stat buf;
    struct node *node;
    struct node *newnode;
    char *newpath;
    int res;
    int failctr = 10;

    do {
        pthread_mutex_lock(&f->lock);
        node = lookup_node(f, dir, oldname);
        if (node == NULL) {
            pthread_mutex_unlock(&f->lock);
            return NULL;
        }
        do {
            f->hidectr ++;
            snprintf(newname, bufsize, ".fuse_hidden%08x%08x",
                (unsigned int) node->nodeid, f->hidectr);
            newnode = lookup_node(f, dir, newname);
        } while(newnode);

        res = try_get_path(f, dir, newname, &newpath, NULL, false);
        pthread_mutex_unlock(&f->lock);
        if (res)
            break;

        memset(&buf, 0, sizeof(buf));
        res = fuse_fs_getattr(fsm, f->fs, newpath, &buf);
        if (res == -ENOENT)
            break;
        fuse_free(newpath);
        newpath = NULL;
    } while(res == 0 && --failctr);

    return newpath;
}
*/



int hide_node( struct fuse_fsm* parent , struct fuse *f, const char *oldpath, fuse_ino_t dir, const char *oldname )
{
    struct fuse_fsm *new_fsm = NULL;
    FUSE_FSM_ALLOC(HIDE_NODE,new_fsm,struct fsm_hide_node_data);
    struct fsm_hide_node_data *dt = (struct fsm_hide_node_data *)new_fsm->data;

    char *newpath;
    int err = -EBUSY;


    struct node *node;
    struct node *newnode;

    pthread_mutex_lock(&f->lock);
    node = lookup_node(f, dir, oldname);
    if (node == NULL){
        pthread_mutex_unlock(&f->lock);
        FUSE_FSM_FREE(new_fsm);
        fuse_fsm_set_err(parent,-EBUSY);
        FUSE_FSM_MARK_PENDING(parent, FUSE_FSM_EVENT_ERROR);
        return -EBUSY;
    }
    do {
        f->hidectr ++;
        snprintf(dt->newname,  sizeof(dt->newname), ".fuse_hidden%08x%08x",
            (unsigned int) node->nodeid, f->hidectr);
        newnode = lookup_node(f, dir, dt->newname);
    } while(newnode);

    err = try_get_path(f, dir, dt->newname, &newpath, NULL, false);
    pthread_mutex_unlock(&f->lock);
    if (err){
        pthread_mutex_unlock(&f->lock);
        FUSE_FSM_FREE(new_fsm);
        fuse_fsm_set_err(parent,-EBUSY);
        FUSE_FSM_MARK_PENDING(parent, FUSE_FSM_EVENT_ERROR);
        return err;
    }

    dt->f = f;
    dt->parent = parent;
    dt->newpath = newpath;
    dt->oldpath = oldpath;
    dt->dir = dir;

    dt->oldname=oldname;
    dt->newpath=newpath;



    fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
    if (fuse_fsm_is_done(new_fsm)){
        FUSE_FSM_FREE(new_fsm);
        return 0;
    }
    return FUSE_LIB_ERROR_PENDING_REQ;
}

