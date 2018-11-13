#include "fuse_lib.h"
#include "fuse_misc.h"
#include "fuse_lib_lookup_path.h"
#include "fuse_fsm.h"
#define BUF_SIZE (512*1024)
#define FUSE_FSM_EVENT_COMPLETED_D { 2,"completed"}
static const struct fuse_fsm_event FUSE_FSM_EVENT_COMPLETED = FUSE_FSM_EVENT_COMPLETED_D;

#define min(a,b)                    \
   ({ __typeof__ (a) _a = (a);      \
       __typeof__ (b) _b = (b);     \
     _a < _b ? _a : _b; })

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
    char *newname;
    fuse_req_t req;
    struct fuse_intr_data d;
    // cpoy+delele implementation
    char *io_buf;
    size_t cur_offset;
    size_t actually_read;
    struct fuse_file_info src_finfo;
    struct fuse_file_info dst_finfo;
    struct stat src_stat;
    struct stat src_stat_after;
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


static struct fuse_fsm_event f10(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
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
    fuse_free(dt->newname);
    reply_err(dt->req, err);
    if (dt->io_buf)
        fuse_free(dt->io_buf);
    return FUSE_FSM_EVENT_NONE;
}


static struct fuse_fsm_event f13(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    update_err(dt->err, fsm);
    int err = dt->err;

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path2(dt->f, dt->olddir, dt->newdir, dt->wnode1, dt->wnode2,(char*) dt->oldpath, (char*)dt->newpath);
    fuse_free(dt->newname);
    reply_err(dt->req, err);
    if (dt->io_buf)
        fuse_free(dt->io_buf);
    return FUSE_FSM_EVENT_NONE;
}

static struct fuse_fsm_event opnsrc(struct fuse_fsm* fsm __attribute__((unused)), void *data) 
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    if (S_ISDIR(dt->src_stat.st_mode)) {
        fuse_fsm_set_err(fsm, -EOPNOTSUPP);
        update_err(dt->err, fsm);
        return FUSE_FSM_EVENT_ERROR;
    }

    update_err(dt->err, fsm);
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    dt->src_finfo.flags = O_RDONLY;
    int err = fuse_fs_open(fsm, dt->f->fs, dt->oldpath, &dt->src_finfo);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}
static struct fuse_fsm_event opndst(struct fuse_fsm* fsm __attribute__((unused)), void *data)
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    update_err(dt->err, fsm);
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    dt->dst_finfo.flags = O_WRONLY | O_CREAT;
    int err = fuse_fs_create(fsm, dt->f->fs, dt->newpath, S_IWUSR , &dt->dst_finfo);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}
static struct fuse_fsm_event rd(struct fuse_fsm* fsm __attribute__((unused)), void *data)
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    update_err(dt->err, fsm);
    size_t size = min(dt->src_stat.st_size - dt->cur_offset, BUF_SIZE);
    if (size == 0)
        return FUSE_FSM_EVENT_COMPLETED;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    if (dt->io_buf == NULL)
        dt->io_buf = fuse_malloc(BUF_SIZE);
    dt->src_finfo.flags = O_RDONLY;
    int err = dt->f->fs->op.read(fsm, dt->oldpath, dt->io_buf, size, dt->cur_offset, &dt->src_finfo);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event wt(struct fuse_fsm* fsm __attribute__((unused)), void *data)
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    update_err(dt->err, fsm);
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    size_t size = min(dt->src_stat.st_size - dt->cur_offset, BUF_SIZE);
    int err = fuse_fs_write(fsm, dt->f->fs, dt->newpath, dt->io_buf, size, dt->cur_offset, &dt->dst_finfo);
    dt->cur_offset += size;
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event clsdst(struct fuse_fsm* fsm __attribute__((unused)), void *data)
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    if (dt->dst_finfo.fh == 0 || dt->dst_finfo.fh == UINT64_MAX)
        return FUSE_FSM_EVENT_OK;
    update_err(dt->err, fsm);
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_release(fsm, dt->f->fs, dt->newpath, &dt->dst_finfo);
    dt->dst_finfo.fh = UINT64_MAX;
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event clsrc(struct fuse_fsm* fsm __attribute__((unused)), void *data)
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    if (dt->src_finfo.fh == 0 || dt->src_finfo.fh == UINT64_MAX)
        return FUSE_FSM_EVENT_OK;
    update_err(dt->err, fsm);
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_release(fsm, dt->f->fs, dt->oldpath, &dt->src_finfo);
    dt->src_finfo.fh = UINT64_MAX;
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

/*Send request to the fs to delete target*/
static struct fuse_fsm_event deldst(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    update_err(dt->err, fsm);
    int err = fuse_fs_unlink(fsm, dt->f->fs, dt->newpath);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event delsrc(struct fuse_fsm* fsm __attribute__((unused)), void *data)
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    update_err(dt->err, fsm);
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_unlink(fsm, dt->f->fs, dt->oldpath);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event prop(struct fuse_fsm* fsm __attribute__((unused)), void *data)
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    // This is the start of the 'copy + delete' implementation. Reset the error 
    fuse_fsm_set_err(fsm, 0);
    dt->err = 0;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_getattr(fsm, dt->f->fs, dt->oldpath, &dt->src_stat);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event prop2(struct fuse_fsm* fsm __attribute__((unused)), void *data)
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    update_err(dt->err, fsm);
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fs_getattr(fsm, dt->f->fs, dt->oldpath, &dt->src_stat_after);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event verify(struct fuse_fsm* fsm __attribute__((unused)), void *data)
{
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    if (dt->src_stat.st_mtime != dt->src_stat_after.st_mtime) 
    {
        fuse_fsm_set_err(fsm, -EBUSY);
        update_err(dt->err, fsm);
        return FUSE_FSM_EVENT_ERROR;
    }
    return FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event chmd(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    update_err(dt->err, fsm);
    int err = fuse_fs_chmod(fsm, dt->f->fs, dt->newpath, dt->src_stat.st_mode);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event chwn(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    update_err(dt->err, fsm);
    int err = fuse_fs_chown(fsm, dt->f->fs,  dt->newpath, dt->src_stat.st_uid,  dt->src_stat.st_gid);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}

static struct fuse_fsm_event chutim(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_rename_data *dt = (struct fsm_rename_data *)data;
    struct timespec tv[2];
    update_err(dt->err, fsm);
    tv[0].tv_sec = dt->src_stat.st_atime;
    tv[0].tv_nsec = ST_ATIM_NSEC(&dt->src_stat);
    tv[1].tv_sec = dt->src_stat.st_mtime;
    tv[1].tv_nsec = ST_MTIM_NSEC(&dt->src_stat);
    int err = fuse_fs_utimens(fsm, dt->f->fs, dt->newpath, tv);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    update_err(dt->err, fsm);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}


FUSE_FSM_EVENTS(RENAME, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR, FUSE_FSM_EVENT_COMPLETED_D)

//f10 - Replay to the driver - success 
//f13 - Replay to the driver - error

FUSE_FSM_STATES(RENAME,          "START"    ,   "REN"        , "GETPROP"          , "OPENSRC"         , "OPENDST"         , "READ"            , "WRITE"           , "CLOSEDST"        , "CLOSESRC"        , "GETPROP2"         , "VERIFY"          , "CHOWN"           , "UTIME"           , "CHMODE"          , "DELSRC"          , "ECLSDST"        , "EDELDST"         , "ECLSRC"   ,"DONE"        )
FUSE_FSM_ENTRY(RENAME,/*ok*/	{"REN",ren} ,{"DONE",f10}    ,{"OPENSRC",opnsrc}  ,{"OPENDST",opndst} ,{"READ",rd}        ,{"WRITE",wt}       ,{"READ",rd}        ,{"CLOSESRC",clsrc} ,{"GETPROP2",prop2} ,{"VERIFY",verify}   ,{"CHOWN",chwn}     ,{"UTIME",chutim}   ,{"CHMODE",chmd}    ,{"DELSRC",delsrc}  ,{"DONE",f10}       ,{"EDELDST",deldst},{"ECLSRC",clsrc}   ,{"DONE",f13}, FUSE_FSM_BAD )
FUSE_FSM_ENTRY(RENAME,/*error*/ {"DONE",f13},{"GETPROP",prop},{"DONE",f13}        ,{"DONE",f13}       ,{"ECLSRC",clsrc}   ,{"ECLSDST",clsdst} ,{"ECLSDST",clsdst} ,{"EDELDST",deldst} ,{"EDELDST",deldst} ,{"EDELDST",deldst}  ,{"EDELDST",deldst} ,{"EDELDST",deldst} ,{"EDELDST",deldst} ,{"EDELDST",deldst} ,{"EDELDST",deldst} ,{"EDELDST",deldst},{"ECLSRC",clsrc}   ,{"DONE",f13}, FUSE_FSM_BAD )
FUSE_FSM_LAST(RENAME, /*done*/ FUSE_FSM_BAD ,FUSE_FSM_BAD    ,FUSE_FSM_BAD        ,FUSE_FSM_BAD       ,FUSE_FSM_BAD       ,{"CLOSEDST",clsdst},FUSE_FSM_BAD       ,FUSE_FSM_BAD       ,FUSE_FSM_BAD       ,FUSE_FSM_BAD        ,FUSE_FSM_BAD       ,FUSE_FSM_BAD       ,FUSE_FSM_BAD       ,FUSE_FSM_BAD       ,FUSE_FSM_BAD       ,FUSE_FSM_BAD      ,FUSE_FSM_BAD       ,FUSE_FSM_BAD, FUSE_FSM_BAD )

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
