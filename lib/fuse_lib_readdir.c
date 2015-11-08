#include "fuse_lib.h"
static int readdir_fill_from_list(fuse_req_t req, struct fuse_dh *dh,
                                  off_t off, enum fuse_readdir_flags flags);

struct fsm_readdir_data{
    char *path;
    struct fuse * f;
    struct fuse_file_info fi;
    fuse_ino_t ino;
    fuse_req_t req;
    struct fuse_dh *dh;
    int size;
    int off;
    enum fuse_readdir_flags flags;
    int err;
};


/*Send request to the fs*/
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_readdir_data *dt = (struct fsm_readdir_data *)data;
    fuse_fill_dir_t filler = fill_dir;

    if (dt->flags & FUSE_READDIR_PLUS)
        filler = fill_dir_plus;

    free_direntries(dt->dh->first);
    dt->dh->first = NULL;
    dt->dh->last = &dt->dh->first;
    dt->dh->len = 0;
    dt->dh->error = 0;
    dt->dh->needlen = dt->size;
    dt->dh->req = dt->req;
    dt->dh->filled = 1;
//    fuse_prepare_interrupt(dt->f, dt->req, &d);
    int err = fuse_fs_readdir(fsm, dt->f->fs, dt->path, dt->dh, filler, dt->off, &dt->fi, dt->flags);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}
/*There is correct data - send it back to the driver*/
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_readdir_data *dt = (struct fsm_readdir_data *)data;
    dt->dh->req = NULL;
    if (dt->dh->error)
        dt->dh->filled = 0;
    free_path(dt->f, dt->ino, dt->path);
    pthread_mutex_lock(&dt->dh->lock);
    if (dt->dh->filled) {
        dt->dh->needlen = dt->size;
        int err = readdir_fill_from_list(dt->req, dt->dh, dt->off, dt->flags);
        if (err) {
            reply_err(dt->req, err);
            pthread_mutex_unlock(&dt->dh->lock);
            return FUSE_FSM_EVENT_ERROR;
        }
    }
    fuse_reply_buf(dt->req, dt->dh->contents, dt->dh->len);
    pthread_mutex_unlock(&dt->dh->lock);
	return FUSE_FSM_EVENT_NONE;
}

/*Error - report driver*/
static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    struct fsm_readdir_data *dt = (struct fsm_readdir_data *)data;
    int err = fuse_fsm_get_err(fsm);
    free_path(dt->f, dt->ino, dt->path);
    reply_err(dt->req, err);
	return FUSE_FSM_EVENT_NONE;
}



static int readdir_fill_from_list(fuse_req_t req, struct fuse_dh *dh,
                                  off_t off, enum fuse_readdir_flags flags)
{
    off_t pos;
    struct fuse_direntry *de = dh->first;

    dh->len = 0;

    if (extend_contents(dh, dh->needlen) == -1)
        return dh->error;

    for (pos = 0; pos < off; pos++) {
        if (!de)
            break;

        de = de->next;
    }
    while (de) {
        char *p = dh->contents + dh->len;
        unsigned rem = dh->needlen - dh->len;
        unsigned thislen;
        unsigned newlen;
        pos++;

        if (flags & FUSE_READDIR_PLUS) {
            struct fuse_entry_param e = {
                .ino = 0,
                .attr = de->stat,
            };
            thislen = fuse_add_direntry_plus(req, p, rem,
                de->name, &e, pos);
        } else {
            thislen = fuse_add_direntry(req, p, rem,
                de->name, &de->stat, pos);
        }
        newlen = dh->len + thislen;
        if (newlen > dh->needlen)
            break;
        dh->len = newlen;
        de = de->next;
    }
    return 0;
}

FUSE_FSM_EVENTS(READDIR,FUSE_FSM_EVENT_OK,FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(READDIR,          "CREATED",  "RDIR"      ,   "DONE")
FUSE_FSM_ENTRY(READDIR,/*ok*/   {"RDIR",f1},  {"DONE",f2} ,   FUSE_FSM_BAD)           
FUSE_FSM_LAST (READDIR,/*error*/{"DONE",f3},  {"DONE",f3} ,   FUSE_FSM_BAD)           

static void fuse_readdir_common(fuse_req_t req, fuse_ino_t ino, size_t size,
				off_t off, struct fuse_file_info *llfi,
				enum fuse_readdir_flags flags)
{
    struct fuse *f = req_fuse_prepare(req);
    struct fuse_file_info fi;
    struct fuse_dh *dh = get_dirhandle(llfi, &fi);
    char *path;

	pthread_mutex_lock(&dh->lock);
	/* According to SUS, directory contents need to be refreshed on
	   rewinddir() */
	if (!off)
		dh->filled = 0;

	if (!dh->filled){
        int err;

        if (f->fs->op.readdir)
            err = get_path_nullok(f, ino, &path);
        else
            err = get_path(f, ino, &path);

        if (!err){
            struct fuse_fsm *new_fsm = NULL;
            FUSE_FSM_ALLOC(READDIR,new_fsm,struct fsm_readdir_data);
            struct fsm_readdir_data *dt = (struct fsm_readdir_data*)new_fsm->data;

            dt->dh = dh;
            dt->off = off;
            dt->size = size;
            dt->flags = flags;
            dt->req = req;
            dt->ino = ino;
            dt->f = f;
            dt->path = path;
            dt->fi = fi;
            fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
            if (fuse_fsm_is_done(new_fsm))
                FUSE_FSM_FREE(new_fsm);
        }else
            reply_err(req,err);

    }else
        reply_err(req,0);
    pthread_mutex_unlock(&dh->lock);
}

void fuse_lib_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			     off_t off, struct fuse_file_info *llfi)
{
	fuse_readdir_common(req, ino, size, off, llfi, 0);
}

void fuse_lib_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *llfi)
{
	fuse_readdir_common(req, ino, size, off, llfi, FUSE_READDIR_PLUS);
}

