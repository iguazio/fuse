#include "fuse_lib.h"

struct fsm_read_data {
	char *path;
	size_t off;
	size_t size;
	struct fuse_file_info fi;
	struct fuse * f;
	struct fuse_bufvec *buf;
	fuse_ino_t ino;
	fuse_req_t req;
    struct fuse_intr_data d;
};

/*Send request to the fs*/
static const char* f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
	struct fsm_read_data *dt = (struct fsm_read_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
	int err = fuse_fs_read_buf(fsm, dt->f->fs, dt->path, &dt->buf, dt->size, dt->off, &dt->fi);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return NULL;
    fuse_fsm_set_err(fsm, err);
    return (err)?"error":"ok";
}
/*Send successfully read data*/
static const char* f2(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
	struct fsm_read_data *dt = (struct fsm_read_data *)data;
	
	dt->buf[0].buf->size = *((size_t*)(&dt->fi));

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);
	fuse_reply_data(dt->req, dt->buf, FUSE_BUF_SPLICE_MOVE);
	fuse_buf_free(dt->buf);

	return NULL;
}

/*Send error read data*/
static const char* f3(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
	struct fsm_read_data *dt = (struct fsm_read_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
	fuse_buf_free(dt->buf);
	return NULL;
}

FUSE_FSM_EVENTS(READ, "ok", "error")
FUSE_FSM_STATES(READ,        "CREATED",     "READ"  , "DONE")
FUSE_FSM_ENTRY(READ,/*ok*/ { "READ",f1 }, { "DONE",f2 }, FUSE_FSM_BAD)
FUSE_FSM_LAST(READ,/*error*/{"DONE",f3 }, { "DONE",f3 }, FUSE_FSM_BAD)




void fuse_lib_read(fuse_req_t req, fuse_ino_t ino, size_t size,
	off_t off, struct fuse_file_info *fi)
{

    int res;
    char *path;
    struct fuse *f = req_fuse_prepare(req);
	res = get_path_nullok(f, ino, &path);
	if (res == 0) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(READ, new_fsm, struct fsm_read_data);
        struct fsm_read_data *dt = (struct fsm_read_data*)new_fsm->data;


        dt->path = path;
        dt->f = f;
        dt->ino = ino;
        dt->size = size;
        dt->off = off;
        dt->fi = *fi;
        dt->req = req;

        fuse_fsm_run(new_fsm, "ok");
        if (!strcmp(fuse_fsm_cur_state(new_fsm),"DONE"))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, res);
}

