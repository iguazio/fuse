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
	int err;
};
#pragma GCC diagnostic ignored "-Wunused-parameter"

/*Send request to the fs*/
static const char* f1(const char * from, const char * to, void *data) {
	struct fsm_read_data *dt = (struct fsm_read_data *)data;
	struct fuse_intr_data d;
	fuse_prepare_interrupt(dt->f, dt->req, &d);
	dt->err = fuse_fs_read_buf(dt->f->fs, dt->path, &dt->buf, dt->size, dt->off, &dt->fi);
	fuse_finish_interrupt(dt->f, dt->req, &d);
	free_path(dt->f, dt->ino, dt->path);
	return NULL;
}
/*Send successfully read data*/
static const char* f2(const char * from, const char * to, void *data) {
	struct fsm_read_data *dt = (struct fsm_read_data *)data;
	
	dt->buf[0].buf->size = *((size_t*)(&dt->fi));

	fuse_reply_data(dt->req, dt->buf, FUSE_BUF_SPLICE_MOVE);
	fuse_buf_free(dt->buf);
	return NULL;
}

/*Send error read data*/
static const char* f3(const char * from, const char * to, void *data) {
	struct fsm_read_data *dt = (struct fsm_read_data *)data;
	reply_err(dt->req, dt->err);
	fuse_buf_free(dt->buf);
	return NULL;
}

FUSE_FSM_EVENTS(READ, "read", "ok", "error")
FUSE_FSM_STATES(READ, "CREATED", "READ", "DONE")
FUSE_FSM_ENTRY(/*read*/{ "READ",f1 }, NONE, NONE)
FUSE_FSM_ENTRY(/*ok*/{ "DONE",f2 }, { "DONE",f2 }, NONE)
FUSE_FSM_LAST(/*error*/{ "DONE",f3 }, { "DONE",f3 }, NONE)


#pragma GCC diagnostic ignored "-Wunused-parameter"

void fuse_lib_read(fuse_req_t req, fuse_ino_t ino, size_t size,
	off_t off, struct fuse_file_info *fi)
{
	struct fuse_fsm *new_fsm = NULL;
	FUSE_FSM_ALLOC(READ, new_fsm, struct fsm_read_data);
	struct fsm_read_data *dt = (struct fsm_read_data*)new_fsm->data;


	struct fuse *f = req_fuse_prepare(req);
	int res;

	dt->f = f;
	dt->ino = ino;
	dt->size = size;
	dt->off = off;
	dt->fi = *fi;
	dt->req = req;

	res = get_path_nullok(f, ino, &dt->path);
	if (res == 0) {
		fuse_fsm_run(new_fsm, "read");

		if (dt->err == FUSE_LIB_ERROR_PENDING_REQ) {
			fuse_async_add_pending(new_fsm);
			return;
		}
		else{
			fuse_fsm_run(new_fsm, dt->err ? "error" : "ok");

			if (!strcmp(fuse_fsm_cur_state(new_fsm), "DONE"))
				FUSE_FSM_FREE(new_fsm);
		}
	}else
		reply_err(req, res);
}

