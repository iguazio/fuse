#include "fuse_lib.h"
#include "fuse_fsm.h"
#include "fuse_log.h"
#include "fuse_user_data_context.h"

struct fsm_read_data {
	char *path;
	size_t off;
	size_t size;
	struct fuse_file_info fi;
	struct fuse * f;
	struct fuse_bufvec buf;
	void* payload_buffer_element;
	fuse_ino_t ino;
	fuse_req_t req;
    struct fuse_intr_data d;
};

static int f1_do_read(struct fuse_fsm* fsm __attribute__((unused)), struct fsm_read_data *dt) {
	struct fuse_fs *fs = dt->f->fs;
	const char *path = dt->path;
	fuse_get_context()->private_data = fs->user_data;

	if(!fs->op.read) {
		return -ENOSYS;
	}

	int res;

	if (fs->debug) {
		fuse_log_debug(
				"read[%llu] %zu bytes from %llu flags: 0x%x\n",
				(unsigned long long) dt->fi.fh,
				dt->size, (unsigned long long) dt->off, dt->fi.flags);
	}

	dt->payload_buffer_element = g_fuse_user_data_context.alloc_payload_buffer_element(dt->size);
	if (dt->payload_buffer_element == NULL) {
		return -ENOMEM;
	}
	dt->buf = FUSE_BUFVEC_INIT(dt->size);
	dt->buf.buf[0].mem = g_fuse_user_data_context.get_payload_buffer_element_buf_ptr(dt->payload_buffer_element);

	res = fs->op.read(fsm, path, dt->payload_buffer_element, dt->size, dt->off, &dt->fi);
	if (res >= 0)
		dt->buf.buf[0].size = res;


	if (fs->debug && res >= 0)
		fuse_log_debug( "   read[%llu] %zu bytes from %llu\n",
				(unsigned long long) dt->fi.fh,
				dt->buf.buf[0].size,
				(unsigned long long) dt->off);
	if (res >= 0 && dt->buf.buf[0].size > (int) dt->size)
		fuse_log_err( "fuse: read too many bytes\n");

	if (res < 0)
		return res;

	return 0;
}

/*Send request to the fs*/
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
	struct fsm_read_data *dt = (struct fsm_read_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
	int err = f1_do_read(fsm, dt);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}
/*Send successfully read data*/
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
	struct fsm_read_data *dt = (struct fsm_read_data *)data;
	
	dt->buf.buf[0].size = *((size_t*)(&dt->fi));

    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);
	fuse_reply_data(dt->req, &dt->buf, FUSE_BUF_SPLICE_MOVE);
	if(dt->payload_buffer_element) {
		g_fuse_user_data_context.free_payload_buffer_element(dt->payload_buffer_element);
		dt->payload_buffer_element = NULL;
	}

	return FUSE_FSM_EVENT_NONE;
}

/*Send error read data*/
static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
	struct fsm_read_data *dt = (struct fsm_read_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    free_path(dt->f, dt->ino, dt->path);
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
    if(dt->payload_buffer_element) {
    	g_fuse_user_data_context.free_payload_buffer_element(dt->payload_buffer_element);
    	dt->payload_buffer_element = NULL;
    }
	return FUSE_FSM_EVENT_NONE;
}

FUSE_FSM_EVENTS(READ, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
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

        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, res);
}

