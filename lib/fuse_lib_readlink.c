#include "fuse_lib.h"
#include "fuse_fsm.h"
#include "fuse_log.h"
#include "fuse_user_data_context.h"

#define LINKNAME_BUFFER_SIZE (PATH_MAX + 1)

struct fsm_readlink_data {
    char *path;
    void* payload_buffer_element;
    char *linkname;
    struct fuse * f;
    fuse_req_t req;
    fuse_ino_t ino;
    struct fuse_intr_data d;
};

static int f1_do_readlink( struct fuse_fsm* fsm __attribute__((unused)), struct fsm_readlink_data *dt )
{
	struct fuse_fs *fs = dt->f->fs;

	fuse_get_context()->private_data = fs->user_data;
	if (!fs->op.readlink) {
		return -ENOSYS;
	}
	if (fs->debug)
		fuse_log_debug( "readlink %s %lu\n", dt->path,
				(unsigned long) LINKNAME_BUFFER_SIZE);

	dt->payload_buffer_element = g_fuse_user_data_context.alloc_payload_buffer_element(LINKNAME_BUFFER_SIZE);
	if (dt->payload_buffer_element == NULL) {
		return -ENOMEM;
	}
	dt->linkname = g_fuse_user_data_context.get_payload_buffer_element_buf_ptr(dt->payload_buffer_element);
	return fs->op.readlink(fsm, dt->path, dt->payload_buffer_element, LINKNAME_BUFFER_SIZE);
}

/*Send request to the fs*/
static struct fuse_fsm_event f1(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_readlink_data *dt = (struct fsm_readlink_data *)data;
    fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
    int err = f1_do_readlink(fsm, dt);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err) ? FUSE_FSM_EVENT_ERROR : FUSE_FSM_EVENT_OK;
}
/*Send successfully read data*/
static struct fuse_fsm_event f2(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_readlink_data *dt = (struct fsm_readlink_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    fuse_reply_readlink(dt->req, dt->linkname);
    if(dt->payload_buffer_element) {
    	g_fuse_user_data_context.free_payload_buffer_element(dt->payload_buffer_element);
    	dt->payload_buffer_element = NULL;
    }
    free_path(dt->f, dt->ino, dt->path);
    return FUSE_FSM_EVENT_NONE;
}

/*Send error read data*/
static struct fuse_fsm_event f3(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    struct fsm_readlink_data *dt = (struct fsm_readlink_data *)data;
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

FUSE_FSM_EVENTS(READLINK, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(READLINK,        "CREATED"  ,     "READ"   , "DONE")
FUSE_FSM_ENTRY(READLINK,/*ok*/ { "READ",f1 }, { "DONE",f2 }, FUSE_FSM_BAD)
FUSE_FSM_LAST(READLINK,/*error*/{"DONE",f3 }, { "DONE",f3 }, FUSE_FSM_BAD)

void fuse_lib_readlink(fuse_req_t req, fuse_ino_t ino)
{
    struct fuse *f = req_fuse_prepare(req);
    char *path;
    int res;
    res = get_path(f, ino, &path);
    if (res == 0) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(READLINK, new_fsm, struct fsm_readlink_data);
        struct fsm_readlink_data *dt = (struct fsm_readlink_data*)new_fsm->data;
        dt->ino = ino;
        dt->path = path;
        dt->f = f;
        dt->ino = ino;
        dt->req = req;
        dt->linkname = NULL;
        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }
    else
        reply_err(req, res);
}
