#include "fuse_lib.h"
#define LOG_CTX //printf("%s::%s\n",__FILE__,__FUNCTION__)
static int open_auto_cache(struct fuse_fsm* parent,struct fuse_fsm** cache_fsm, struct fuse *f, fuse_ino_t ino, const char *path, struct fuse_file_info *fi);

struct fsm_open_data {
	struct node *node;
	struct fuse_fsm *cache_fsm;
    struct fuse_intr_data d;
	char *path;
	struct fuse * f;
	struct fuse_file_info fi;
	fuse_ino_t ino;
	fuse_req_t req;
};

#pragma GCC diagnostic ignored "-Wunused-parameter"

//Send open request
static struct fuse_fsm_event f1(struct fuse_fsm* fsm, void *data) {
	LOG_CTX;
	struct fsm_open_data *dt = (struct fsm_open_data *)data;
	fuse_prepare_interrupt(dt->f, dt->req, &dt->d);
	int err = fuse_fs_open(fsm, dt->f->fs, dt->path, &dt->fi);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}


//Reply success to the driver
static struct fuse_fsm_event f2(struct fuse_fsm* fsm, void *data) {
	LOG_CTX;
	struct fsm_open_data *dt = (struct fsm_open_data *)data;

	if (dt->f->conf.direct_io)
		dt->fi.direct_io = 1;
	if (dt->f->conf.kernel_cache)
		dt->fi.keep_cache = 1;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);

	pthread_mutex_lock(&dt->f->lock);
	get_node(dt->f, dt->ino)->open_count++;
	pthread_mutex_unlock(&dt->f->lock);
	if (fuse_reply_open(dt->req, &dt->fi) == -ENOENT) {
		/* The open syscall was interrupted, so it
		must be cancelled */
		fuse_do_release(NULL,dt->f, dt->ino, dt->path, &dt->fi);
	}
	free_path(dt->f, dt->ino, dt->path);
    if (dt->cache_fsm)
        FUSE_FSM_FREE(dt->cache_fsm);
	return FUSE_FSM_EVENT_NONE;
}

//Reply error to the driver
static struct fuse_fsm_event f3(struct fuse_fsm* fsm, void *data) {
	LOG_CTX;
	struct fsm_open_data *dt = (struct fsm_open_data *)data;
    fuse_finish_interrupt(dt->f, dt->req, &dt->d);
    int err = fuse_fsm_get_err(fsm);
	reply_err(dt->req,err);
	free_path(dt->f, dt->ino, dt->path);
    if (dt->cache_fsm)
        FUSE_FSM_FREE(dt->cache_fsm);
	return FUSE_FSM_EVENT_NONE;
}


//Send cache request
static struct fuse_fsm_event f11(struct fuse_fsm* fsm, void *data) {
	LOG_CTX;
	struct fsm_open_data *dt = (struct fsm_open_data *)data;
	int err = open_auto_cache(fsm, &dt->cache_fsm, dt->f, dt->ino, dt->path, &dt->fi);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return FUSE_FSM_EVENT_NONE;
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}


FUSE_FSM_EVENTS(OPEN, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(OPEN,		"CREATED"	  , "OPEN"		    , "CACHE"       ,   "DONE")
FUSE_FSM_ENTRY(OPEN, /*ok*/  { "OPEN",f1 }, { "CACHE",f11 } , { "DONE",f2 } ,	FUSE_FSM_BAD)
FUSE_FSM_LAST(OPEN, /*error*/ FUSE_FSM_BAD , { "DONE",f3 }	, { "DONE",f3 } ,	FUSE_FSM_BAD)




void fuse_lib_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{

    struct fuse *f = req_fuse_prepare(req);
    char *path;
	int err = get_path(f, ino, &path);
	if (!err) {
        struct fuse_fsm *new_fsm = NULL;
        FUSE_FSM_ALLOC(OPEN, new_fsm, struct fsm_open_data);
        struct fsm_open_data *dt = (struct fsm_open_data*)new_fsm->data;

        dt->f = f;
        dt->fi = *fi;
        dt->ino = ino;
        dt->req = req;
        dt->path = path;

        fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
        if (fuse_fsm_is_done(new_fsm))
            FUSE_FSM_FREE(new_fsm);
    }else
        reply_err(req, err);
}

///////////////////////////////////////////// OPEN CACHE /////////////////////////////

struct fsm_open_cache_data {
	struct fuse_fsm *parent;
	struct node *node;
	const char *path;
	struct stat stbuf;
	struct fuse * f;
	struct fuse_file_info *fi;
	fuse_ino_t ino;
	int err;
};

/*Send getattrt*/
static struct fuse_fsm_event fc1(struct fuse_fsm* fsm, void *data) {
    struct fsm_open_cache_data *dt = (struct fsm_open_cache_data *)data;
    int err;
    err = fuse_fs_fgetattr(fsm, dt->f->fs, dt->path, &dt->stbuf, dt->fi);
    if (err == FUSE_LIB_ERROR_PENDING_REQ){
        return FUSE_FSM_EVENT_NONE;
    }
    fuse_fsm_set_err(fsm, err);
    return (err)?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK;
}

/*Got getattrt OK*/
static struct fuse_fsm_event fc2(struct fuse_fsm* fsm, void *data) {
	LOG_CTX;

    struct fsm_open_cache_data *dt = (struct fsm_open_cache_data *)data;

    pthread_mutex_lock(&dt->f->lock);
    update_stat(dt->node, &dt->stbuf);
    pthread_mutex_unlock(&dt->f->lock);
    if (dt->node->cache_valid)
        dt->fi->keep_cache = 1;

    dt->node->cache_valid = 1;
    pthread_mutex_unlock(&dt->f->lock);
    FUSE_FSM_MARK_PENDING(dt->parent, FUSE_FSM_EVENT_OK);
	return FUSE_FSM_EVENT_NONE;
}

/*Got getattrt err*/
static struct fuse_fsm_event fc3(struct fuse_fsm* fsm, void *data) {
	LOG_CTX;
	struct fsm_open_cache_data *dt = (struct fsm_open_cache_data *)data;
	pthread_mutex_lock(&dt->f->lock);
	dt->node->cache_valid = 1;
	pthread_mutex_unlock(&dt->f->lock);
    int err = fuse_fsm_get_err(fsm);
    fuse_fsm_set_err(dt->parent,err);
    FUSE_FSM_MARK_PENDING(dt->parent, FUSE_FSM_EVENT_ERROR);
    return FUSE_FSM_EVENT_NONE;
}



FUSE_FSM_EVENTS(OPEN_CACHE, FUSE_FSM_EVENT_OK, FUSE_FSM_EVENT_ERROR)
FUSE_FSM_STATES(OPEN_CACHE,         "CREATED",      "GETA",     "DONE")
FUSE_FSM_ENTRY(OPEN_CACHE,/*ok*/{ "GETA",fc1 }, { "DONE",fc2 }, FUSE_FSM_BAD)
FUSE_FSM_LAST(OPEN_CACHE,/*error*/{ "DONE",fc3 }, { "DONE",fc3 }, FUSE_FSM_BAD)

static int open_auto_cache(struct fuse_fsm* parent,struct fuse_fsm** cache_fsm, struct fuse *f, fuse_ino_t ino, const char *path, struct fuse_file_info *fi)
{
	struct node* node = get_node(f, ino);
    *cache_fsm = NULL;
	if (node->cache_valid) {
		struct timespec now;

		curr_time(&now);
		if (diff_timespec(&now, &node->stat_updated) >
			f->conf.ac_attr_timeout) {

			struct fuse_fsm *new_fsm = NULL;
			FUSE_FSM_ALLOC(OPEN_CACHE, new_fsm, struct fsm_open_cache_data);
			struct fsm_open_cache_data *dt = (struct fsm_open_cache_data*)new_fsm->data;

			dt->parent = parent;
			dt->f = f;
			dt->fi = fi;
			dt->path = path;
			dt->ino = ino;
			dt->node = node;
            fuse_fsm_run(new_fsm, FUSE_FSM_EVENT_OK);
            if (fuse_fsm_is_done(new_fsm)){
                FUSE_FSM_FREE(new_fsm);
                return 0;
            }
            *cache_fsm = new_fsm;
            return FUSE_LIB_ERROR_PENDING_REQ;
		}
	}
	return 0;
}

