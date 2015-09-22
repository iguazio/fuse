#include "fuse_lib.h"
#define LOG_CTX //printf("%s::%s\n",__FILE__,__FUNCTION__)
static int open_auto_cache(struct fuse_fsm* parent, struct fuse *f, fuse_ino_t ino, const char *path, struct fuse_file_info *fi);

struct fsm_open_data {
	struct node *node;
	struct fuse_fsm *self;
	char *path;
	struct fuse * f;
	struct fuse_file_info fi;
	fuse_ino_t ino;
	fuse_req_t req;
	int err;
};

#pragma GCC diagnostic ignored "-Wunused-parameter"

//Send open request
static const char * f1(const char * from, const char * to, void *data) {
	LOG_CTX;
	struct fsm_open_data *dt = (struct fsm_open_data *)data;
	struct fuse_intr_data d;
	fuse_prepare_interrupt(dt->f, dt->req, &d);
	dt->err = fuse_fs_open(dt->f->fs, dt->path, &dt->fi);
	fuse_finish_interrupt(dt->f, dt->req, &d);
	return NULL;
}


//Reply success to the driver
static const char* f2(const char * from, const char * to, void *data) {
	LOG_CTX;
	struct fsm_open_data *dt = (struct fsm_open_data *)data;

	if (dt->f->conf.direct_io)
		dt->fi.direct_io = 1;
	if (dt->f->conf.kernel_cache)
		dt->fi.keep_cache = 1;

	pthread_mutex_lock(&dt->f->lock);
	get_node(dt->f, dt->ino)->open_count++;
	pthread_mutex_unlock(&dt->f->lock);
	if (fuse_reply_open(dt->req, &dt->fi) == -ENOENT) {
		/* The open syscall was interrupted, so it
		must be cancelled */
		fuse_do_release(dt->f, dt->ino, dt->path, &dt->fi);
	}
	free_path(dt->f, dt->ino, dt->path);
	return NULL;
}

//Reply error to the driver
static const char* f3(const char * from, const char * to, void *data) {
	LOG_CTX;
	struct fsm_open_data *dt = (struct fsm_open_data *)data;
	reply_err(dt->req, dt->err);
	free_path(dt->f, dt->ino, dt->path);
	return NULL;
}

//Open successfully completed. Either send request for cache refresh or finish
static const char* f4(const char * from, const char * to, void *data) {
	LOG_CTX;
	struct fsm_open_data *dt = (struct fsm_open_data *)data;
	if (dt->f->conf.auto_cache)
		return "send";
	else
		return "ok";
}

//Send cache request
static const char* f11(const char * from, const char * to, void *data) {
	LOG_CTX;
	struct fsm_open_data *dt = (struct fsm_open_data *)data;
	dt->err = open_auto_cache(dt->self, dt->f, dt->ino, dt->path, &dt->fi);
	if (dt->err == FUSE_LIB_ERROR_PENDING_REQ)
		return NULL;
	if (dt->err)
		return "error";
	else 
		return "ok";
}


FUSE_FSM_EVENTS(OPEN, "send", "ok", "error")
FUSE_FSM_STATES(OPEN,		"CREATED"	  , "OPEN"			,"O_COMPL",		   "CACHE",			"DONE")
FUSE_FSM_ENTRY(/*send*/		 { "OPEN",f1 }, NONE			, { "CACHE",f11 }, NONE		   ,	NONE)
FUSE_FSM_ENTRY(/*ok*/		 NONE		  , { "O_COMPL",f4 }, { "DONE",f2 }  ,{ "DONE",f2 },	NONE)
FUSE_FSM_LAST(/*error*/		 NONE		  , { "DONE",f3 }	, NONE			 ,{ "DONE",f2 },	NONE)




void fuse_lib_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{

	struct fuse_fsm *new_fsm = NULL;
	FUSE_FSM_ALLOC(OPEN, new_fsm, struct fsm_open_data);
	struct fsm_open_data *dt = (struct fsm_open_data*)new_fsm->data;

	struct fuse *f = req_fuse_prepare(req);

	dt->f = f;
	dt->fi = *fi;
	dt->ino = ino;
	dt->req = req;
	dt->self = new_fsm;

	int err = get_path(f, ino, &dt->path);
	if (!err) {
		fuse_fsm_run(new_fsm, "send");
		if (dt->err == FUSE_LIB_ERROR_PENDING_REQ)
			fuse_async_add_pending(new_fsm);
		else
			fuse_fsm_run(new_fsm, dt->err ? "error" : "ok");
	}
	if (!strcmp(fuse_fsm_cur_state(new_fsm), "DONE"))
		FUSE_FSM_FREE(new_fsm);

}


struct fsm_open_cache_data {
	struct fuse_fsm *parent;
	struct fuse_fsm *self;
	struct node *node;
	const char *path;
	struct stat stbuf;
	struct fuse * f;
	struct fuse_file_info *fi;
	fuse_ino_t ino;
	int err;
};

/*Send getattrt*/
static const char* fc1(const char * from, const char * to, void *data) {
	LOG_CTX;
	struct fsm_open_cache_data *dt = (struct fsm_open_cache_data *)data;
	pthread_mutex_lock(&dt->f->lock);
	dt->err = fuse_fs_fgetattr(dt->f->fs, dt->path, &dt->stbuf, dt->fi);
	pthread_mutex_unlock(&dt->f->lock);
	return NULL;
}

/*Got getattrt OK*/
static const char* fc2(const char * from, const char * to, void *data) {
	LOG_CTX;
	struct fsm_open_cache_data *dt = (struct fsm_open_cache_data *)data;
	pthread_mutex_lock(&dt->f->lock);
	update_stat(dt->node, &dt->stbuf);
	if (dt->node->cache_valid)
		dt->fi->keep_cache = 1;

	dt->node->cache_valid = 1;
	pthread_mutex_unlock(&dt->f->lock);
	fuse_fsm_run(dt->parent, "ok");
	return NULL;

}

/*Got getattrt err*/
static const char* fc3(const char * from, const char * to, void *data) {
	LOG_CTX;
	struct fsm_open_cache_data *dt = (struct fsm_open_cache_data *)data;
	pthread_mutex_lock(&dt->f->lock);
	dt->node->cache_valid = 1;
	pthread_mutex_unlock(&dt->f->lock);
	fuse_fsm_run(dt->parent, "error");
	return NULL;
}



FUSE_FSM_EVENTS(OPEN_CACHE, "send", "ok", "error")
FUSE_FSM_STATES(OPEN_CACHE, "CREATED", "GETA", "DONE")
FUSE_FSM_ENTRY(/*send*/{ "GETA",fc1 }, NONE, NONE)
FUSE_FSM_ENTRY(/*ok*/{ "DONE",fc2 }, { "DONE",fc2 }, NONE)
FUSE_FSM_LAST(/*error*/{ "DONE",fc3 }, { "DONE",fc3 }, NONE)

static int open_auto_cache(struct fuse_fsm* parent, struct fuse *f, fuse_ino_t ino, const char *path, struct fuse_file_info *fi)
{
	struct node* node = get_node(f, ino);
	if (node->cache_valid) {
		struct timespec now;

		curr_time(&now);
		if (diff_timespec(&now, &node->stat_updated) >
			f->conf.ac_attr_timeout) {

			struct fuse_fsm *new_fsm = NULL;
			FUSE_FSM_ALLOC(OPEN_CACHE, new_fsm, struct fsm_open_cache_data);
			struct fsm_open_cache_data *dt = (struct fsm_open_cache_data*)new_fsm->data;

			dt->parent = parent;
			dt->self = new_fsm;
			dt->f = f;
			dt->fi = fi;
			dt->path = path;
			dt->ino = ino;
			dt->node = node;


			fuse_fsm_run(new_fsm, "send");
			if (dt->err == FUSE_LIB_ERROR_PENDING_REQ) {
				fuse_async_add_pending(new_fsm);
				return FUSE_LIB_ERROR_PENDING_REQ;
			}

			if (!strcmp(fuse_fsm_cur_state(new_fsm), "DONE")) {
				fuse_fsm_run(new_fsm, (dt->err) ? "error" : "ok");
				FUSE_FSM_FREE(new_fsm);
			}
			return 0;
		}
	}
	return 0;
}

