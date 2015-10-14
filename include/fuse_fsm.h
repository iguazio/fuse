/*
The basic idea of this implementation is that every state machine can be directly 
represented as a state transition table. We will be using a two-dimensional transition table (matrix), 
depending of current active state and possible events (see Below).

Table 1: State Transition Table
            STATE 1          STATE 2                STATE 3
event 1     (STATE2,ACTION1) (STATE3,ACTION2)       (STATE1,ACTION4)
event 2     (STATE2,ACTION2) (STATE1,ACTION1)       (STATE3,ACTION4)

e.g. the current state would be 'STATE2' and the second event has been triggered, 
the machine will initiate 'ACTION2' and move to 'STATE3'.

This compact representation can easily be derived from any state diagram. 
Suchlike tabular structures can be transferred into programming languages without difficulty. 
This is the main benefit of this representation.

Typical example of usage:

static const char* f1(struct fuse_fsm* fsm , void *data) {
    int err = fuse_fs_unlink(fsm, dt->f->fs, dt->path);
    if (err == FUSE_LIB_ERROR_PENDING_REQ)
        return NULL;
    fuse_fsm_set_err(fsm, err);
    return (err)?"error":"ok";
}

static const char* f10(struct fuse_fsm* fsm, void *data) {
    struct fsm_unlink_data *dt = (struct fsm_unlink_data *)data;
    reply_err(dt->req, 0);
    return NULL;
}

static const char* f13(struct fuse_fsm* fsm __attribute__((unused)), void *data) {
    int err = fuse_fsm_get_err(fsm);
    reply_err(dt->req, err);
    return NULL;
}

FUSE_FSM_EVENTS(UNLINK,  "ok", "error")
FUSE_FSM_STATES(UNLINK,   "START",         "RM"      ,"DONE")
FUSE_FSM_ENTRY(UNLINK,	 {"RM",f1}     ,{"DONE",f10} , NONE)
FUSE_FSM_LAST(UNLINK, {"DONE",f13},    {"DONE",f13}  , NONE)

void go(){
    ...
    struct fuse_fsm *new_fsm = NULL;
    FUSE_FSM_ALLOC(UNLINK, new_fsm, struct fsm_unlink_data);
    struct fsm_unlink_data *dt = (struct fsm_unlink_data*)new_fsm->data;
    ...
    fuse_fsm_run(new_fsm, "ok");
    if (!strcmp(fuse_fsm_cur_state(new_fsm),"DONE")){
        int res = fuse_fsm_get_err(new_fsm);
        FUSE_FSM_FREE(new_fsm);
        return res;
    }
    return FUSE_LIB_ERROR_PENDING_REQ;
}
*/

#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "fuse_async_responce.h"
struct fuse_fsm;

typedef const char* (*fuse_lib_fsm_transition_function_t)(struct fuse_fsm* fsm __attribute__((unused)),void *data);
const char* fuse_lib_fsm_transition_function_null(struct fuse_fsm* fsm __attribute__((unused)),void *data);

struct fuse_fsm_entry{
    const char *next_state;
    fuse_lib_fsm_transition_function_t f;
    int next_state_id;
};

struct fuse_fsm{
    int do_free_on_done;
    const char *name;
    int err;
    int current_state;
    const char** events;
    const char** states;
    const struct fuse_fsm_entry *fuse_fsm_transition_table;
    const int num_of_states;
    const int num_of_events;
    char data[0];
};

void    fuse_fsm_set_err(struct fuse_fsm *fsm, int err);
int     fuse_fsm_get_err(struct fuse_fsm *fsm);
void    fuse_fsm_free_on_done(struct fuse_fsm *fsm, int do_cleanup);
void    fuse_fsm_run( struct fuse_fsm * fsm, const char* event ); 
const char* fuse_fsm_cur_state( struct fuse_fsm * fsm ) ;
void    fuse_fsm_set_debug(int d);

#define FUSE_FSM_BAD {NULL,fuse_lib_fsm_transition_function_null}


#define FUSE_FSM_EVENTS(api_name,...) \
    static const char *fuse_fsm_events_##api_name[]={__VA_ARGS__};

#define FUSE_FSM_STATES(api_name,...)\
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wmissing-field-initializers\"")\
    static const char *fuse_fsm_states_##api_name[]={__VA_ARGS__};\
    static struct fuse_fsm_entry fuse_fsm_transition_table_##api_name[sizeof(fuse_fsm_events_##api_name)/sizeof(fuse_fsm_events_##api_name[0])][sizeof(fuse_fsm_states_##api_name)/sizeof(fuse_fsm_states_##api_name[0])] = {

#define FUSE_FSM_ENTRY(api_name,...) {__VA_ARGS__} , 

#define FUSE_FSM_LAST(api_name,...) {__VA_ARGS__}} ; _Pragma("GCC diagnostic pop") ; \
    __attribute__((constructor)) static void fuse_fsm_init_##api_name(void) {\
        int i;\
        int num_of_states = sizeof(fuse_fsm_states_##api_name)/sizeof(char*);\
        for (i = 0;i<sizeof(fuse_fsm_transition_table_##api_name)/sizeof(struct fuse_fsm_entry);i++)\
            ((struct fuse_fsm_entry*)fuse_fsm_transition_table_##api_name)[i].next_state_id = _fuse_fsm_state_str_to_id(num_of_states,fuse_fsm_states_##api_name,((struct fuse_fsm_entry*)fuse_fsm_transition_table_##api_name)[i].next_state);\
        /*expect state machine to have at least "ok" and "error" in the right order*/\
        assert(!strcmp(fuse_fsm_events_##api_name[0],"ok"));\
        assert(!strcmp(fuse_fsm_events_##api_name[1],"error"));\
        /*expect state machine to have "DONE" state*/   \
        for (i = 0;i<num_of_states;i++) \
            if(!strcmp(fuse_fsm_states_##api_name[i],"DONE"))\
                break;\
        assert(i < num_of_states);\
}

#define _FUSE_FSM_INIT(api_name) {0, #api_name,0, 0, (const char**)fuse_fsm_events_##api_name,\
    (const char**)fuse_fsm_states_##api_name,\
   (const struct fuse_fsm_entry *)fuse_fsm_transition_table_##api_name,\
    sizeof(fuse_fsm_states_##api_name)/sizeof(fuse_fsm_states_##api_name[0]),\
    sizeof(fuse_fsm_events_##api_name)/sizeof(fuse_fsm_events_##api_name[0])}

#define FUSE_FSM_ALLOC(api_name,fsm,tt) {struct fuse_fsm f = _FUSE_FSM_INIT(api_name);\
    fsm = (struct fuse_fsm*)fuse_calloc(1,sizeof(struct fuse_fsm) + sizeof(tt));\
    memcpy(fsm,&f,sizeof(struct fuse_fsm));}


#define FUSE_FSM_FREE(fsm)   fuse_free(fsm)


/*private*/
int     _fuse_fsm_state_str_to_id(int num_of_states,const char** states,const char *state);
