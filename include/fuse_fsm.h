#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

FUSE_FSM_EVENTS(UNLINK,  "ok", "error")
FUSE_FSM_STATES(UNLINK,   "START",         "RM"      ,"DONE")
FUSE_FSM_ENTRY(      	 {"RM",f1}     ,{"DONE",f10} , NONE)
FUSE_FSM_LAST(        {"DONE",f13},    {"DONE",f13}  , NONE)

go(){
    ...
    struct fuse_fsm *new_fsm = NULL;
    FUSE_FSM_ALLOC(UNLINK, new_fsm, struct fsm_unlink_data);
    struct fsm_unlink_data *dt = (struct fsm_unlink_data*)new_fsm->data;
    ...
    fuse_fsm_run(new_fsm, "ok");
    ...
}


*/
#include "fuse_async_responce.h"
struct fuse_fsm;

typedef const char* (*fuse_lib_fsm_transition_function_t)(struct fuse_fsm* fsm __attribute__((unused)),void *data);
const char* fuse_lib_fsm_transition_function_null(struct fuse_fsm* fsm __attribute__((unused)),void *data);

struct fuse_fsm_entry{
    const char *next_state;
    fuse_lib_fsm_transition_function_t f;
};

struct fuse_fsm{
    int do_cleanup_on_done;
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
void    fuse_fsm_cleanup_on_done(struct fuse_fsm *fsm, int do_cleanup);

#define NONE {NULL,fuse_lib_fsm_transition_function_null}


#define FUSE_FSM_EVENTS(api_name,...) \
    static const char *fuse_fsm_events_##api_name[]={__VA_ARGS__};
#define FUSE_FSM_STATES(api_name,...)\
    static const char *fuse_fsm_states_##api_name[]={__VA_ARGS__};\
    static const struct fuse_fsm_entry fuse_fsm_transition_table_##api_name[sizeof(fuse_fsm_events_##api_name)/sizeof(fuse_fsm_events_##api_name[0])][sizeof(fuse_fsm_states_##api_name)/sizeof(fuse_fsm_states_##api_name[0])] = {
#define FUSE_FSM_ENTRY(...) {__VA_ARGS__},
#define FUSE_FSM_LAST(...) {__VA_ARGS__}};

#define _FUSE_FSM_INIT(api_name) {0, #api_name,0, 0, (const char**)fuse_fsm_events_##api_name,\
    (const char**)fuse_fsm_states_##api_name,\
   (const struct fuse_fsm_entry *)fuse_fsm_transition_table_##api_name,\
    sizeof(fuse_fsm_states_##api_name)/sizeof(fuse_fsm_states_##api_name[0]),\
    sizeof(fuse_fsm_events_##api_name)/sizeof(fuse_fsm_events_##api_name[0])}

#define FUSE_FSM_ALLOC(api_name,fsm,tt) {struct fuse_fsm f = _FUSE_FSM_INIT(api_name);\
    fsm = (struct fuse_fsm*)fuse_calloc(1,sizeof(struct fuse_fsm) + sizeof(tt));\
    memcpy(fsm,&f,sizeof(struct fuse_fsm));}


#define FUSE_FSM_FREE(fsm)   fuse_free(fsm)

void fuse_fsm_run( struct fuse_fsm * fsm, const char* event ); 
const char* fuse_fsm_cur_state( struct fuse_fsm * fsm ) ;
