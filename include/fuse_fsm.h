#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuse_async_responce.h"

typedef const char* (*fuse_lib_fsm_transition_function_t)(const char * from,const char * to,void *data);
const char* fuse_lib_fsm_transition_function_null(const char * from,const char * to,void *data);

struct fuse_fsm_entry{
    const char *next_state;
    fuse_lib_fsm_transition_function_t f;
};

struct fuse_fsm{
    int current_state;
    const char** events;
    const char** states;
    const struct fuse_fsm_entry *fuse_fsm_transition_table;
    const int num_of_states;
    const int num_of_events;
    char data[0];
};


#define NONE {NULL,fuse_lib_fsm_transition_function_null}


#define FUSE_FSM_EVENTS(api_name,...) \
    static const char *fuse_fsm_events_##api_name[]={__VA_ARGS__};
#define FUSE_FSM_STATES(api_name,...)\
    static const char *fuse_fsm_states_##api_name[]={__VA_ARGS__};\
    static const struct fuse_fsm_entry fuse_fsm_transition_table_##api_name[sizeof(fuse_fsm_events_##api_name)/sizeof(fuse_fsm_events_##api_name[0])][sizeof(fuse_fsm_states_##api_name)/sizeof(fuse_fsm_states_##api_name[0])] = {
#define FUSE_FSM_ENTRY(...) {__VA_ARGS__},
#define FUSE_FSM_LAST(...) {__VA_ARGS__}};

#define _FUSE_FSM_INIT(api_name) {0, (const char**)fuse_fsm_events_##api_name,\
    (const char**)fuse_fsm_states_##api_name,\
   (const struct fuse_fsm_entry *)fuse_fsm_transition_table_##api_name,\
    sizeof(fuse_fsm_states_##api_name)/sizeof(fuse_fsm_states_##api_name[0]),\
    sizeof(fuse_fsm_events_##api_name)/sizeof(fuse_fsm_events_##api_name[0])}

#define FUSE_FSM_ALLOC(api_name,fsm,tt) {struct fuse_fsm f = _FUSE_FSM_INIT(api_name);\
    fsm = (struct fuse_fsm*)calloc(1,sizeof(struct fuse_fsm) + sizeof(tt));\
    memcpy(fsm,&f,sizeof(struct fuse_fsm));}


#define FUSE_FSM_FREE(fsm)   free(fsm)

int fuse_fsm_run( struct fuse_fsm * fsm, const char* event ); 
const char* fuse_fsm_cur_state( struct fuse_fsm * fsm ) ;
