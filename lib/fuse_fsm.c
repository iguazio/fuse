#include "fuse_fsm.h"

static int evnt_str_to_id(struct fuse_fsm * fsm, const char *event){
    int i;
    for (i=0; i<fsm->num_of_events; i++){
        if (!strcmp(fsm->events[i],event))
            return i;
    }
    return -1;
}

static int state_str_to_id(struct fuse_fsm * fsm, const char *state){
    int i;
    for (i=0; i<fsm->num_of_states; i++){
        if (!strcmp(fsm->states[i],state))
            return i;
    }
    return -1;
}

int fuse_fsm_run( struct fuse_fsm * fsm, const char* event ) 
{
    int curr_s = fsm->current_state;
    int event_id = evnt_str_to_id(fsm,event);
    if (event_id == -1)
        return -1;

    const struct fuse_fsm_entry *entry = &fsm->fuse_fsm_transition_table[fsm->num_of_states*event_id + curr_s];

    //Debug
    printf("FSM %s %s->%s\n",fsm->name,fsm->states[curr_s],entry->next_state);

    const char* next_event = entry->f(fsm, fsm->data);
    fsm->current_state = state_str_to_id(fsm,entry->next_state);
	if (next_event != NULL)
		return fuse_fsm_run(fsm, next_event);
    return 0;
}

const char* fuse_fsm_cur_state( struct fuse_fsm * fsm ) 
{
    return fsm->states[fsm->current_state];
}

const char* fuse_lib_fsm_transition_function_null(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    fprintf(stderr,"panic - unexpected state transition in %s %p\n", fsm->name, data);
	return NULL;
}

void fuse_fsm_set_err( struct fuse_fsm *fsm, int err )
{
    fsm->err = err;
}

int fuse_fsm_get_err( struct fuse_fsm *fsm )
{
    return fsm->err;
}
