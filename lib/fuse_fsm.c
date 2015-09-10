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

/*FixMe: strcmp()  should be optimized*/
int fuse_fsm_run( struct fuse_fsm * fsm, const char* event ) 
{
    int curr_s = fsm->current_state;
    int event_id = evnt_str_to_id(fsm,event);
    if (event_id == -1)
        return -1;

    const struct fuse_fsm_entry *entry = &fsm->fuse_fsm_transition_table[fsm->num_of_events*event_id + curr_s];

    entry->f(fsm->states[curr_s],entry->next_state, fsm->data);
    fsm->current_state = state_str_to_id(fsm,entry->next_state);
    return 0;
}

const char* fuse_fsm_cur_state( struct fuse_fsm * fsm ) 
{
    return fsm->states[fsm->current_state];
}

void fuse_lib_fsm_transition_function_null(const char * from,const char * to,void *data){
    fprintf(stderr,"panic - unexpected state transition (%s->%s),%p\n",from,to,data);
}
