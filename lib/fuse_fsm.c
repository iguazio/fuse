#include "fuse_fsm.h"
#include <assert.h>

static int debug = 0;


static int evnt_str_to_id(struct fuse_fsm * fsm, const char *event){
    int i;
    for (i=0; i<fsm->num_of_events; i++){
        if (!strcmp(fsm->events[i],event))
            return i;
    }
    return -1;
}

static  const char* fsm_process_event( struct fuse_fsm * fsm, const char* event ){
    int curr_s = fsm->current_state;
    int event_id = evnt_str_to_id(fsm,event);
    assert (event_id >= 0);

    const struct fuse_fsm_entry *entry = &fsm->fuse_fsm_transition_table[fsm->num_of_states*event_id + curr_s];

    if (debug)
        printf("FSM %p %s %s %s->%s\n",fsm, fsm->name, event, fsm->states[curr_s],entry->next_state);

    fsm->current_state = entry->next_state_id;
    const char* next_event = entry->f(fsm, fsm->data);

    return next_event;
}
void fuse_fsm_run( struct fuse_fsm * fsm, const char* event ) 
{
    while (event != NULL)
        event = fsm_process_event(fsm,event);

    if (fsm->do_free_on_done && !strcmp(fuse_fsm_cur_state(fsm),"DONE"))
        FUSE_FSM_FREE(fsm);
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

void fuse_fsm_free_on_done( struct fuse_fsm *fsm, int do_cleanup )
{
    fsm->do_free_on_done = do_cleanup;
}

void fuse_fsm_set_debug(int d){
    debug = d;
}

int _fuse_fsm_state_str_to_id( int num_of_states,const char** states,const char *state )
{
    int i;
    if (state == NULL)
        return -1;
    for (i=0; i<num_of_states; i++){
        if (!strcmp(states[i],state))
            return i;
    }
    return -1;
}
