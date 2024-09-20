#include "fuse_fsm.h"
#include <assert.h>
#include "fuse_log.h"

struct fuse_dlist_head allocated_fsm = FUSE_DLIST_HEAD_INIT(allocated_fsm);
struct fuse_dlist_head pending_fsm_queue = FUSE_DLIST_HEAD_INIT(pending_fsm_queue);



static  struct fuse_fsm_event fsm_process_event( struct fuse_fsm * fsm, struct fuse_fsm_event event ){
    int curr_s = fsm->current_state;
	int event_id = event.id;
    assert (event_id >= 0);

    const struct fuse_fsm_entry *entry = &fsm->fuse_fsm_transition_table[fsm->num_of_states*event_id + curr_s];

    int hist_idx = fsm->hist.curr_idx % FSM_HIST_DEPTH;
    fsm->hist.entries[hist_idx].id = fsm->hist.curr_idx;
    fsm->hist.entries[hist_idx].from_state = fsm->current_state;
    fsm->hist.entries[hist_idx].to_state = entry->next_state_id;
    fsm->hist.entries[hist_idx].by_event = event_id;


    fuse_log_debug("FSM %p %s %s %s->%s\n",fsm, fsm->name, event.name, fsm->states[curr_s],entry->next_state);

    fsm->current_state = entry->next_state_id;
    struct fuse_fsm_event next_event = entry->f(fsm, fsm->data);
    fsm->hist.entries[hist_idx].next_event = next_event.id;

    fsm->hist.entries[hist_idx].fsm_err_after_transition = fsm->err;
    fsm->hist.curr_idx++;

    return next_event;
}
void fuse_fsm_run( struct fuse_fsm * fsm, struct fuse_fsm_event event ) 
{
    *fuse_get_context() = fsm->fuse_ctxt;

    while (event.id != FUSE_FSM_EVENT_NONE.id)
        event = fsm_process_event(fsm,event);
}


const char* fuse_fsm_cur_state( struct fuse_fsm * fsm ) 
{
    return fsm->states[fsm->current_state];
}

struct fuse_fsm_event fuse_lib_fsm_transition_function_null(struct fuse_fsm* fsm __attribute__((unused)),void *data){
    fuse_log_err("panic - unexpected state transition in %s %p. Dumping history of processed %d states:\n", fsm->name, data, fsm->hist.curr_idx);
    int num_of_entries = fsm->hist.curr_idx > FSM_HIST_DEPTH ? FSM_HIST_DEPTH:fsm->hist.curr_idx;
    for (int i = 0;i < num_of_entries; i++)
        fuse_log_err("%s: [%d] %d->%d by %d , err after %d, next event %d\n", 
            fsm->name,  
            fsm->hist.entries[i].id,
            fsm->hist.entries[i].from_state,
            fsm->hist.entries[i].to_state,
            fsm->hist.entries[i].by_event,
            fsm->hist.entries[i].fsm_err_after_transition, 
            fsm->hist.entries[i].next_event);

	return FUSE_FSM_EVENT_NONE;
}

void fuse_fsm_set_err( struct fuse_fsm *fsm, int err )
{
    fsm->err = err;
}

int fuse_fsm_get_err( struct fuse_fsm *fsm )
{
    return fsm->err;
}


int fuse_fsm_is_done(struct fuse_fsm *fsm)
{
	return fsm->current_state == fsm->num_of_states-1;
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
