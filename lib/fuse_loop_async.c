/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "config.h"
#include "fuse_lowlevel.h"
#include "fuse_async_response.h"
#include "fuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>


static int signaler_fd_create(int *out_fd)
{
    int32_t signum_vec[] =
    { SIGQUIT,
        SIGTERM,
        SIGHUP,
        SIGPIPE,
        SIGABRT,
        SIGCHLD
    };
    uint32_t signum_vlen = sizeof(signum_vec) / sizeof(signum_vec[0]);
    sigset_t mask;
    size_t i;
    int32_t fd;

    /* Create a sigset of all the signals that we're interested in */
    sigemptyset(&mask);
    for (i = 0; i < signum_vlen; ++i)
        sigaddset(&mask, signum_vec[i]);

    /* We must block the signals in order for signalfd to receive them */
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        return errno;

    fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (fd == -1)
        return errno;

    *out_fd = fd;

    return 0;
}



int fuse_session_loop_async( struct fuse_session *se, int fd, fuse_async_get_msg_t callback_on_new_msg, void* callback_payload)
{
    int res = 0;
    struct fuse_chan *ch = fuse_session_chan(se);
    struct fuse_fsm* fsm;
    struct fuse_buf fbuf = {
        .mem = NULL,
    };

    struct pollfd fds[3];
    int ret;

    /* Open STREAMS device. */
    fds[0].fd = fuse_chan_fd(ch);
    fds[0].events = POLLIN;


    fds[1].fd = fd;
    fds[1].events = POLLIN;

    
    fds[2].events = POLLIN;
    if (signaler_fd_create(&fds[2].fd)) {
        fprintf(stderr, "Failed to create signaler_fd\n");
        return -errno;
    }

    while (!fuse_session_exited(se)) {
        ret = poll(fds, 3, -1);
        if (ret > 0){
            if (fds[0].revents & POLLIN){
                res = fuse_session_receive_buf(se, &fbuf, ch);
                if (res == -EINTR)
                    continue;
                if (res <= 0)
                    break;
                fuse_session_process_buf(se, &fbuf, ch);
            }
            if (fds[0].revents & POLLERR) {
                break;
            }
            if (fds[1].revents & POLLIN){
                int err;
                while (!callback_on_new_msg(callback_payload,&err,&fsm)){
                    fuse_fsm_set_err(fsm,err);
                    fuse_fsm_run(fsm,err?FUSE_FSM_EVENT_ERROR:FUSE_FSM_EVENT_OK);
                    if (fuse_fsm_is_done(fsm))
                        FUSE_FSM_FREE(fsm);
                }
            }
            while ((fsm = fuse_dlist_pop(&pending_fsm_queue, struct fuse_fsm, node)) != NULL) {
                fuse_dlist_add(&allocated_fsm, &fsm->node);
                fuse_fsm_run(fsm, fsm->pending_event);
                if (fuse_fsm_is_done(fsm))
                    FUSE_FSM_FREE(fsm);
            }
            
            if (fds[2].revents & POLLIN) 
            {
                fprintf(stderr, "fuse:caught exit signal\n");
                fuse_session_exit(se);
            }
        }
        fuse_mem_verify();
    }

    fuse_free(fbuf.mem);
    fuse_session_reset(se);
    close(fds[2].fd);
    return res < 0 ? -1 : 0;
}
