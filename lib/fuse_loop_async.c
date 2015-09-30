/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "config.h"
#include "fuse_lowlevel.h"
#include "fuse_async_responce.h"
#include "fuse.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stropts.h>
#include <poll.h>




int fuse_session_loop_async( struct fuse_session *se, int fd, fuse_async_get_msg_t callback_on_new_msg, void* callback_payload)
{
    int res = 0;
    struct fuse_chan *ch = fuse_session_chan(se);
    struct fuse_buf fbuf = {
        .mem = NULL,
    };

    struct pollfd fds[2];
    int ret;

    /* Open STREAMS device. */
    fds[0].fd = fuse_chan_fd(ch);
    fds[0].events = POLLIN;


    fds[1].fd = fd;
    fds[1].events = POLLIN;

    while (!fuse_session_exited(se)) {
        ret = poll(fds, 2, -1);
        if (ret > 0){
            if (fds[0].revents & POLLIN){
                res = fuse_session_receive_buf(se, &fbuf, ch);
                if (res == -EINTR)
                    continue;
                if (res <= 0)
                    break;
                fuse_session_process_buf(se, &fbuf, ch);
            }
            if (fds[1].revents & POLLIN){
                int err;
                struct fuse_fsm* fsm;
                if (!callback_on_new_msg(callback_payload,&err,&fsm)){
                    fuse_fsm_set_err(fsm,err);
                    fuse_fsm_run(fsm,err?"error":"ok");
                }
            }
        }
    }

    free(fbuf.mem);
    fuse_session_reset(se);
    return res < 0 ? -1 : 0;
}
