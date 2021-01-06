#pragma once

#include "fuse_common.h"

struct fuse_fsm;
typedef int (*fuse_async_get_msg_t)(int *err,struct fuse_fsm** fsm);
typedef void* (*fuse_alloc_payload_buffer_element)(size_t size);
typedef void (*fuse_free_payload_buffer_element)(void* element);
typedef void* (*fuse_get_payload_buffer_element_buf_ptr)(void* element);

struct fuse_user_data_context {
	void* user_context;
	int user_context_events_fd;
	fuse_async_get_msg_t callback_on_new_msg;
	fuse_alloc_payload_buffer_element alloc_payload_buffer_element;
	fuse_free_payload_buffer_element free_payload_buffer_element;
	fuse_get_payload_buffer_element_buf_ptr get_payload_buffer_element_buf_ptr;
};


extern __thread struct fuse_user_data_context g_fuse_user_data_context;
