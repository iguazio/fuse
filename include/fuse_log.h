#pragma once
#include <stdint.h>
#define FUSE_LOG_ERROR 0
#define FUSE_LOG_WARN 1
#define FUSE_LOG_DEBUG 2

typedef void(*fuse_log_t)(const char *file, int line, const char *function, int level, const char *fmt, ...);
uint64_t    fuse_current_context_uniqueid(void);

extern fuse_log_t _fuse_log;
fuse_log_t fuse_log_set(fuse_log_t new_callback);

#define fuse_log_err(fmt, ...) _fuse_log(__FILE__, __LINE__, __FUNCTION__, FUSE_LOG_ERROR, "unique: %llu " fmt, fuse_current_context_uniqueid(), ##__VA_ARGS__)
#define fuse_log_warn(fmt, ...) _fuse_log(__FILE__, __LINE__, __FUNCTION__, FUSE_LOG_WARN, "unique: %llu " fmt, fuse_current_context_uniqueid(), ##__VA_ARGS__)
#define fuse_log_debug(fmt, ...) _fuse_log(__FILE__, __LINE__, __FUNCTION__, FUSE_LOG_DEBUG, "unique: %llu " fmt, fuse_current_context_uniqueid(), ##__VA_ARGS__)




