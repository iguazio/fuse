#pragma once
#include <stdint.h>
#define FUSE_LOG_ERROR 0
#define FUSE_LOG_WARN 1
#define FUSE_LOG_DEBUG 2

typedef void(*fuse_log_t)(const char *file, int line, const char *function, int level, const char *fmt, ...);
uint64_t    fuse_current_uniqueid(void);

extern fuse_log_t _fuse_log;
fuse_log_t fuse_log_set(fuse_log_t new_callback);

#define fuse_log_err(fmt, ...) _fuse_log(__FILE__, __LINE__, __FUNCTION__, FUSE_LOG_ERROR, "unique: %llu " fmt, fuse_current_uniqueid(), ##__VA_ARGS__)
#define fuse_log_warn(fmt, ...) _fuse_log(__FILE__, __LINE__, __FUNCTION__, FUSE_LOG_WARN, "unique: %llu " fmt, fuse_current_uniqueid(), ##__VA_ARGS__)
#define fuse_log_debug(fmt, ...) _fuse_log(__FILE__, __LINE__, __FUNCTION__, FUSE_LOG_DEBUG, "unique: %llu " fmt, fuse_current_uniqueid(), ##__VA_ARGS__)
#define fuse_log_err_unique(fmt,_curr_uniq_id, ...) _fuse_log(__FILE__, __LINE__, __FUNCTION__, FUSE_LOG_ERROR, "unique: %llu " fmt, _curr_uniq_id, ##__VA_ARGS__)
#define fuse_log_warn_unique(fmt,_curr_uniq_id, ...) _fuse_log(__FILE__, __LINE__, __FUNCTION__, FUSE_LOG_WARN, "unique: %llu " fmt, _curr_uniq_id, ##__VA_ARGS__)
#define fuse_log_debug_unique(fmt,_curr_uniq_id, ...) _fuse_log(__FILE__, __LINE__, __FUNCTION__, FUSE_LOG_DEBUG, "unique: %llu " fmt, _curr_uniq_id, ##__VA_ARGS__)




