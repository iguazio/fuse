#include <stdio.h>
#include <stdarg.h>
#include "fuse_log.h"

static void stderr_log(const char *file, int line, const char *function, int level, const char *fmt, ...);

fuse_log_t _fuse_log = stderr_log;

fuse_log_t fuse_log_set(fuse_log_t new_callback)
{
    fuse_log_t old = _fuse_log;
    _fuse_log = new_callback;
    return old;
}

static void stderr_log(const char *file, int line, const char *function, int level, const char *fmt, ...)
{
    va_list args;
    char buf[2048];
    (void)line;
    (void)file;
    (void)function;
    (void)level;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    fputs(buf, stderr);
}
