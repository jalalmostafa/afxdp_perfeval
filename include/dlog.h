#ifndef DQDK_DLOG_H
#define DQDK_DLOG_H

#include <stdio.h>

#ifndef DEBUG
#define dlog(format, vargs...)
#else
#define dlog(format, vargs...)          \
    do {                                \
        fprintf(stderr, format, vargs); \
    } while (0)
#endif

#define dlog_error(func, ret) dlog("[ERROR] [%s:%d]" func "(%d): %s\n", \
    __FILE__, __LINE__, ret, strerror(errno));

#define dlog_warn(func, ret) dlog("[WARN] [%s:%d]" func "(%d): %s\n", \
    __FILE__, __LINE__, ret, strerror(errno));

#endif
