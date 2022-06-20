#ifndef DQDK_DLOG_H
#define DQDK_DLOG_H

#include <stdio.h>

#define dlog(format, vargs...)          \
    do {                                \
        fprintf(stderr, format, vargs); \
    } while (0)

#define dlog_error2(func, ret) dlog("[ERROR] [%s:%d] " func " (%d): %s\n", \
    __FILE__, __LINE__, ret, strerror(errno));

#define dlog_error(error) dlog("[ERROR] %s\n", error)
#define dlog_errorv(errfmt, vargs...) dlog("[ERROR] " errfmt "\n", vargs)

#define dlog_warn(func, ret) dlog("[WARN] [%s:%d] " func " (%d): %s\n", \
    __FILE__, __LINE__, ret, strerror(errno));

#define dlog_info(info) dlog("[INFO] %s\n", info)

#endif
