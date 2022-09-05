#ifndef DQDK_DLOG_H
#define DQDK_DLOG_H

#include <stdio.h>

#define dlogv(format, vargs...) fprintf(stdout, format, vargs)
#define dlog(format) fprintf(stdout, format)

#define dlog_error2(func, ret) dlogv("[ERROR] [%s:%d] " func " (%d): %s\n", \
    __FILE__, __LINE__, ret, strerror(errno));

#define dlog_error(error) dlogv("[ERROR] %s\n", error)
#define dlog_errorv(errfmt, vargs...) dlogv("[ERROR] " errfmt "\n", vargs)

#define dlog_warn(func, ret) dlogv("[WARN] [%s:%d] " func " (%d): %s\n", __FILE__, __LINE__, ret, strerror(errno));

#define dlog_info(info) dlogv("[INFO] %s\n", info)
#define dlog_info_head(info) dlogv("[INFO] %s", info)
#define dlog_info_print(fmt, vargs...) dlogv(fmt, vargs)
#define dlog_info_exit() dlog("\n")

#define dlog_infov(infofmt, vargs...) dlogv("[INFO] " infofmt "\n", vargs)

#endif
