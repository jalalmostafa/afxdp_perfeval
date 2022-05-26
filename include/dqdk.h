#ifndef DQDK_H
#define DQDK_H

#include <sys/uio.h>

#include "datatypes.h"
#include "dqdkopts.h"
#include "mem.h"

enum {
    DQDK_SRC_UDP = 0,
#define DQDK_SRC_KERN_UDP DQDK_SRC_KERN_UDP
    DQDK_SRC_XDP_UDP
#define DQDK_SRC_USER_UDP DQDK_SRC_XDP_UDP
};

enum {
    DQDK_DST_KERN_UDP = 0,
#define DQDK_DST_KERN_UDP DQDK_DST_KERN_UDP
    DQDK_DST_USER_UDP,
#define DQDK_DST_USER_UDP DQDK_DST_USER_UDP
    DQDK_DST_RDMA,
#define DQDK_DST_RDMA DQDK_DST_RDMA,
    DQDK_DST_FILE,
#define DQDK_DST_FD DQDK_DST_FILE,

};

struct dqdk_src {
    u16 type;
    int (*open)(struct dqdk_ctx* ctx, void* options);
    /* returns < 0 on failure, reutrns number of available packets on success*/
    int (*pollv)(struct dqdk_ctx* ctx, u8* buffer, u32 vcount, u32 timeout);
    int (*close)(struct dqdk_ctx* ctx);
};

struct dqdk_dst {
    u16 type;
    int (*open)(struct dqdk_ctx* ctx, void* options);
    int (*writev)(struct dqdk_ctx* ctx, u8* buffer, u32 size);
    int (*close)(struct dqdk_ctx* ctx);
};

struct dqdk_ctx {
    struct dqdk_src* src;
    struct dqdk_dst* dst;
    struct dqdk_iovec* iovecs;
    struct dqdk_opts opts;
    u8* buffer;
    void* private;
};

struct dqdk_ctx* dqdk_init(struct dqdk_src* src, struct dqdk_dst* dst, struct dqdk_opts opts);
int dqdk_run_loop(struct dqdk_ctx* ctx, int (*break_condition)());
int dqdk_free(struct dqdk_ctx* ctx);

#endif
