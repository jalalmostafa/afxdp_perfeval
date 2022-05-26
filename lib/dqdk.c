#include <poll.h>
#include <errno.h>
#include <stdlib.h>

#include "drivers/xdp.h"
#include "dqdkopts.h"
#include "dqdk.h"
#include "dlog.h"

struct dqdk_ctx* dqdk_init(struct dqdk_src* src, struct dqdk_dst* dst,
    struct dqdk_opts opts)
{
    struct dqdk_ctx* ctx = calloc(1, sizeof(struct dqdk_ctx));
    ctx->src = src;
    ctx->dst = dst;
    ctx->opts = opts;
    // ctx->iovecs = dqdk_iovec_init(opts.payload_size, opts.sg_entries);
    ctx->iovecs = NULL;
    ctx->buffer = DQDK_BUFFER_ALLOC(opts.payload_size * opts.sg_entries);
    return ctx;
}

int dqdk_run_loop(struct dqdk_ctx* ctx, int (*break_condition)())
{
    int ret = 0;
    int dst_status = 0, src_status = 0;

    if (ctx == NULL) {
        return -EINVAL;
    }

    while (!break_condition()) {
        ret = ctx->src->pollv(ctx, ctx->buffer, ctx->opts.sg_entries, ctx->opts.poll_timeout);

        if (ret <= 0) {
            dlog_warn("ctx->src->pollv", ret);
            continue;
        }

        ret = ctx->dst->writev(ctx, ctx->buffer, ret);
        if (ret <= 0) {
            dlog_error("ctx->dst->writev", ret);
        }
    }

    return ret;
}

int dqdk_free(struct dqdk_ctx* ctx)
{
    if (ctx != NULL) {
        dqdk_iovec_free(ctx->iovecs);
        free(ctx);
        return 1;
    }

    return 0;
}