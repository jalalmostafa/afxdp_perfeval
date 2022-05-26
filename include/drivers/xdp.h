#ifndef DQDK_ADAPTER_XDP_H
#define DQDK_ADAPTER_XDP_H

#include <stdio.h>
#include <xdp/libxdp.h>

#include "dqdk.h"
#include "../datatypes.h"

struct dqdk_xdp_ctx;

struct xdp_opts {
    const char* ifname;
    int ifindex;
    enum xdp_attach_mode mode;
    bool verbose;
    u32 queue_id;
    u32 mtu;
    u64 hugetable_size;
};

int xdp_open(struct dqdk_ctx* ctx, void* opts);
int xdp_pollv(struct dqdk_ctx* ctx, u8* buffer, u32 vcount, u32 timeout);
int xdp_writev(struct dqdk_ctx* ctx, u8* buffer, u32 size);
int xdp_cleanup(struct dqdk_ctx* ctx);

#endif
