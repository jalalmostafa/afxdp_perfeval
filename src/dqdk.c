// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/icmp.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <netinet/udp.h>
#include <math.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <time.h>
#include <endian.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>

#include "dqdk.h"
#include "tcpip/ipv4.h"
#include "tcpip/udp.h"

#define UMEM_LEN (XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

#define MAX_QUEUES 16
#define UMEM_SIZE (UMEM_LEN * FRAME_SIZE)
#define FILLQ_LEN UMEM_LEN
#define COMPQ_LEN XSK_RING_PROD__DEFAULT_NUM_DESCS

struct xsk_stat {
    u64 rcvd_frames;
    u64 rcvd_pkts;
    u64 fail_polls;
    u64 timeout_polls;
    u64 rx_empty_polls;
    u64 rx_fill_fail_polls;
    u64 rx_successful_fills;
    u64 tx_successful_fills;
    u64 invalid_ip_pkts;
    u64 invalid_udp_pkts;
    u64 runtime;
    u64 tx_wakeup_sendtos;
    u64 sent_frames;
    struct xdp_statistics xstats;
};

typedef struct {
    struct xsk_umem* umem;
    struct xsk_ring_prod fq0;
    struct xsk_ring_cons cq0;
    u32 nbfqs;
    u32 size;
    void* buffer;
} umem_info;

typedef struct {
    u16 index;
    u16 queue_id;
    struct xsk_socket* socket;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    umem_info* umem_info;
    struct xsk_ring_prod* fill_ring;
    struct xsk_ring_cons* comp_ring;
    u32 libbpf_flags;
    u32 xdp_flags;
    u16 bind_flags;
    u32 batch_size;
    u8 busy_poll;
    u16 tx_pkt_size;
    u32 outstanding_tx;
    struct xsk_stat stats;
} xsk_info;

u32 break_flag = 0;

static void* umem_buffer_create(u32 size)
{
#ifdef NO_HGPG
    return mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
    return huge_malloc(size);
#endif
}

static umem_info* umem_info_create(u32 nbfqs)
{
    umem_info* info = (umem_info*)calloc(1, sizeof(umem_info));

    info->size = UMEM_SIZE * nbfqs;
    info->buffer = umem_buffer_create(info->size);
    if (info->buffer == NULL) {
        dlog_error2("umem_buffer_create", 0);
        return NULL;
    }

    info->umem = NULL;
    info->nbfqs = nbfqs;
    return info;
}

static void umem_info_free(umem_info* info)
{
    if (info != NULL) {
        munmap(info->buffer, info->size);
        xsk_umem__delete(info->umem);
    }
}

static int umem_configure(umem_info* umem)
{
    int ret;

    if (umem == NULL) {
        dlog_error("Invalid umem buffer: NULL");
        return EINVAL;
    }

    const struct xsk_umem_config cfg = {
        .fill_size = FILLQ_LEN,
        .comp_size = COMPQ_LEN,
        .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
#ifdef UMEM_UNALIGNED
        .flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG
#else
        .flags = 0
#endif
    };

    ret = xsk_umem__create(&umem->umem, umem->buffer, umem->size,
        &umem->fq0, &umem->cq0, &cfg);
    if (ret) {
        dlog_error2("xsk_umem__create", ret);
        return ret;
    }

    return 0;
}

static int xsk_configure(xsk_info* xsk, const char* ifname)
{
    int ret = 0;
    u32 nbfqs = xsk->umem_info->nbfqs;

    const struct xsk_socket_config xsk_config = {
        .rx_size = FILLQ_LEN,
        .tx_size = COMPQ_LEN,
        .bind_flags = xsk->bind_flags,
        .libbpf_flags = xsk->libbpf_flags,
        .xdp_flags = xsk->xdp_flags
    };

    struct xsk_ring_prod* fq = NULL;
    struct xsk_ring_cons* cq = NULL;

    if (nbfqs == 1) {
        fq = &xsk->umem_info->fq0;
    } else {
        if (xsk->fill_ring == NULL) {
            xsk->fill_ring = calloc(1, sizeof(struct xsk_ring_prod));
        }

        fq = xsk->fill_ring;
    }

    if (nbfqs == 1) {
        cq = &xsk->umem_info->cq0;
    } else {
        if (xsk->comp_ring == NULL) {
            xsk->comp_ring = calloc(1, sizeof(struct xsk_ring_cons));
        }

        cq = xsk->comp_ring;
    }

    ret = xsk_socket__create_shared(&xsk->socket, ifname, xsk->queue_id,
        xsk->umem_info->umem, &xsk->rx, &xsk->tx, fq, cq, &xsk_config);
    if (ret) {
        dlog_error2("xsk_socket__create", ret);
        return ret;
    }

    if (xsk->busy_poll) {
        u32 sockopt = 1;
        ret = setsockopt(xsk_socket__fd(xsk->socket), SOL_SOCKET, SO_PREFER_BUSY_POLL,
            (void*)&sockopt, sizeof(sockopt));
        if (ret) {
            dlog_error2("setsockopt(SO_PREFER_BUSY_POLL)", ret);
            return ret;
        }

        sockopt = 20;
        ret = setsockopt(xsk_socket__fd(xsk->socket), SOL_SOCKET, SO_BUSY_POLL,
            (void*)&sockopt, sizeof(sockopt));
        if (ret) {
            dlog_error2("setsockopt(SO_BUSY_POLL)", ret);
            return ret;
        }

        sockopt = xsk->batch_size;
        ret = setsockopt(xsk_socket__fd(xsk->socket), SOL_SOCKET, SO_BUSY_POLL_BUDGET,
            (void*)&sockopt, sizeof(sockopt));
        if (ret) {
            dlog_error2("setsockopt(SO_BUSY_POLL_BUDGET)", ret);
            return ret;
        }
    }

    return 0;
}

static int fq_ring_configure(xsk_info* xsk)
{
    // push all frames to fill ring
    u32 idx = 0, ret, nbfqs = xsk->umem_info->nbfqs, fqlen = FILLQ_LEN;

    struct xsk_ring_prod* fq = nbfqs == 1 ? &xsk->umem_info->fq0
                                          : xsk->fill_ring;

    ret = xsk_ring_prod__reserve(fq, fqlen, &idx);
    if (ret != fqlen) {
        dlog_error2("xsk_ring_prod__reserve", ret);
        return EIO;
    }

    // fill addresses
    u32 base = nbfqs != 1 ? xsk->index * UMEM_SIZE : 0;
    for (u32 i = 0; i < fqlen; i++) {
        *xsk_ring_prod__fill_addr(fq, idx++) = base + (i * FRAME_SIZE);
    }

    xsk_ring_prod__submit(fq, fqlen);
    return 0;
}

static void pktgen_fill_umem(umem_info* umem, u8* dmac, u8* smac, u32 to, u16 pkt_size)
{
    u8 pkt_data[FRAME_SIZE];
    udp_create_frame(pkt_data, dmac, smac, pkt_size - ETH_FCS_SIZE);
    for (u32 i = 0; i < to; i++) {
        // udp_create_frame(pkt_data, dmac, smac, pkt_size - ETH_FCS_SIZE);
        u8* slot = xsk_umem__get_data(umem->buffer, i * FRAME_SIZE);
        memcpy(slot, pkt_data, pkt_size);
    }
}

always_inline u8* process_frame(xsk_info* xsk, u8* buffer, u32 len)
{
    struct ethhdr* frame = (struct ethhdr*)buffer;
    u16 ethertype = ntohs(frame->h_proto);

    xsk->stats.rcvd_frames++;
    if (ethertype != ETH_P_IP) {
        return NULL;
    }

    xsk->stats.rcvd_pkts++;
    struct iphdr* packet = (struct iphdr*)(frame + 1);
    if (packet->version != 4) {
        return NULL;
    }

    if (!ip4_audit(packet, len - sizeof(struct ethhdr))) {
        xsk->stats.invalid_ip_pkts++;
        return NULL;
    }

    u32 iphdrsz = ip4_get_header_size(packet);
    u32 udplen = ntohs(packet->tot_len) - iphdrsz;
    struct udphdr* udp = (struct udphdr*)(((u8*)packet) + iphdrsz);
    if (!udp_audit(udp, packet->saddr, packet->daddr, udplen)) {
        xsk->stats.invalid_udp_pkts++;
        return NULL;
    }

    return (u8*)(udp + 1);
}

always_inline int xdp_rxdrop(xsk_info* xsk, umem_info* umem)
{
    u32 idx_rx = 0, idx_fq = 0;
    struct xsk_ring_prod* fq = umem->nbfqs == 1 ? &umem->fq0 : xsk->fill_ring;

    int rcvd = xsk_ring_cons__peek(&xsk->rx, xsk->batch_size, &idx_rx);
    if (!rcvd) {
        /**
         * wakeup by issuing a recvfrom if needs wakeup
         * or if busy poll was specified. If SO_PREFER_BUSY_POLL is specified
         * then we should wake up to force a bottom-half interrup
         */
        if (xsk->busy_poll || xsk_ring_prod__needs_wakeup(fq)) {
            xsk->stats.rx_empty_polls++;
            recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }

        return ECOMM;
    }

    int ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
    while (ret != rcvd) {
        if (ret < 0) {
            return -ret;
        }

        if (xsk->busy_poll || xsk_ring_prod__needs_wakeup(fq)) {
            xsk->stats.rx_fill_fail_polls++;
            recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }

        ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
    }
    xsk->stats.rx_successful_fills++;
    for (int i = 0; i < rcvd; i++) {
        u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
#ifdef UMEM_UNALIGNED
        u64 orig = xsk_umem__extract_addr(addr);
        addr = xsk_umem__add_offset_to_addr(addr);
#endif

#ifdef UDP_MODE
        u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
        u8* frame = xsk_umem__get_data(umem->buffer, addr);
        u8* data = process_frame(xsk, frame, len);

        (void)data;
#else
        xsk_umem__get_data(umem->buffer, addr);
#endif
        idx_rx++;
#ifdef UMEM_UNALIGNED
        *xsk_ring_prod__fill_addr(fq, idx_fq) = orig;
#endif
        idx_fq++;
    }

#ifndef UDP_MODE
    xsk->stats.rcvd_frames += rcvd;
#endif

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk_ring_prod__submit(fq, rcvd);
    return 0;
}

always_inline int awake_sendto(xsk_info* xsk)
{
    if (sendto(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, 0) >= 0
        || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY
        || errno == ENETDOWN)
        return 0;
    return -1;
}

always_inline int complete_tx(xsk_info* xsk, struct xsk_ring_cons* cq)
{
    unsigned int rcvd, ret;
    u32 idx;

    if (!xsk->outstanding_tx)
        return 0;

    if (xsk->bind_flags & ~XDP_USE_NEED_WAKEUP || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
        xsk->stats.tx_wakeup_sendtos++;
        ret = awake_sendto(xsk);
        if (ret) {
            dlog_error2("awake_sendto", ret);
            return ECOMM;
        }
    }

    rcvd = xsk_ring_cons__peek(cq, xsk->batch_size, &idx);
    if (rcvd > 0) {
        xsk_ring_cons__release(cq, rcvd);
        xsk->outstanding_tx -= rcvd;
    }

    return 0;
}

always_inline int xdp_txonly(xsk_info* xsk, umem_info* umem, u32* umem_cursor)
{
    u32 idx;
    int ret;

    struct xsk_ring_cons* cq = umem->nbfqs == 1 ? &umem->cq0 : xsk->comp_ring;
    while (xsk_ring_prod__reserve(&xsk->tx, xsk->batch_size, &idx) < xsk->batch_size) {
        ret = complete_tx(xsk, cq);
        if (ret)
            return ret;

        if (break_flag)
            return 0;
    }

    u32 base = umem->nbfqs != 1 ? xsk->index * UMEM_SIZE : 0;
    for (u32 i = 0; i < xsk->batch_size; i++) {
        struct xdp_desc* desc = xsk_ring_prod__tx_desc(&xsk->tx, idx + i);
        desc->addr = base + ((*umem_cursor + i) * FRAME_SIZE);
        desc->len = xsk->tx_pkt_size - ETH_FCS_SIZE;
    }

    xsk->stats.tx_successful_fills++;
    xsk_ring_prod__submit(&xsk->tx, xsk->batch_size);
    xsk->stats.sent_frames += xsk->batch_size;
    xsk->outstanding_tx += xsk->batch_size;
    *umem_cursor += xsk->batch_size;
    *umem_cursor %= UMEM_LEN;

    ret = complete_tx(xsk, cq);
    if (ret)
        return ret;

    return 0;
}

always_inline int complete_tx_l2fwd(xsk_info* xsk, struct xsk_ring_prod* fq, struct xsk_ring_cons* cq)
{
    u32 idx_cq = 0, idx_fq = 0, rcvd;
    int ret;
    if (!xsk->outstanding_tx)
        return 0;

    if (xsk->bind_flags & XDP_COPY) {
        xsk->stats.tx_wakeup_sendtos++;
        awake_sendto(xsk);
    }

    /* re-add completed Tx buffers */
    size_t ndescs = (xsk->outstanding_tx > xsk->batch_size) ? xsk->batch_size : xsk->outstanding_tx;
    rcvd = xsk_ring_cons__peek(cq, ndescs, &idx_cq);
    if (rcvd > 0) {
        ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
        while (ret != (int)rcvd) {
            if (ret < 0) {
                dlog_error2("xsk_ring_prod__reserve", ret);
                return ECOMM;
            }

            if (xsk->busy_poll || xsk_ring_prod__needs_wakeup(fq)) {
                xsk->stats.rx_fill_fail_polls++;
                recvfrom(xsk_socket__fd(xsk->socket), NULL, 0,
                    MSG_DONTWAIT, NULL, NULL);
            }
            ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
        }

        for (u32 i = 0; i < rcvd; i++)
            *xsk_ring_prod__fill_addr(fq, idx_fq++) = *xsk_ring_cons__comp_addr(cq, idx_cq++);

        xsk_ring_prod__submit(fq, rcvd);
        xsk_ring_cons__release(cq, rcvd);
        xsk->outstanding_tx -= rcvd;
    }

    return 0;
}

always_inline int xdp_l2fwd(xsk_info* xsk, umem_info* umem)
{
    u32 rcvd, i;
    u32 idx_rx = 0, idx_tx = 0;
    int ret;
    struct xsk_ring_prod* fq = umem->nbfqs != 1 ? xsk->fill_ring : &umem->fq0;
    struct xsk_ring_cons* cq = umem->nbfqs != 1 ? xsk->comp_ring : &umem->cq0;

    complete_tx_l2fwd(xsk, fq, cq);

    rcvd = xsk_ring_cons__peek(&xsk->rx, xsk->batch_size, &idx_rx);
    if (!rcvd) {
        if (xsk->busy_poll || xsk_ring_prod__needs_wakeup(fq)) {
            xsk->stats.rx_empty_polls++;
            recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }

        return ECOMM;
    }

    xsk->stats.rcvd_frames += rcvd;

    ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
    while (ret != (int)rcvd) {
        if (ret < 0) {
            dlog_error2("xsk_ring_prod__reserve", ret);
            return ECOMM;
        }

        complete_tx_l2fwd(xsk, fq, cq);

        if (xsk->busy_poll || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
            xsk->stats.tx_wakeup_sendtos++;
            awake_sendto(xsk);
        }
        ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
    }

    xsk->stats.tx_successful_fills++;
    xsk->stats.rx_successful_fills++;
    for (i = 0; i < rcvd; i++) {
        u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

#ifdef UMEM_UNALIGNED
        u64 orig = addr;
        addr = xsk_umem__add_offset_to_addr(addr);
#endif
        char* pkt = xsk_umem__get_data(umem->buffer, addr);
        struct ether_header* eth = (struct ether_header*)pkt;
        struct ether_addr* src_addr = (struct ether_addr*)&eth->ether_shost;
        struct ether_addr* dst_addr = (struct ether_addr*)&eth->ether_dhost;
        struct ether_addr tmp;

        tmp = *src_addr;
        *src_addr = *dst_addr;
        *dst_addr = tmp;

#ifdef UMEM_UNALIGNED
        xsk_ring_prod__tx_desc(&xsk->tx, idx_tx)->addr = orig;
#else
        xsk_ring_prod__tx_desc(&xsk->tx, idx_tx)->addr = addr;
#endif
        xsk_ring_prod__tx_desc(&xsk->tx, idx_tx++)->len = len;
    }

    xsk_ring_prod__submit(&xsk->tx, rcvd);
    xsk_ring_cons__release(&xsk->rx, rcvd);

    xsk->stats.sent_frames += rcvd;
    xsk->outstanding_tx += rcvd;
    return 0;
}

struct benchmark_ctx {
    xsk_info* xsks;
    u32 nbxsks_per_thread;
    u8 pollmode;
    u8 shared_umem;
    u8 smac[6];
    u8 dmac[6];
};

#define POLL_TIMEOUT 1000

void* bench_rx(void* rxctx_ptr)
{
    struct benchmark_ctx* ctx = (struct benchmark_ctx*)rxctx_ptr;
    xsk_info* xsks = ctx->xsks;
    u64 t0, t1;

    switch (ctx->pollmode) {
    case DQDK_RCV_POLL:
        struct pollfd* fds = (struct pollfd*)calloc(ctx->nbxsks_per_thread, sizeof(struct pollfd));
        for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
            fds[i].fd = xsk_socket__fd(xsks[i].socket);
            fds[i].events = POLLIN;
        }

        t0 = clock_nsecs();
        while (!break_flag) {
            int ret = poll(fds, ctx->nbxsks_per_thread, POLL_TIMEOUT);
            if (ret < 0) {
                dlog_error2("poll", ret);
                continue;
            } else if (ret == 0) {
                dlog_info("[Poll] Timeout");
                continue;
            } else {
                for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
                    ret = xdp_rxdrop(&xsks[i], xsks[i].umem_info);
                }
            }
        }
        t1 = clock_nsecs();
        free(fds);
        break;
    case DQDK_RCV_RTC:
        t0 = clock_nsecs();
        while (!break_flag) {
            for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
                xdp_rxdrop(&xsks[i], xsks[i].umem_info);
            }
        }
        t1 = clock_nsecs();
        break;
    }

    socklen_t socklen = sizeof(struct xdp_statistics);
    for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
        xsks[i].stats.runtime = t1 - t0;
        int ret = getsockopt(xsk_socket__fd(xsks[i].socket), SOL_XDP,
            XDP_STATISTICS, &xsks[i].stats.xstats, &socklen);
        if (ret) {
            dlog_error2("getsockopt(XDP_STATISTICS)", ret);
        }
    }

    return NULL;
}

void* bench_tx(void* txctxptr)
{
    struct benchmark_ctx* ctx = (struct benchmark_ctx*)txctxptr;
    xsk_info* xsks = ctx->xsks;
    u32 umem_cursor = 0;
    u64 t0, t1;

    switch (ctx->pollmode) {
    case DQDK_RCV_POLL:
        struct pollfd* fds = (struct pollfd*)calloc(ctx->nbxsks_per_thread, sizeof(struct pollfd));

        for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
            fds[i].fd = xsk_socket__fd(xsks[i].socket);
            fds[i].events = POLLOUT;
        }

        t0 = clock_nsecs();
        while (!break_flag) {
            int ret = poll(fds, ctx->nbxsks_per_thread, POLL_TIMEOUT);
            if (ret < 0) {
                dlog_error2("poll", ret);
                continue;
            } else if (ret == 0) {
                dlog_info("[Poll] Timeout");
                continue;
            } else {
                for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
                    ret = xdp_txonly(&xsks[i], xsks[i].umem_info, &umem_cursor);
                }
            }
        }
        t1 = clock_nsecs();
        free(fds);
        break;
    case DQDK_RCV_RTC:
        t0 = clock_nsecs();
        while (!break_flag) {
            for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
                xdp_txonly(&xsks[i], xsks[i].umem_info, &umem_cursor);
            }
        }
        t1 = clock_nsecs();
        break;
    }

    socklen_t socklen = sizeof(struct xdp_statistics);
    for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
        xsks[i].stats.runtime = t1 - t0;
        int ret = getsockopt(xsk_socket__fd(xsks[i].socket), SOL_XDP,
            XDP_STATISTICS, &xsks[i].stats.xstats, &socklen);
        if (ret) {
            dlog_error2("getsockopt(XDP_STATISTICS)", ret);
        }
    }

    return NULL;
}

void* bench_l2fwd(void* l2fwdctxptr)
{
    struct benchmark_ctx* ctx = (struct benchmark_ctx*)l2fwdctxptr;
    xsk_info* xsks = ctx->xsks;
    u64 t0, t1;

    switch (ctx->pollmode) {
    case DQDK_RCV_POLL:
        struct pollfd* fds = (struct pollfd*)calloc(ctx->nbxsks_per_thread, sizeof(struct pollfd));

        for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
            fds[i].fd = xsk_socket__fd(xsks[i].socket);
            fds[i].events = POLLIN | POLLOUT;
        }

        t0 = clock_nsecs();
        while (!break_flag) {
            int ret = poll(fds, ctx->nbxsks_per_thread, POLL_TIMEOUT);
            if (ret < 0) {
                dlog_error2("poll", ret);
                continue;
            } else if (ret == 0) {
                dlog_info("[Poll] Timeout");
                continue;
            } else {
                for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
                    ret = xdp_l2fwd(&xsks[i], xsks[i].umem_info);
                }
            }
        }
        t1 = clock_nsecs();
        free(fds);
        break;
    case DQDK_RCV_RTC:
        t0 = clock_nsecs();
        while (!break_flag) {
            for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
                xdp_l2fwd(&xsks[i], xsks[i].umem_info);
            }
        }
        t1 = clock_nsecs();
        break;
    }

    socklen_t socklen = sizeof(struct xdp_statistics);
    for (size_t i = 0; i < ctx->nbxsks_per_thread; i++) {
        xsks[i].stats.runtime = t1 - t0;
        int ret = getsockopt(xsk_socket__fd(xsks[i].socket), SOL_XDP,
            XDP_STATISTICS, &xsks[i].stats.xstats, &socklen);
        if (ret) {
            dlog_error2("getsockopt(XDP_STATISTICS)", ret);
        }
    }

    return NULL;
}

void signal_handler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM:
    case SIGABRT:
    case SIGUSR1:
        break_flag = 1;
        break;
    default:
        break;
    }
}

int infoprint(enum libbpf_print_level level,
    const char* format, va_list ap)
{
    (void)level;
    return vfprintf(stderr, format, ap);
}

#define AVG_PPS(pkts, rt) (pkts * 1e9 / rt)

void stats_dump(struct xsk_stat* stats)
{
    printf("    Total runtime (ns):       %llu\n"
           "    Received Frames:          %llu\n"
           "    Average RX L2 PPS:        %f\n"
           "    Received Packets:         %llu\n"
           "    Average RX L3 PPS:        %f\n"
           "    Sent Frames:              %llu\n"
           "    Average TX Frames:        %f\n"
           "    Invalid L3 Packets:       %llu\n"
           "    Invalid L4 Packets:       %llu\n"
           "    Failed Polls:             %llu\n"
           "    Timeout Polls:            %llu\n"
           "    XSK Fill Fail Polls:      %llu\n"
           "    XSK RX Successful Fills:  %llu\n"
           "    XSK TX Successful Fills:  %llu\n"
           "    XSK RXQ Empty:            %llu\n"
           "    XSK TXQ Need Wakeup:      %llu\n"
           "    X-XSK RX Dropped:         %llu\n"
           "    X-XSK RX FillQ Empty:     %llu\n"
           "    X-XSK RX Invalid Descs:   %llu\n"
           "    X-XSK RX Ring Full:       %llu\n"
           "    X-XSK TX Invalid Descs:   %llu\n"
           "    X-XSK TX Ring Empty:      %llu\n",
        stats->runtime, stats->rcvd_frames,
        AVG_PPS(stats->rcvd_frames, stats->runtime), stats->rcvd_pkts,
        AVG_PPS(stats->rcvd_pkts, stats->runtime), stats->sent_frames,
        AVG_PPS(stats->sent_frames, stats->runtime),

        stats->invalid_ip_pkts, stats->invalid_udp_pkts,
        stats->fail_polls, stats->timeout_polls,
        stats->rx_fill_fail_polls, stats->rx_successful_fills,
        stats->tx_successful_fills, stats->rx_empty_polls, stats->tx_wakeup_sendtos,

        stats->xstats.rx_dropped, stats->xstats.rx_fill_ring_empty_descs,
        stats->xstats.rx_invalid_descs, stats->xstats.rx_ring_full,
        stats->xstats.tx_invalid_descs, stats->xstats.tx_ring_empty_descs);
}

void xsk_stats_dump(xsk_info* xsk)
{
    printf("XSK %u on Queue %u Statistics:\n", xsk->index, xsk->queue_id);
    stats_dump(&xsk->stats);
}

enum benchmark {
    BENCH_RX_DROP,
    BENCH_TX_ONLY,
    BENCH_L2FWD
};

typedef void* (*benchmark_handler_t)(void*);

#define XDP_FILE_XSK "./bpf/xsk.bpf.o"
#define XDP_FILE_RR2 "./bpf/rr2.bpf.o"
#define XDP_FILE_RR4 "./bpf/rr4.bpf.o"
#define XDP_FILE_RR8 "./bpf/rr8.bpf.o"

void dqdk_usage(char** argv)
{
    printf("Usage: %s -i <interface_name> -q <hardware_queue_id>\n", argv[0]);
    printf("Arguments:\n");

    printf("    -a <irq1,irq2,...>           Set affinity mapping between application threads and drivers queues\n");
    printf("                                 e.g. q1 to irq1, q2 to irq2,...\n");
    printf("    -d <duration>                Set the run duration in seconds. Default: 3 secs\n");
    printf("    -i <interface>               Set NIC to work on\n");
    printf("    -q <qid[-qid]>               Set range of hardware queues to work on e.g. -q 1 or -q 1-3.\n");
    printf("                                 Specifying multiple queues will launch a thread for each queue except if -p poll\n");
    printf("    -m <native|offload|generic>  Set XDP mode to 'native', 'offload', or 'generic'. Default: native\n");
    printf("    -c                           Enforce XDP Copy mode, default is zero-copy mode\n");
    printf("    -v                           Verbose\n");
    printf("    -b <size>                    Set batch size. Default: 64\n");
    printf("    -w                           Use XDP need wakeup flag\n");
    printf("    -p <poll|rtc>                Enforce poll or run-to-completion mode. Default: rtc\n");
    printf("    -s <nb_xsks>                 Set number of sockets working on shared umem\n");
    printf("    -t <tx-packet-size>          Set txonly packet size\n");
    printf("    -I <irq_string>              Read and count interrupts of interface from /proc/interrupts using its IRQ string\n");
    printf("    -M <rxdrop|txonly|l2fwd>     Set Microbenchmark. Default: rxdrop\n");
    printf("    -B                           Enable NAPI busy-poll\n");
    printf("    -D <dmac>                    Set destination MAC address for txonly\n");
    printf("    -H                           Considering Hyper-threading is enabled, this flag will assign affinity\n");
    printf("                                 of softirq and the app to two logical cores of the same physical core.\n");
}

int main(int argc, char** argv)
{
#ifdef UDP_MODE
    dlog_info("UDP Compilation!");
#else
    dlog_info("RX_DROP Compilation!");
#endif

#ifdef NO_HGPG
    dlog_info("NO_HGPG Compilation!");
#else
    dlog_info("HGPG Compilation!");
#endif

    // options values
    char *opt_ifname = NULL, *opt_irqstring = NULL;
    u8 opt_dmac[6] = { 0 };
    enum xdp_attach_mode opt_mode = XDP_MODE_NATIVE;
    enum benchmark opt_benchmark = BENCH_RX_DROP;
    benchmark_handler_t opt_handler = bench_rx;
    u32 opt_batchsize = 64, opt_queues[MAX_QUEUES] = { -1 },
        opt_irqs[MAX_QUEUES] = { -1 }, opt_shared_umem = 0;
    struct itimerspec opt_duration = {
        .it_interval.tv_sec = DQDK_DURATION,
        .it_interval.tv_nsec = 0,
        .it_value.tv_sec = opt_duration.it_interval.tv_sec,
        .it_value.tv_nsec = 0
    };
    u8 opt_needs_wakeup = 0, opt_verbose = 0, opt_zcopy = 1, opt_hyperthreading = 0,
       opt_pollmode = DQDK_RCV_RTC, opt_affinity = 0, opt_busy_poll = 0;
    u16 opt_txpktsize = 64;

    // program variables
    int ifindex, ret, opt;
    u32 nbqueues = 0, nbirqs = 0, nprocs = get_nprocs();
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    interrupts_t *before_interrupts = NULL, *after_interrupts = NULL;
    struct xdp_program* kern_prog = NULL;
    struct xdp_options xdp_opts;
    char* xdp_filename = XDP_FILE_XSK;
    pthread_t* xsk_workers = NULL;
    pthread_attr_t* xsk_worker_attrs = NULL;
    cpu_set_t* cpusets = NULL;
    xsk_info* xsks = NULL;
    umem_info* shared_umem = NULL;
    struct benchmark_ctx* ctxs = NULL;
    timer_t timer;
    socklen_t socklen;
    u8 smac[6];

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGUSR1, signal_handler);

    if (argc == 1) {
        dqdk_usage(argv);
        return 0;
    }

    while ((opt = getopt(argc, argv, "a:b:cd:hi:l:m:p:q:s:vwt:BI:M:D:H")) != -1) {
        switch (opt) {
        case 'h':
            dqdk_usage(argv);
            return 0;
        case 'a':
            // mapping to queues is 1-to-1 e.g. first irq to first queue...
            opt_affinity = 1;
            if (strchr(optarg, ',') == NULL) {
                nbirqs = 1;
                opt_irqs[0] = atoi(optarg);
            } else {
                char *delimiter = NULL, *cursor = optarg;
                u32 irq = -1;
                do {
                    irq = strtol(cursor, &delimiter, 10);
                    if (errno != 0
                        || cursor == delimiter
                        || (delimiter[0] != ',' && delimiter[0] != '\0')) {
                        dlog_error("Invalid IRQ string");
                        goto cleanup;
                    }

                    cursor = delimiter + 1;
                    opt_irqs[nbirqs++] = irq;
                } while (delimiter[0] != '\0');
            }
            break;
        case 'd':
            opt_duration.it_interval.tv_sec = atoi(optarg);
            opt_duration.it_interval.tv_nsec = 0;
            opt_duration.it_value.tv_sec = opt_duration.it_interval.tv_sec;
            opt_duration.it_value.tv_nsec = 0;
            break;
        case 'i':
            opt_ifname = optarg;
            ifindex = if_nametoindex(opt_ifname);
            break;
        case 'q':
            if (strchr(optarg, '-') == NULL) {
                nbqueues = 1;
                opt_queues[0] = atoi(optarg);
            } else {
                char* delimiter = NULL;
                u32 start = strtol(optarg, &delimiter, 10), end;
                if (delimiter != optarg) {
                    end = strtol(++delimiter, &delimiter, 10);
                } else {
                    dlog_error("Invalid queue range. Accepted: 1,2,3 or 1");
                    exit(EXIT_FAILURE);
                }

                nbqueues = (end - start) + 1;
                if (nbqueues > MAX_QUEUES) {
                    dlog_errorv("Too many queues. Maximum is %d", MAX_QUEUES);
                    exit(EXIT_FAILURE);
                }

                for (u32 idx = 0; idx < nbqueues; ++idx) {
                    opt_queues[idx] = start + idx;
                }
            }
            break;
        case 'm':
            if (strcmp("native", optarg) == 0) {
                opt_mode = XDP_MODE_NATIVE;
            } else if (strcmp("generic", optarg) == 0) {
                opt_mode = XDP_MODE_SKB;
            } else if (strcmp("offload", optarg) == 0) {
                opt_mode = XDP_MODE_HW;
            } else {
                dlog_error("Invalid XDP Mode");
                exit(EXIT_FAILURE);
            }
            break;
        case 'c':
            opt_zcopy = 0;
            break;
        case 'v':
            opt_verbose = 1;
            break;
        case 'b':
            opt_batchsize = atoi(optarg);
            break;
        case 'w':
            opt_needs_wakeup = 1;
            break;
        case 'p':
            if (strcmp("poll", optarg) == 0) {
                opt_pollmode = DQDK_RCV_POLL;
            } else if (strcmp("rtc", optarg) == 0) {
                opt_pollmode = DQDK_RCV_RTC;
            } else {
                dlog_error("Invalid Poll Mode");
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            opt_shared_umem = atoi(optarg);
            break;
        case 'I':
            opt_irqstring = optarg;
            break;
        case 'M':
            if (strcmp("rxdrop", optarg) == 0) {
                opt_handler = bench_rx;
                opt_benchmark = BENCH_RX_DROP;
            } else if (strcmp("txonly", optarg) == 0) {
                opt_handler = bench_tx;
                opt_benchmark = BENCH_TX_ONLY;
            } else if (strcmp("l2fwd", optarg) == 0) {
                opt_handler = bench_l2fwd;
                opt_benchmark = BENCH_L2FWD;
            } else {
                dlog_error("Invalid Benchmarking Mode");
                exit(EXIT_FAILURE);
            }
            break;
        case 'B':
            opt_busy_poll = 1;
            break;
        case 'D':
            if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    &opt_dmac[0], &opt_dmac[1], &opt_dmac[2], &opt_dmac[3],
                    &opt_dmac[4], &opt_dmac[5])
                < 6) {
                dlog_error("Invalid Destination MAC Address");
                exit(EXIT_FAILURE);
            }
            break;
        case 't':
            opt_txpktsize = atoi(optarg);
            if (opt_txpktsize < 64 || opt_txpktsize > 4096) {
                dlog_errorv("Invalid TX Packet Size %d (not between 64 and 4096)", opt_txpktsize);
                exit(EXIT_FAILURE);
            }
            break;
        case 'H':
            opt_hyperthreading = 1;
            break;
        default:
            dqdk_usage(argv);
            dlog_error("Invalid Arg\n");
            exit(EXIT_FAILURE);
        }
    }

    if (opt_ifname == NULL || nbqueues == 0) {
        dlog_error("Invalid interface name or number of queues");
        goto cleanup;
    }

    struct ifaddrs* addrs = NULL;
    getifaddrs(&addrs);
    if (addrs != NULL) {
        for (struct ifaddrs* addr = addrs;
             addr->ifa_next != NULL;
             addr = addr->ifa_next) {
            if (strcmp(addr->ifa_name, opt_ifname) == 0
                && addr->ifa_addr->sa_family == AF_PACKET) {
                u8* mac = ((struct sockaddr_ll*)addr->ifa_addr)->sll_addr;
                memcpy(smac, mac, 6);
            }
        }
        freeifaddrs(addrs);
    }

    if (opt_affinity) {
        if (opt_pollmode != DQDK_RCV_RTC) {
            dlog_error("IRQ and thread affinity is only possible in RTC mode using command option: -p rtc ");
            goto cleanup;
        }

        if (nbirqs != nbqueues) {
            dlog_error("IRQs and number of queues must be equal");
            goto cleanup;
        }

        if (nbirqs > nprocs) {
            dlog_error("IRQs should be smaller or equal to number of processors");
            goto cleanup;
        }
    }

    switch (opt_mode) {
    case XDP_MODE_SKB:
        dlog_info("XDP generic mode is activated.");
        break;
    case XDP_MODE_NATIVE:
        dlog_info("XDP driver mode is activated.");
        break;
    case XDP_MODE_HW:
        dlog_info("XDP HW-Offloading is activated.");
        break;
    default:
        break;
    }

    if (opt_zcopy && opt_mode == XDP_MODE_SKB) {
        dlog_info("Turning off zero-copy for XDP generic mode");
        opt_zcopy = 0;
    }

    switch (opt_benchmark) {
    case BENCH_RX_DROP:
        dlog_info("Benchmarking Mode: RX_DROP");
        break;
    case BENCH_TX_ONLY:
        dlog_info("Benchmarking Mode: TX_ONLY");
        break;
    case BENCH_L2FWD:
        dlog_info("Benchmarking Mode: L2FWD");
        break;
    default:
        break;
    }

    if (opt_verbose) {
        libbpf_set_print(infoprint);
    }

    switch (opt_pollmode) {
    case DQDK_RCV_POLL:
        dlog_info("Multithreading is turned off. Polling all sockets...");
        break;
    case DQDK_RCV_RTC:
        dlog_info("One fill queue per socket in run-to-completion mode");
        break;
    default:
        break;
    }

    u32 nbxsks = opt_shared_umem > 1 ? opt_shared_umem : nbqueues;
    char queues[4 * MAX_QUEUES] = { 0 };
    char* queues_format = queues;
    for (u32 i = 0; i < nbqueues; i++) {
        ret = (i == nbqueues - 1) ? snprintf(queues_format, 2, "%d", opt_queues[i])
                                  : snprintf(queues_format, 4, "%d, ", opt_queues[i]);
        queues_format += ret;
    }

    if (opt_shared_umem > 1) {
        if (opt_shared_umem > 8) {
            dlog_error("No more than 8 sockets are supported");
            goto cleanup;
        }

        if (nbqueues == 1 && !is_power_of_2(opt_shared_umem)) {
            dlog_error("Number of shared sockets per one queue should a power of 2");
            goto cleanup;
        }

        if (nbqueues != 1) {
            nbxsks = opt_shared_umem = nbqueues;
            dlog_info("Per-queue routing to XSK.");
        } else {
            dlog_info("Round robin routing to XSKs.");
            u32 qid = opt_queues[0];

            switch (nbxsks) {
            case 2:
                xdp_filename = XDP_FILE_RR2;
                break;
            case 4:
                xdp_filename = XDP_FILE_RR4;
                break;
            case 8:
                xdp_filename = XDP_FILE_RR8;
                break;
            }

            for (size_t i = 0; i < nbxsks; i++) {
                opt_queues[i] = qid;
            }

            dlog_infov("Working %d XSKs with shared UMEM on queue %s", nbqueues, queues);
        }
    } else {
        dlog_info("Per-queue routing to XSK.");
        dlog_infov("Working %d XSKs on queues: %s", nbqueues, queues);
    }

    if (opt_affinity && opt_pollmode == DQDK_RCV_RTC) {
        dlog_info_head("IRQ-to-Queue Mappings: ");
        for (size_t i = 0; i < nbirqs; i++) {
            if (i != nbirqs - 1) {
                dlog_info_print("%d-%d, ", opt_irqs[i], opt_queues[i]);
            } else {
                dlog_info_print("%d-%d", opt_irqs[i], opt_queues[i]);
            }
        }
        dlog_info_exit();
    }

    if ((ret = setrlimit(RLIMIT_MEMLOCK, &rlim))) {
        dlog_error2("setrlimit", ret);
        goto cleanup;
    }

    kern_prog = xdp_program__open_file(xdp_filename, NULL, NULL);
    ret = xdp_program__attach(kern_prog, ifindex, opt_mode, 0);
    if (ret) {
        dlog_error2("xdp_program__attach", ret);
        goto cleanup;
    }

    struct bpf_object* obj = xdp_program__bpf_obj(kern_prog);
    int mapfd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    if (IS_THREADED(opt_pollmode, nbqueues)) {
        xsk_workers = (pthread_t*)calloc(nbxsks, sizeof(pthread_t));
        ctxs = (struct benchmark_ctx*)calloc(nbxsks, sizeof(struct benchmark_ctx));
    }

    xsks = (xsk_info*)calloc(nbxsks, sizeof(xsk_info));
    xsk_worker_attrs = (pthread_attr_t*)calloc(nbxsks, sizeof(pthread_attr_t));
    if (opt_affinity) {
        cpusets = (cpu_set_t*)calloc(nbxsks, sizeof(cpu_set_t));
    }

    if (opt_shared_umem > 1) {
        shared_umem = nbqueues != 1 ? umem_info_create(nbxsks) : umem_info_create(1);
        umem_configure(shared_umem);
    }

    struct sigevent sigv;
    sigv.sigev_notify = SIGEV_SIGNAL;
    sigv.sigev_signo = SIGUSR1;
    timer_create(CLOCK_MONOTONIC, &sigv, &timer);
    timer_settime(timer, 0, &opt_duration, NULL);

    if (opt_irqstring != NULL) {
        before_interrupts = nic_get_interrupts(opt_irqstring, nprocs);
    }

    for (u32 i = 0; i < nbxsks; i++) {
        xsks[i].tx_pkt_size = opt_txpktsize;
        xsks[i].batch_size = opt_batchsize;
        xsks[i].busy_poll = opt_busy_poll;

        xsks[i].libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
        xsks[i].bind_flags = (opt_zcopy ? XDP_ZEROCOPY : XDP_COPY)
            | (opt_needs_wakeup ? XDP_USE_NEED_WAKEUP : 0);

        if (i != 0 && opt_shared_umem > 1) {
            xsks[i].bind_flags = XDP_SHARED_UMEM;
        }

        xsks[i].xdp_flags = 0;
        xsks[i].queue_id = opt_queues[i];
        xsks[i].index = i;

        if (opt_shared_umem > 1) {
            xsks[i].umem_info = shared_umem;
        } else {
            xsks[i].umem_info = umem_info_create(1);
            umem_configure(xsks[i].umem_info);
        }

        ret = xsk_configure(&xsks[i], opt_ifname);
        if (ret) {
            dlog_error2("xsk_configure", ret);
            goto cleanup;
        }

        if (opt_benchmark != BENCH_TX_ONLY) {
            if (opt_shared_umem > 1) {
                if (nbqueues == 1) {
                    if (i == 0) {
                        ret = fq_ring_configure(&xsks[i]);
                        if (ret) {
                            dlog_error2("fq_ring_configure", ret);
                            goto cleanup;
                        }
                    }
                } else {
                    ret = fq_ring_configure(&xsks[i]);
                    if (ret) {
                        dlog_error2("fq_ring_configure", ret);
                        goto cleanup;
                    }
                }
            } else {
                ret = fq_ring_configure(&xsks[i]);
                if (ret) {
                    dlog_error2("fq_ring_configure", ret);
                    goto cleanup;
                }
            }
        } else if (opt_shared_umem > 1) {
            if (i == 0) {
                pktgen_fill_umem(shared_umem, opt_dmac, smac, UMEM_LEN * nbqueues, opt_txpktsize);
            }
        } else {
            pktgen_fill_umem(xsks[i].umem_info, opt_dmac, smac, UMEM_LEN, opt_txpktsize);
        }

        u32 sockfd = xsk_socket__fd(xsks[i].socket);
        u32 mapkey = nbqueues == 1 && opt_shared_umem > 1 ? xsks[i].index
                                                          : xsks[i].queue_id;
        ret = bpf_map_update_elem(mapfd, &mapkey, &sockfd, BPF_ANY);
        if (ret) {
            dlog_error2("bpf_map_update_elem", ret);
            goto cleanup;
        }

        if (i == 0) {
            socklen = sizeof(struct xdp_options);
            ret = getsockopt(xsk_socket__fd(xsks[i].socket), SOL_XDP,
                XDP_OPTIONS, &xdp_opts, &socklen);
            if (ret) {
                dlog_error2("getsockopt(XDP_OPTIONS)", ret);
            } else if (xdp_opts.flags & XDP_OPTIONS_ZEROCOPY) {
                dlog_info("Zero copy is activated!");
            } else {
                dlog_info("Zero copy is NOT activated!");
            }
        }

        if (IS_THREADED(opt_pollmode, nbqueues)) {
            pthread_attr_t* attrs = opt_affinity ? &xsk_worker_attrs[i] : NULL;
            struct benchmark_ctx* ctx = &ctxs[i];
            ctx->xsks = &xsks[i];
            ctx->pollmode = opt_pollmode;
            ctx->nbxsks_per_thread = 1;
            ctx->shared_umem = opt_shared_umem;
            memcpy(ctx->smac, smac, 6);
            memcpy(ctx->dmac, opt_dmac, 6);

            if (opt_affinity) {
                pthread_attr_init(attrs);
                // Set process and interrupt affinity to same CPU
                int app_aff, irq_aff;
                // FIXME: this is incorrect logic. hyperthreads are necessarily contiguous.
                if (opt_hyperthreading) {
                    irq_aff = 2 * i;
                    app_aff = (2 * i) + 1;
                } else {
                    irq_aff = app_aff = i % nprocs;
                }

                nic_set_irq_affinity(opt_irqs[i], irq_aff);

                CPU_ZERO(&cpusets[i]);
                CPU_SET(app_aff, &cpusets[i]);
                ret = pthread_attr_setaffinity_np(attrs, sizeof(cpu_set_t), &cpusets[i]);
                if (ret) {
                    dlog_error2("pthread_attr_setaffinity_np", ret);
                }
            }

            pthread_create(&xsk_workers[i], attrs, opt_handler, (void*)ctx);
        }
    }

    if (!IS_THREADED(opt_pollmode, nbqueues)) {
        struct benchmark_ctx ctx = {
            .xsks = xsks,
            .pollmode = opt_pollmode,
            .nbxsks_per_thread = nbxsks,
            .shared_umem = opt_shared_umem,
        };
        memcpy(&ctx.smac, smac, 6);
        memcpy(&ctx.dmac, opt_dmac, 6);

        if (opt_affinity) {
            int app_aff, irq_aff;
            // FIXME: this is incorrect logic. hyperthreads are necessarily contiguous.
            if (opt_hyperthreading) {
                irq_aff = 0;
                app_aff = 1;
            } else {
                irq_aff = app_aff = 0;
            }
            nic_set_irq_affinity(opt_irqs[0], irq_aff);
            CPU_ZERO(&cpusets[0]);
            CPU_SET(app_aff, &cpusets[0]);
            sched_setaffinity(0, sizeof(cpu_set_t), &cpusets[0]);
        }

        opt_handler(&ctx);
    }

    struct xsk_stat avg_stats;
    memset(&avg_stats, 0, sizeof(avg_stats));
    for (u32 i = 0; i < nbxsks; i++) {
        if (IS_THREADED(opt_pollmode, nbqueues)) {
            pthread_join(xsk_workers[i], NULL);
        }

        xsk_stats_dump(&xsks[i]);
        avg_stats.runtime = MAX(avg_stats.runtime, xsks[i].stats.runtime);
        avg_stats.rcvd_pkts += xsks[i].stats.rcvd_pkts;
        avg_stats.rcvd_frames += xsks[i].stats.rcvd_frames;
        avg_stats.sent_frames += xsks[i].stats.sent_frames;

        avg_stats.fail_polls += xsks[i].stats.fail_polls;
        avg_stats.invalid_ip_pkts += xsks[i].stats.invalid_ip_pkts;
        avg_stats.invalid_udp_pkts += xsks[i].stats.invalid_udp_pkts;
        avg_stats.rx_empty_polls += xsks[i].stats.rx_empty_polls;
        avg_stats.rx_fill_fail_polls += xsks[i].stats.rx_fill_fail_polls;
        avg_stats.timeout_polls += xsks[i].stats.timeout_polls;
        avg_stats.tx_wakeup_sendtos += xsks[i].stats.tx_wakeup_sendtos;
        avg_stats.rx_successful_fills += xsks[i].stats.rx_successful_fills;
        avg_stats.tx_successful_fills += xsks[i].stats.tx_successful_fills;

        avg_stats.xstats.rx_dropped += xsks[i].stats.xstats.rx_dropped;
        avg_stats.xstats.rx_invalid_descs += xsks[i].stats.xstats.rx_invalid_descs;
        avg_stats.xstats.tx_invalid_descs += xsks[i].stats.xstats.tx_invalid_descs;
        avg_stats.xstats.rx_ring_full += xsks[i].stats.xstats.rx_ring_full;
        avg_stats.xstats.rx_fill_ring_empty_descs += xsks[i].stats.xstats.rx_fill_ring_empty_descs;
        avg_stats.xstats.tx_ring_empty_descs += xsks[i].stats.xstats.tx_ring_empty_descs;
    }

    if (opt_irqstring != NULL) {
        after_interrupts = nic_get_interrupts(opt_irqstring, nprocs);
    }

    if (nbxsks != 1) {
        printf("Average Stats:\n");
        stats_dump(&avg_stats);
    }
cleanup:
    if (after_interrupts != NULL && before_interrupts != NULL) {
        u32 sum = 0;
        dlog_info_head("IRQ Interrupts: ");
        for (u32 i = 0; i < after_interrupts->nbirqs; i++) {
            irq_interrupts_t* intr_before = &before_interrupts->interrupts[i];
            irq_interrupts_t* intr_after = &after_interrupts->interrupts[i];

            if (intr_before->irq != intr_after->irq) {
                dlog_errorv("Incorrect IRQs: %d-%d", intr_before->irq, intr_after->irq);
                continue;
            }

            int intrs = intr_after->interrupts - intr_before->interrupts;
            dlog_info_print("%d: %d - ", intr_after->irq, intrs);
            sum += intrs;
        }

        dlog_info_print("Total: %d", sum);
        dlog_info_exit();

        free(before_interrupts->interrupts);
        free(after_interrupts->interrupts);
        free(before_interrupts);
        free(after_interrupts);
    }

    timer_delete(timer);
    xdp_program__detach(kern_prog, ifindex, opt_mode, 0);
    xdp_program__close(kern_prog);

    if (xsks != NULL) {
        for (size_t i = 0; i < nbxsks; i++) {
            xsk_info xsk = xsks[i];
            xsk_socket__delete(xsk.socket);

            if (xsk.umem_info != NULL) {
                if (xsk.umem_info->nbfqs != 1) {
                    free(xsk.fill_ring);
                    free(xsk.comp_ring);
                }

                if (!opt_shared_umem) {
                    umem_info_free(xsk.umem_info);
                    free(xsk.umem_info);
                }
            }
        }
        free(xsks);

        if (xsk_workers != NULL) {
            free(xsk_workers);
        }
    }

    if (xsk_worker_attrs != NULL) {
        for (size_t i = 0; i < nbxsks; i++) {
            pthread_attr_destroy(&xsk_worker_attrs[i]);
        }

        free(xsk_worker_attrs);
    }

    if (ctxs != NULL) {
        free(ctxs);
    }

    if (cpusets != NULL) {
        free(cpusets);
    }

    if (shared_umem != NULL) {
        umem_info_free(shared_umem);

        if (shared_umem != NULL) {
            free(shared_umem);
        }
    }
#ifdef NO_HGPG
    set_hugepages(0);
#endif
}
