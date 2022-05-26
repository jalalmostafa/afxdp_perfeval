#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <math.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "tcpip/inet_csum.h"
#include "tcpip/ipv4.h"
#include "tcpip/udp.h"
#include "datatypes.h"
#include "dlog.h"
#include "drivers/xdp.h"
#include "dqdk.h"

#define BATCH_SIZE 1000
#define FILLQ_LEN XSK_RING_PROD__DEFAULT_NUM_DESCS * 2
#define COMPQ_LEN XSK_RING_CONS__DEFAULT_NUM_DESCS

typedef struct {
    struct xsk_socket* socket;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    struct xsk_umem* umem;
    struct xsk_ring_prod fillq;
    struct xsk_ring_cons compq;
    void* buffer;
    u32 libbpf_flags;
    u32 xdp_flags;
    u16 bind_flags;
    struct xdp_program* xdp_program;
    struct xdp_opts opts;
} xsk_private_t;

static void* umem_buffer_create(u64 size)
{
    return mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
}

/*
    bind flags:
    XDP_USE_NEED_WAKEUP
 */
static int xsk_configure(xsk_private_t* xsk)
{
    int ret = 0;
    u32 xdp_prog = -1, idx;

    xsk->libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    xsk->xdp_flags = 0;
    xsk->bind_flags = 0;

    const struct xsk_umem_config cfg = {
        .fill_size = FILLQ_LEN,
        .comp_size = COMPQ_LEN,
        .frame_size = xsk->opts.mtu,
        .frame_headroom = 0,
        .flags = 0
    };

    xsk->buffer = umem_buffer_create(xsk->opts.hugetable_size);
    ret = xsk_umem__create(&xsk->umem, xsk->buffer, xsk->opts.hugetable_size,
        &xsk->fillq, &xsk->compq, &cfg);
    if (ret) {
        return ret;
    }

    // push all frames to fill ring
    ret = xsk_ring_prod__reserve(&xsk->fillq, FILLQ_LEN, &idx);
    if (ret != FILLQ_LEN) {
        return -EIO;
    }

    // fill addresses
    for (int i = 0; i < FILLQ_LEN; i++) {
        *xsk_ring_prod__fill_addr(&xsk->fillq, idx++) = i * xsk->opts.mtu;
    }

    xsk_ring_prod__submit(&xsk->fillq, FILLQ_LEN);
    const struct xsk_socket_config xsk_config = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .bind_flags = xsk->bind_flags,
        .libbpf_flags = xsk->libbpf_flags,
        .xdp_flags = xsk->xdp_flags
    };

    ret = xsk_socket__create(&xsk->socket, xsk->opts.ifname, xsk->opts.queue_id,
        xsk->umem, &xsk->rx, &xsk->tx, &xsk_config);
    if (ret) {
        return ret;
    }

    return 0;
}

u8* process_frame(__u8* buffer, __u32 len)
{
    struct ethhdr* frame = (struct ethhdr*)buffer;
    int ethertype = ntohs(frame->h_proto);

    if (ethertype != ETH_P_IP) {
        return NULL;
    }

    struct iphdr* packet = (struct iphdr*)(frame + 1);
    if (packet->version != 4) {
        return NULL;
    }

    switch (packet->protocol) {
    case IPPROTO_ICMP:
        struct icmphdr* icmp = (struct icmphdr*)(packet + 1);
        if (icmp->type != ICMP_ECHO) {
            return NULL;
        }

        return construct_pong(frame, len);
    case IPPROTO_UDP:
        break;
    default:
        return NULL;
    }
}

int xdp_pingpong(xsk_private_t* xsk)
{
    u32 idx_rx = 0, idx_tx = 0, idx_fq = 0, idx_cq = 0;
    int ret, rcvd;

    rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        return -ECOMM;
    }

    // best effort: free as much as you can
    ret = xsk_prod_nb_free(&xsk->fillq, rcvd);
    ret = xsk_ring_prod__reserve(&xsk->fillq, ret, &idx_fq);
    if (ret < 0) {
        return ret;
    }

    // while (ret != rcvd) {
    //     if (ret < 0) {
    //         return -ret;
    //     }

    //     ret = xsk_ring_prod__reserve(&umem->fillq, rcvd, &idx_fq);
    // }

    ret = xsk_ring_cons__peek(&xsk->compq, BATCH_SIZE, &idx_cq);
    if (ret > 0) {
        xsk_ring_cons__release(&xsk->compq, rcvd);
        for (int i = 0; i < ret; i++)
            *xsk_ring_prod__fill_addr(&xsk->fillq, idx_fq++) = *xsk_ring_cons__comp_addr(&xsk->compq, idx_cq++);
        xsk_ring_prod__submit(&xsk->fillq, rcvd);
    }

    ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
    if (ret < 0) {
        return ret;
    }

    // while (ret != rcvd) {
    //     if (ret < 0) {
    //         return -ret;
    //     }
    //     // TODO: empty completion ring!!!
    //     ret = xsk_ring_prod__reserve(&xsk->tx, rcvd, &idx_tx);
    // }

    for (int i = 0; i < rcvd; i++) {
        __u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        __u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
        __u64 orig = xsk_umem__extract_addr(addr);

        addr = xsk_umem__add_offset_to_addr(addr);

        __u8* frame = xsk_umem__get_data(xsk->buffer, addr);

        __u8* pong = process_frame(frame, len);

        if (pong != NULL) {
            memcpy(frame, pong, xsk->opts.mtu);

            xsk_ring_prod__tx_desc(&xsk->tx, idx_tx)->addr = orig;
            xsk_ring_prod__tx_desc(&xsk->tx, idx_tx)->len = len;
            idx_tx++;
        }
        idx_rx++;
        idx_fq++;
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk_ring_prod__submit(&xsk->tx, rcvd);
    return 0;
}

int verbose_print(enum libbpf_print_level level,
    const char* format, va_list ap)
{
    (void)level;
    return vfprintf(stderr, format, ap);
}

int xdp_open(struct dqdk_ctx* ctx, void* opts)
{
    struct xdp_opts* xopts = (struct xdp_opts*)opts;
    int ret = 0, mapfd;
    struct bpf_object* obj = NULL;

#ifdef DEBUG
    if (xopts->verbose) {
        libbpf_set_print(verbose_print);
    }
#endif

    if (xopts->ifname == NULL) {
        return -EINVAL;
    }

    xsk_private_t* xsk = (xsk_private_t*)calloc(1, sizeof(xsk_private_t));
    xsk->opts = *xopts;

    xopts->ifindex = if_nametoindex(xopts->ifname);

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (ret = setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        dlog_error("setrlimit", ret);
        return ret;
    }

    xsk->xdp_program = xdp_program__open_file("udpfilter.bpf.o", NULL, NULL);
    ret = xdp_program__attach(xsk->xdp_program, xopts->ifindex, xopts->mode, 0);
    if (ret) {
        dlog_error("xdp_program__attach", ret);
        return ret;
    }

    ret = xsk_configure(xsk);
    if (ret) {
        dlog_error("xsk_configure", ret);
        return ret;
    }

    obj = xdp_program__bpf_obj(xsk->xdp_program);
    mapfd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    ret = xsk_socket__update_xskmap(xsk->socket, mapfd);

    return ret;
}

inline int xdp_pollv(struct dqdk_ctx* ctx, u8* buffer, u32 size, u32 timeout)
{
    xsk_private_t* xsk = (xsk_private_t*)ctx->private;
    u32 idx_rx = 0, idx_fq = 0;
    int ret, rcvd;
    u32 payload_size;

    rcvd = xsk_ring_cons__peek(&xsk->rx, size, &idx_rx);
    if (!rcvd) {
        return -ECOMM;
    }

    while (ret != rcvd) {
        if (ret < 0)
            return ret;
        // if (opt_busy_poll || xsk_ring_prod__needs_wakeup(&xsk->umem->fq)) {
        //     xsk->app_stats.fill_fail_polls++;
        //     recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        // }
        ret = xsk_ring_prod__reserve(&xsk->fillq, rcvd, &idx_fq);
    }

    ret = xsk_ring_prod__reserve(&xsk->fillq, rcvd, &idx_fq);
    if (ret < 0) {
        return ret;
    }

    for (int i = 0; i < rcvd; i++) {
        u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
        u64 orig = xsk_umem__extract_addr(addr);

        addr = xsk_umem__add_offset_to_addr(addr);

        u8* frame = xsk_umem__get_data(xsk->buffer, addr);
        payload_size = get_udp_payload_size(frame, len);
        // if (payload_size != ctx->opts.payload_size) {
        //     dlog("xdp_pollv: unexpected data size: got %d, expected: %s\n", payload_size, ctx->opts.payload_size);
        // }

        u8* data = udp_extract_frame_data(frame, len);

        if (data != NULL) {
            memcpy(buffer, data, ctx->opts.payload_size);
            buffer += payload_size;
        }
        idx_rx++;
        idx_fq++;
    }

    xsk_ring_prod__submit(&xsk->fillq, rcvd);
    xsk_ring_cons__release(&xsk->rx, rcvd);
    return rcvd;
}

int xdp_writev(struct dqdk_ctx* ctx, u8* buffer, u32 size)
{
}

int xdp_cleanup(struct dqdk_ctx* ctx)
{
    xsk_private_t* private = (xsk_private_t*)ctx->private;

    if (private != NULL) {
        xdp_program__detach(private->xdp_program, private->opts.ifindex, private->opts.mode, 0);
        xdp_program__close(private->xdp_program);

        if (private->buffer != NULL) {
            munmap(private->buffer, private->opts.hugetable_size);
        }

        if (private->umem != NULL) {
            xsk_umem__delete(private->umem);
        }

        if (private->socket != NULL) {
            xsk_socket__delete(private->socket);
        }

        free(private);
    }

    ctx->private = NULL;
}
