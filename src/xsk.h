#ifndef DQDK_ADAPTER_XDP_H
#define DQDK_ADAPTER_XDP_H

#include <xdp/libxdp.h>
#include <xdp/xsk.h>
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
#include <sys/ioctl.h>
#include <stdlib.h>

#include "tcpip/inet_csum.h"
#include "tcpip/ipv4.h"
#include "tcpip/udp.h"
#include "tcpip/icmp4.h"
#include "dqdk.h"
#include "dlog.h"

struct xdp_opts {
    const char* ifname;
    int ifindex;
    enum xdp_attach_mode mode;
    u8 zcopy;
    u8 verbose;
    u8 need_wakeup;
    u8 udp_mode;
    u32 queue_id;
    u32 queue_size;
    u32 batch_size;
    // int expected_pps;
};

struct xsk_stat {
    u64 rcvd_pkts;
    u64 rcvd_udps;
    u64 fill_fail_polls;
    u64 invalid_ip_pkts;
    u64 invalid_udp_pkts;
};

typedef struct {
    struct xsk_socket* socket;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    struct xsk_umem* umem;
    struct xsk_ring_prod fillq;
    struct xsk_ring_cons compq;
    u32 umem_chunk_size;
    u64 umem_total_size;
    void* buffer;
    u32 libbpf_flags;
    u32 xdp_flags;
    u16 bind_flags;
    struct xdp_program* xdp_program;
    struct xdp_opts opts;
    struct xsk_stat stats;
} xsk_t;

#define FILLQ_LEN XSK_RING_PROD__DEFAULT_NUM_DESCS * 2
#define COMPQ_LEN XSK_RING_CONS__DEFAULT_NUM_DESCS
#define UMEM_LEN FILLQ_LEN

#define XDP_UMEM_MIN_CHUNK_SIZE 2048

#define CHUNK_SIZE(mtu) (mtu < XDP_UMEM_MIN_CHUNK_SIZE ? XDP_UMEM_MIN_CHUNK_SIZE : XSK_UMEM__DEFAULT_FRAME_SIZE)

static int get_if_mtu(const char* ifname)
{
    struct ifreq req;
    int ret;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    req.ifr_addr.sa_family = AF_INET;
    memcpy(&req.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(fd, SIOCGIFMTU, &req);
    if (ret) {
        dlog_error2("ioctl", ret);
    }
    close(fd);
    return req.ifr_mtu + sizeof(struct ethhdr);
}

static int xsk_configure(xsk_t* xsk)
{
    struct bpf_object* obj = NULL;
    int ret = 0, mapfd, fd;
    // int sock_opt;
    u32 idx_fq;

    const struct xsk_umem_config cfg = {
        .fill_size = FILLQ_LEN,
        .comp_size = COMPQ_LEN,
        .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    ret = xsk_umem__create(&xsk->umem, xsk->buffer, xsk->umem_total_size,
        &xsk->fillq, &xsk->compq, &cfg);
    if (ret) {
        return ret;
    }

    // push all frames to fill ring
    ret = xsk_ring_prod__reserve(&xsk->fillq, cfg.fill_size, &idx_fq);
    if (ret != (int)cfg.fill_size) {
        return -EIO;
    }

    // fill addresses
    for (u32 i = 0; i < cfg.fill_size; i++) {
        *xsk_ring_prod__fill_addr(&xsk->fillq, idx_fq++) = i * xsk->umem_chunk_size;
    }

    xsk_ring_prod__submit(&xsk->fillq, cfg.fill_size);

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

    fd = xsk_socket__fd(xsk->socket);
    obj = xdp_program__bpf_obj(xsk->xdp_program);
    mapfd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    dlog("Map FD: %d\n", mapfd);
    ret = bpf_map_update_elem(mapfd, &xsk->opts.queue_id, &fd, BPF_NOEXIST);
    dlog_error2("bpf_map_update_elem", ret);

    // sock_opt = 1;
    // ret = setsockopt(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, (void*)&sock_opt,
    //     sizeof(sock_opt));
    // if (ret < 0) {
    //     return ret;
    // }

    // sock_opt = 20;
    // ret = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, (void*)&sock_opt,
    //     sizeof(sock_opt));
    // if (ret < 0) {
    //     return ret;
    // }

    // sock_opt = xsk->opts.batch_size;
    // ret = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, (void*)&sock_opt,
    //     sizeof(sock_opt));
    // if (ret < 0) {
    //     return ret;
    // }

    return 0;
}

always_inline u8* process_frame(xsk_t* xsk, u8* buffer, u32 len)
{
    struct ethhdr* frame = (struct ethhdr*)buffer;
    struct iphdr* packet = (struct iphdr*)(frame + 1);
    int ethertype = ntohs(frame->h_proto);

    if (ethertype != ETH_P_IP) {
        return NULL;
    }

    if (packet->version != 4) {
        return NULL;
    }

    if (!ip4_audit(packet, len - sizeof(struct ethhdr))) {
        xsk->stats.invalid_ip_pkts++;
        return NULL;
    }

    if (xsk->opts.udp_mode) {
        switch (packet->protocol) {
        case IPPROTO_UDP:
            struct udphdr* udp = (struct udphdr*)(((u8*)packet) + ip4_get_header_size(packet));
            u32 udplen = ntohs(packet->tot_len) - ip4_get_header_size(packet);
            if (!udp_audit(udp, udplen)) {
                xsk->stats.invalid_udp_pkts++;
                return NULL;
            }
            xsk->stats.rcvd_udps += 1;
            return (u8*)(udp + 1);
        default:
            dlog_errorv("Unsupported IP Protocol: %d", packet->protocol);
            return NULL;
        }
    }

    return NULL;
}

int verbose_print(enum libbpf_print_level level,
    const char* format, va_list ap)
{
    (void)level;
    return vfprintf(stderr, format, ap);
}

xsk_t* xsk_init(struct xdp_opts* xopts)
{
    if (xopts->verbose) {
        libbpf_set_print(verbose_print);
    }

    xsk_t* xsk = (xsk_t*)calloc(1, sizeof(xsk_t));
    xsk->opts = *xopts;
    int mtu = get_if_mtu(xsk->opts.ifname);
    dlog("Interface Name: %s, Interface MTU: %d\n", xsk->opts.ifname, mtu);
    xsk->umem_chunk_size = CHUNK_SIZE(mtu);
    xsk->umem_total_size = xsk->umem_chunk_size * UMEM_LEN;
    xsk->buffer = huge_malloc(xsk->umem_total_size);

    if (xopts->need_wakeup) {
        xsk->bind_flags |= XDP_USE_NEED_WAKEUP;
    }

    xsk->bind_flags |= xopts->zcopy ? XDP_ZEROCOPY : XDP_COPY;
    xsk->libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;

    return xsk;
}

int xsk_open(xsk_t* xsk)
{
    int ret = 0;

    if (xsk->buffer == NULL) {
        return -1;
    }

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if ((ret = setrlimit(RLIMIT_MEMLOCK, &rlim))) {
        dlog_error2("setrlimit", ret);
        return ret;
    }

    xsk->xdp_program = xdp_program__open_file("./bpf/xsk.bpf.o", NULL, NULL);
    ret = xdp_program__attach(xsk->xdp_program, xsk->opts.ifindex, xsk->opts.mode, 0);
    if (ret) {
        dlog_error2("xdp_program__attach", ret);
        return ret;
    }

    ret = xsk_configure(xsk);
    if (ret) {
        dlog_error2("xsk_configure", ret);
        return ret;
    }

    return ret;
}

always_inline int xsk_ip4(xsk_t* xsk, u8* buffer)
{
    u32 idx_rx = 0, idx_fq = 0;
    int ret, rcvd;
    u32 payload_size;

    rcvd = xsk_ring_cons__peek(&xsk->rx, xsk->opts.batch_size, &idx_rx);
    if (!rcvd) {
        return -ECOMM;
    }

    while (ret != rcvd) {
        if (ret < 0)
            return ret;
        if (xsk_ring_prod__needs_wakeup(&xsk->fillq)) {
            xsk->stats.fill_fail_polls++;
            recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }
        ret = xsk_ring_prod__reserve(&xsk->fillq, rcvd, &idx_fq);
    }

    xsk->stats.rcvd_pkts += rcvd;
    for (int i = 0; i < rcvd; i++) {
        u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
        // u64 orig = xsk_umem__extract_addr(addr);

        // addr = xsk_umem__add_offset_to_addr(addr);

        u8* frame = xsk_umem__get_data(xsk->buffer, addr);
        payload_size = udp_get_payload_size(frame, len);

        u8* data = process_frame(xsk, frame, len);
        if (data != NULL) {
            // simulate processing
            memcpy(buffer, data, payload_size);
        }

        idx_rx++;
        idx_fq++;
    }

    xsk_ring_prod__submit(&xsk->fillq, rcvd);
    xsk_ring_cons__release(&xsk->rx, rcvd);
    return rcvd;
}

always_inline int xsk_write(xsk_t* xsk, u8* buffer, u32 size)
{
    (void)xsk;
    (void)buffer;
    (void)size;
    return 0;
}

int xsk_cleanup(xsk_t* xsk)
{
    if (xsk != NULL) {
        xdp_program__detach(xsk->xdp_program, xsk->opts.ifindex, xsk->opts.mode, 0);
        xdp_program__close(xsk->xdp_program);

        if (xsk->buffer != NULL) {
            munmap(xsk->buffer, xsk->umem_total_size);
        }

        if (xsk->umem != NULL) {
            xsk_umem__delete(xsk->umem);
        }

        if (xsk->socket != NULL) {
            xsk_socket__delete(xsk->socket);
        }

        free(xsk);
        return 0;
    }
    return 1;
}

#endif
