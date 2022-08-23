// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
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
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <time.h>

#include "dqdk.h"
#include "tcpip/ipv4.h"
#include "tcpip/udp.h"

#define UMEM_LEN (1024 * 4)
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

#define MAX_SOCKS 4
#define UMEM_SIZE (UMEM_LEN * FRAME_SIZE)
#define FILLQ_LEN (XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
#define COMPQ_LEN XSK_RING_CONS__DEFAULT_NUM_DESCS

struct xsk_stat {
    u64 rcvd_frames;
    u64 rcvd_pkts;
    u64 fail_polls;
    u64 timeout_polls;
    u64 rx_empty_polls;
    u64 rx_fill_fail_polls;
    u64 invalid_ip_pkts;
    u64 invalid_udp_pkts;
    u64 runtime;
    struct xdp_statistics xstats;
};

typedef struct {
    struct xsk_umem* umem;
    struct xsk_ring_prod* fill_ring;
    struct xsk_ring_cons* comp_ring;
    u32 count;
    void* buffer;
} umem_info;

typedef struct {
    u32 index;
    u32 queue_id;
    struct xsk_socket* socket;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    umem_info* umem_info;
    u32 libbpf_flags;
    u32 xdp_flags;
    u16 bind_flags;
    u32 batch_size;
    struct xsk_stat stats;
} xsk_info;

u32 break_flag = 0;

static void* umem_buffer_create()
{
    // return mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
    //     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return huge_malloc(UMEM_SIZE);
}

static umem_info* umem_info_create(u32 count)
{
    printf("umem_info_create: nbfillqueues: %d\n", count);

    umem_info* info = (umem_info*)calloc(1, sizeof(umem_info));

    info->buffer = umem_buffer_create();
    if (info->buffer == NULL) {
        dlog_error2("umem_buffer_create", 0);
        return NULL;
    }

    info->umem = NULL;
    info->count = count;
    info->comp_ring = (struct xsk_ring_cons*)calloc(info->count, sizeof(struct xsk_ring_cons));
    info->fill_ring = (struct xsk_ring_prod*)calloc(info->count, sizeof(struct xsk_ring_prod));
    return info;
}

static void umem_info_free(umem_info* info)
{
    if (info != NULL) {
        munmap(info->buffer, UMEM_SIZE);
        free(info->fill_ring);
        free(info->comp_ring);
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
        .flags = 0 // XDP_UMEM_UNALIGNED_CHUNK_FLAG
    };

    ret = xsk_umem__create(&umem->umem, umem->buffer, UMEM_SIZE,
        &umem->fill_ring[0], &umem->comp_ring[0], &cfg);
    if (ret) {
        dlog_error2("xsk_umem__create", ret);
        return ret;
    }

    // push all frames to fill ring
    u32 idx;
    ret = xsk_ring_prod__reserve(&umem->fill_ring[0], FILLQ_LEN, &idx);
    if (ret != FILLQ_LEN) {
        dlog_error2("xsk_ring_prod__reserve", ret);
        return EIO;
    }

    // fill addresses
    for (int i = 0; i < FILLQ_LEN; i++) {
        *xsk_ring_prod__fill_addr(&umem->fill_ring[0], idx++) = i * FRAME_SIZE;
    }

    xsk_ring_prod__submit(&umem->fill_ring[0], FILLQ_LEN);
    return 0;
}

static int xsk_configure(xsk_info* xsk, const char* ifname)
{
    int ret = 0;
    u32 nbxsks = xsk->umem_info->count;
    printf("xsk_configure: nbxsks: %d\n", nbxsks);
    const struct xsk_socket_config xsk_config = {
        .rx_size = FILLQ_LEN,
        .tx_size = COMPQ_LEN,
        .bind_flags = xsk->bind_flags,
        .libbpf_flags = xsk->libbpf_flags,
        .xdp_flags = xsk->xdp_flags
    };

    struct xsk_ring_prod* fq = nbxsks == 1 ? xsk->umem_info->fill_ring
                                           : &xsk->umem_info->fill_ring[xsk->index];
    struct xsk_ring_cons* cq = nbxsks == 1 ? xsk->umem_info->comp_ring
                                           : &xsk->umem_info->comp_ring[xsk->index];

    ret = xsk_socket__create_shared(&xsk->socket, ifname, xsk->queue_id,
        xsk->umem_info->umem, &xsk->rx, NULL, fq, cq, &xsk_config);
    if (ret) {
        dlog_error2("xsk_socket__create", ret);
        return ret;
    }

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

    return 0;
}

void log_pingpong(struct iphdr* packet)
{
    __u32 saddr = ntohl(packet->saddr);
    __u32 daddr = ntohl(packet->daddr);
    dlog("[PING]: %i.%i.%i.%i is pinging %i.%i.%i.%i\n", (saddr >> 24) & 0xFF,
        (saddr >> 16) & 0xFF, (saddr >> 8) & 0xFF, saddr & 0xFF,
        (daddr >> 24) & 0xFF, (daddr >> 16) & 0xFF, (daddr >> 8) & 0xFF,
        daddr & 0xFF);
}

void log_frame(struct ethhdr* frame)
{
    int ethertype = ntohs(frame->h_proto);
    dlog("[SRC MAC] %02X:%02X:%02X:%02X:%02X:%02X - [DST MAC] %02X:%02X:%02X:%02X:%02X:%02X - [PROTO] 0x%04X\n",
        frame->h_source[0], frame->h_source[1], frame->h_source[2], frame->h_source[3], frame->h_source[4], frame->h_source[5],
        frame->h_dest[0], frame->h_dest[1], frame->h_dest[2], frame->h_dest[3], frame->h_dest[4], frame->h_dest[5], ethertype);
}

struct reply {
    struct icmphdr hdr;
    u8 buffer[56];
};

u8 pong_reply[FRAME_SIZE];

u8* construct_pong(struct ethhdr* frame, u32 len)
{
    struct iphdr* packet = (struct iphdr*)(frame + 1);
    struct icmphdr* icmp = (struct icmphdr*)(packet + 1);
    u8* data = (u8*)(icmp + 1);

    int datalen = len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct icmphdr);

    memset(pong_reply, 0, FRAME_SIZE);
    int icmplen = sizeof(struct icmphdr) + datalen;

    struct icmphdr* pong = (struct icmphdr*)(pong_reply + sizeof(struct ethhdr) + sizeof(struct iphdr));
    pong->type = ICMP_ECHOREPLY;
    pong->code = 0;
    pong->checksum = 0;
    pong->un.echo.id = icmp->un.echo.id;
    pong->un.echo.sequence = icmp->un.echo.sequence;
    memcpy((void*)(pong + 1), data, datalen);
    pong->checksum = ip_fast_csum(pong, 2 + ceil(datalen / 4));

    struct iphdr* pong_packet = (struct iphdr*)(pong_reply + sizeof(struct ethhdr));
    pong_packet->daddr = packet->saddr;
    pong_packet->saddr = packet->daddr;
    pong_packet->protocol = IPPROTO_ICMP;
    pong_packet->ihl = 5;
    pong_packet->version = 4;
    pong_packet->ttl = 64;

    int pktlen = sizeof(struct iphdr) + icmplen;
    pong_packet->tot_len = htons(pktlen);
    pong_packet->tos = packet->tos;
    pong_packet->check = ip_fast_csum(pong_packet, pong_packet->ihl);

    struct ethhdr* pong_frame = (struct ethhdr*)pong_reply;
    memcpy(pong_frame->h_dest, frame->h_source, ETH_ALEN);
    memcpy(pong_frame->h_source, frame->h_dest, ETH_ALEN);
    pong_frame->h_proto = frame->h_proto;

    return pong_reply;
}

void log_icmp(u8* frame)
{
    struct ethhdr* framehdr = (struct ethhdr*)frame;
    struct iphdr* packet = (struct iphdr*)(((struct ethhdr*)framehdr) + 1);
    log_frame(framehdr);
    log_pingpong(packet);
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

    struct udphdr* udp = (struct udphdr*)(((u8*)packet) + ip4_get_header_size(packet));
    u32 udplen = ntohs(packet->tot_len) - ip4_get_header_size(packet);
    if (!udp_audit(udp, packet->saddr, packet->daddr, udplen)) {
        xsk->stats.invalid_udp_pkts++;
        return NULL;
    }
    return (u8*)(udp + 1);
}

always_inline int xdp_udpip(xsk_info* xsk, umem_info* umem)
{
    u32 idx_rx = 0, idx_fq = 0;
    struct xsk_ring_prod* fq = umem->count == 1 ? umem->fill_ring : &umem->fill_ring[xsk->index];

    int rcvd = xsk_ring_cons__peek(&xsk->rx, xsk->batch_size, &idx_rx);

    if (!rcvd) {
        if (xsk_ring_prod__needs_wakeup(fq)) {
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

        if (xsk_ring_prod__needs_wakeup(fq)) {
            xsk->stats.rx_fill_fail_polls++;
            recvfrom(xsk_socket__fd(xsk->socket), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }

        ret = xsk_ring_prod__reserve(fq, rcvd, &idx_fq);
    }

    for (int i = 0; i < rcvd; i++) {
        u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        addr = xsk_umem__add_offset_to_addr(addr);
        // u64 orig = xsk_umem__extract_addr(addr);

#ifndef RX_DROP
        u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
        u8* frame = xsk_umem__get_data(umem->buffer, addr);

        u8* data = process_frame(xsk, frame, len);
        (void)data;
#else
        xsk_umem__get_data(umem->buffer, addr);
#endif
        idx_rx++;
        idx_fq++;
    }

#ifdef RX_DROP
    xsk->stats.rcvd_frames += rcvd;
#endif

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk_ring_prod__submit(fq, rcvd);
    return 0;
}

struct rx_ctx {
    xsk_info* xsks;
    u32 count;
    u8 pollmode;
    u8 bench_mode;
    u8 shared_umem;
};

#define POLL_TIMEOUT 1000
void* poll_rx(void* rxctx_ptr)
{
    struct rx_ctx* ctx = (struct rx_ctx*)rxctx_ptr;
    xsk_info* xsks = ctx->xsks;
    u64 t0, t1;

    switch (ctx->pollmode) {
    case DQDK_PM_POLL:
        struct pollfd* fds = (struct pollfd*)calloc(ctx->count, sizeof(struct pollfd));

        for (size_t i = 0; i < ctx->count; i++) {
            fds[i].fd = xsk_socket__fd(xsks[i].socket);
            fds[i].events = POLLIN;
        }

        t0 = clock_nsecs();
        while (!break_flag) {
            int ret = poll(fds, ctx->count, POLL_TIMEOUT);
            if (ret < 0) {
                dlog_error2("poll", ret);
                // xsk->stats.fail_polls++;
                continue;
            } else if (ret == 0) {
                dlog_info("[Poll] Timeout");
                // xsk->stats.timeout_polls++;
                continue;
            } else {
                for (size_t i = 0; i < ctx->count; i++) {
                    xdp_udpip(&xsks[i], xsks[i].umem_info);
                }
            }
        }
        t1 = clock_nsecs();
        free(fds);
        break;
    case DQDK_PM_RTC:
        t0 = clock_nsecs();
        while (!break_flag) {
            for (size_t i = 0; i < ctx->count; i++) {
                xdp_udpip(&xsks[i], xsks[i].umem_info);
            }
        }
        t1 = clock_nsecs();
        break;
    }

    socklen_t socklen = sizeof(struct xdp_statistics);
    for (size_t i = 0; i < ctx->count; i++) {
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
    printf("    Total runtime (ns):     %llu\n"
           "    Received Frames:        %llu\n"
           "    Average FPS:            %f\n"
           "    Received Packets:       %llu\n"
           "    Average PPS:            %f\n"
           "    Invalid L3 Packets:     %llu\n"
           "    Invalid L4 Packets:     %llu\n"
           "    Failed Polls:           %llu\n"
           "    Timeout Polls:          %llu\n"
           "    XSK Fill Fail Polls:    %llu\n"
           "    XSK RXQ Empty:          %llu\n"
           "    XSK RX Dropped:         %llu\n"
           "    XSK RX FillQ Empty:     %llu\n"
           "    XSK RX Invalid Descs:   %llu\n"
           "    XSK RX Ring Full:       %llu\n"
           "    XSK TX Invalid Descs:   %llu\n"
           "    XSK TX Ring Empty:      %llu\n",
        stats->runtime, stats->rcvd_frames,
        AVG_PPS(stats->rcvd_frames, stats->runtime), stats->rcvd_pkts,
        AVG_PPS(stats->rcvd_pkts, stats->runtime), stats->invalid_ip_pkts,
        stats->invalid_udp_pkts, stats->fail_polls, stats->timeout_polls,
        stats->rx_fill_fail_polls, stats->rx_empty_polls,
        stats->xstats.rx_dropped, stats->xstats.rx_fill_ring_empty_descs,
        stats->xstats.rx_invalid_descs, stats->xstats.rx_ring_full,
        stats->xstats.tx_invalid_descs, stats->xstats.tx_ring_empty_descs);
}

void xsk_stats_dump(xsk_info* xsk)
{
    printf("XSK %u on Queue %u Statistics:\n", xsk->index, xsk->queue_id);
    stats_dump(&xsk->stats);
}

#define XDP_FILE_XSK "./bpf/xsk.bpf.o"
#define XDP_FILE_RR2 "./bpf/rr2.bpf.o"
#define XDP_FILE_RR3 "./bpf/rr3.bpf.o"
#define XDP_FILE_RR4 "./bpf/rr4.bpf.o"

int main(int argc, char** argv)
{
    timer_t timer;
    int ifindex, ret, opt;
    char* opt_ifname = NULL;
    enum xdp_attach_mode opt_mode = XDP_MODE_NATIVE;
    u32 opt_batchsize = 64, opt_queues[MAX_SOCKS] = { -1 }, opt_shared_umem = 0;
    struct itimerspec opt_duration;
    u8 opt_needs_wakeup = 0, opt_verbose = 0, opt_zcopy = 1,
       opt_transportmode = IPPROTO_UDP, opt_pollmode = DQDK_PM_POLL;

    struct xdp_options xdp_opts;
    socklen_t socklen;
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    u32 nbqueues = 0;
    char* xdp_filename = XDP_FILE_XSK;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGUSR1, signal_handler);

    while ((opt = getopt(argc, argv, "b:cd:i:l:m:p:q:s:vw")) != -1) {
        switch (opt) {
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
                if (delimiter != NULL) {
                    end = strtol(++delimiter, &delimiter, 10);
                } else {
                    dlog_error("Invalid queue range");
                    exit(EXIT_FAILURE);
                }

                nbqueues = (end - start) + 1;
                if (nbqueues > MAX_SOCKS) {
                    dlog_errorv("Too many queues. Maximum is %d", MAX_SOCKS);
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
        case 'l':
            if (strcmp("ip", optarg) == 0) {
                opt_transportmode = IPPROTO_RAW;
            } else if (strcmp("udp", optarg) == 0) {
                opt_transportmode = IPPROTO_UDP;
            } else {
                dlog_error("Invalid Protocol");
                exit(EXIT_FAILURE);
            }
            break;
        case 'p':
            if (strcmp("poll", optarg) == 0) {
                opt_pollmode = DQDK_PM_POLL;
            } else if (strcmp("rtc", optarg) == 0) {
                opt_pollmode = DQDK_PM_RTC;
            } else {
                dlog_error("Invalid Poll Mode");
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            opt_shared_umem = atoi(optarg);
            break;
        default:
            dlog_error("Invalid Arg\n");
            exit(EXIT_FAILURE);
        }
    }

    switch (opt_mode) {
    case XDP_MODE_SKB:
        dlog_info("XDP generic mode is chosen.");
        break;
    case XDP_MODE_NATIVE:
        dlog_info("XDP driver mode is chosen.");
        break;
    case XDP_MODE_HW:
        dlog_info("XDP HW-Offloading is chosen.");
        break;
    default:
        break;
    }

    if (opt_zcopy && opt_mode == XDP_MODE_SKB) {
        dlog_info("Turning off zero-copy for XDP generic mode");
        opt_zcopy = 0;
    }

    if (opt_verbose) {
        libbpf_set_print(infoprint);
    }

    switch (opt_pollmode) {
    case DQDK_PM_POLL:
        dlog_info("Multithreading is turned off. Polling all sockets...");
        break;
    case DQDK_PM_RTC:
        dlog_info("One fill queue per socket in run-to-completion mode");
        break;
    default:
        break;
    }

    char queues[5 * MAX_SOCKS] = { 0 };
    char* queues_format = queues;
    for (u32 i = 0; i < nbqueues; i++) {
        ret = (i == nbqueues - 1) ? snprintf(queues_format, 5, "%d", opt_queues[i])
                                  : snprintf(queues_format, 5, "%d, ", opt_queues[i]);
        queues_format += ret;
    }

    if (opt_shared_umem > 1) {
        if (opt_shared_umem > 4) {
            dlog_error("No more than 4 sockets are supported");
            exit(EXIT_FAILURE);
        }

        if (nbqueues != 1) {
            // TODO: support shared umem on many queues
            dlog_error("Shared UMEM works only on one queue");
            // dlog_info("Per-queue routing to XSK.");
            goto cleanup;
        } else {
            dlog_info("Round robin routing to XSK.");
            nbqueues = opt_shared_umem;
            u32 qid = opt_queues[0];

            switch (nbqueues) {
            case 2:
                xdp_filename = XDP_FILE_RR2;
                break;
            case 3:
                xdp_filename = XDP_FILE_RR3;
                break;
            case 4:
                xdp_filename = XDP_FILE_RR4;
                break;
            }

            for (size_t i = 1; i < nbqueues; i++) {
                opt_queues[i] = qid;
            }

            dlog_infov("Working %d XSKs with shared UMEM on queue %s", nbqueues, queues);
        }
    } else {
        dlog_info("Per-queue routing to XSK.");
        dlog_infov("Working %d XSKs on queues: %s", nbqueues, queues);
    }

    if ((ret = setrlimit(RLIMIT_MEMLOCK, &rlim))) {
        dlog_error2("setrlimit", ret);
        goto cleanup;
    }

    struct xdp_program* kern_prog = xdp_program__open_file(xdp_filename, NULL, NULL);
    printf("xdp_filename %s\n", xdp_filename);
    ret = xdp_program__attach(kern_prog, ifindex, opt_mode, 0);
    if (ret) {
        dlog_error2("xdp_program__attach", ret);
        goto cleanup;
    }

    struct bpf_object* obj = xdp_program__bpf_obj(kern_prog);
    int mapfd = bpf_object__find_map_fd_by_name(obj, "xsks_map");

    pthread_t* xsk_workers = NULL;
    if (IS_THREADED(opt_pollmode, nbqueues)) {
        xsk_workers = (pthread_t*)calloc(nbqueues, sizeof(pthread_t));
    }
    xsk_info* xsks = (xsk_info*)calloc(nbqueues, sizeof(xsk_info));
    umem_info* shared_umem = NULL;

    if (opt_shared_umem) {
        shared_umem = IS_THREADED(opt_pollmode, nbqueues) ? umem_info_create(nbqueues) : umem_info_create(1);
        umem_configure(shared_umem);
    }
    struct sigevent sigv;
    sigv.sigev_notify = SIGEV_SIGNAL;
    sigv.sigev_signo = SIGUSR1;
    timer_create(CLOCK_MONOTONIC, &sigv, &timer);
    timer_settime(timer, 0, &opt_duration, NULL);
    for (u32 i = 0; i < nbqueues; i++) {
        xsks[i].batch_size = opt_batchsize;
        xsks[i].libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
        xsks[i].bind_flags = (opt_zcopy ? XDP_ZEROCOPY : XDP_COPY)
            | (opt_needs_wakeup ? XDP_USE_NEED_WAKEUP : 0);

        if (i != 0 && opt_shared_umem) {
            xsks[i].bind_flags = XDP_SHARED_UMEM;
        }

        xsks[i].xdp_flags = 0;
        xsks[i].queue_id = opt_queues[i];
        xsks[i].index = i;

        if (opt_shared_umem) {
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
            struct rx_ctx ctx = {
                .xsks = &xsks[i],
                .bench_mode = opt_transportmode,
                .pollmode = opt_pollmode,
                .count = 1,
                .shared_umem = opt_shared_umem,
            };
            pthread_create(&xsk_workers[i], NULL, poll_rx, (void*)&ctx);
        }
    }

    if (!IS_THREADED(opt_pollmode, nbqueues)) {
        struct rx_ctx ctx = {
            .xsks = xsks,
            .bench_mode = opt_transportmode,
            .pollmode = opt_pollmode,
            .count = nbqueues,
            .shared_umem = opt_shared_umem,
        };

        poll_rx(&ctx);
    }

    struct xsk_stat avg_stats;
    memset(&avg_stats, 0, sizeof(avg_stats));
    for (u32 i = 0; i < nbqueues; i++) {
        if (IS_THREADED(opt_pollmode, nbqueues)) {
            pthread_join(xsk_workers[i], NULL);
        }

        xsk_stats_dump(&xsks[i]);
        avg_stats.runtime = MAX(avg_stats.runtime, xsks[i].stats.runtime);
        avg_stats.fail_polls += xsks[i].stats.fail_polls;
        avg_stats.invalid_ip_pkts += xsks[i].stats.invalid_ip_pkts;
        avg_stats.invalid_udp_pkts += xsks[i].stats.invalid_udp_pkts;
        avg_stats.rcvd_frames += xsks[i].stats.rcvd_frames;
        avg_stats.rcvd_pkts += xsks[i].stats.rcvd_pkts;
        avg_stats.rx_empty_polls += xsks[i].stats.rx_empty_polls;
        avg_stats.rx_fill_fail_polls += xsks[i].stats.rx_fill_fail_polls;
        avg_stats.timeout_polls += xsks[i].stats.timeout_polls;
        avg_stats.xstats.rx_dropped += xsks[i].stats.xstats.rx_dropped;
        avg_stats.xstats.rx_invalid_descs += xsks[i].stats.xstats.rx_invalid_descs;
        avg_stats.xstats.tx_invalid_descs += xsks[i].stats.xstats.tx_invalid_descs;
        avg_stats.xstats.rx_ring_full += xsks[i].stats.xstats.rx_ring_full;
        avg_stats.xstats.rx_fill_ring_empty_descs += xsks[i].stats.xstats.rx_fill_ring_empty_descs;
        avg_stats.xstats.tx_ring_empty_descs += xsks[i].stats.xstats.tx_ring_empty_descs;
    }

    if (nbqueues != 1) {
        printf("Average Stats:\n");
        stats_dump(&avg_stats);
    }
cleanup:
    timer_delete(timer);
    xdp_program__detach(kern_prog, ifindex, opt_mode, 0);
    xdp_program__close(kern_prog);

    if (xsks != NULL) {
        for (size_t i = 0; i < nbqueues; i++) {
            xsk_info xsk = xsks[i];
            xsk_socket__delete(xsk.socket);

            if (!opt_shared_umem && xsk.umem_info != NULL) {
                umem_info_free(xsk.umem_info);
                free(xsk.umem_info);
            }
        }
        free(xsks);
        free(xsk_workers);
    }

    if (opt_shared_umem) {
        umem_info_free(shared_umem);

        if (shared_umem != NULL) {
            free(shared_umem);
        }
    }

    set_hugepages(0);
}
