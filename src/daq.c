// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/ip.h>
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

#define UMEM_LEN 1000
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (UMEM_LEN * FRAME_SIZE)
#define FRAME_INVALID -1
#define FILLQ_LEN XSK_RING_PROD__DEFAULT_NUM_DESCS * 2
#define COMPQ_LEN XSK_RING_CONS__DEFAULT_NUM_DESCS

#define NETIF "veth0"
#define XDP_MODE XDP_MODE_NATIVE
#define QUEUE_ID 0

typedef unsigned int queue_id;

typedef struct {
    struct xsk_umem* umem;
    struct xsk_ring_prod fill_ring;
    struct xsk_ring_cons comp_ring;
    void* buffer;
} umem_info;

typedef struct {
    char* ifname;
    queue_id qid;
    __u32 ifindex;
} net_info;

typedef struct {
    struct xsk_socket* socket;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    __u32 libbpf_flags;
    __u32 xdp_flags;
    __u16 bind_flags;
} xsk_info;

__u32 break_flag = 0;

static void* umem_buffer_create()
{
    // use huge pages?
    return mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static umem_info* umem_info_create()
{
    umem_info* info = (umem_info*)calloc(1, sizeof(umem_info));

    if (info == NULL) {
        return NULL;
    }

    info->buffer = umem_buffer_create();
    info->umem = NULL;

    return info;
}

static void umem_info_free(umem_info* info)
{
    if (info != NULL) {
        munmap(info->buffer, UMEM_SIZE);
        xsk_umem__delete(info->umem);
    }
}

/*
    UMEM Flags
    Unaligned Memory CHUNK: XDP_UMEM_UNALIGNED_CHUNK_FLAG (Use HUGE Pages - mmap MAP_HUGETLB - and custom memory allocator)

    bind flags:
    XDP_USE_NEED_WAKEUP


 */
static int xsk_configure(xsk_info* xsk, net_info* net, umem_info* umem)
{
    int ret = 0;
    __u32 xdp_prog = -1;

    if (umem == NULL) {
        return EINVAL;
    }

    const struct xsk_umem_config cfg = {
        .fill_size = FILLQ_LEN,
        .comp_size = COMPQ_LEN,
        .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0
    };

    ret = xsk_umem__create(&umem->umem, umem->buffer, UMEM_SIZE,
        &umem->fill_ring, &umem->comp_ring, &cfg);
    if (ret) {
        return ret;
    }

    // push all frames to fill ring
    __u32 idx;
    ret = xsk_ring_prod__reserve(&umem->fill_ring, FILLQ_LEN, &idx);
    if (ret != FILLQ_LEN) {
        return EIO;
    }

    // fill addresses
    for (int i = 0; i < FILLQ_LEN; i++) {
        *xsk_ring_prod__fill_addr(&umem->fill_ring, idx++) = i * FRAME_SIZE;
    }

    xsk_ring_prod__submit(&umem->fill_ring, FILLQ_LEN);

    const struct xsk_socket_config xsk_config = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .bind_flags = xsk->bind_flags,
        .libbpf_flags = xsk->libbpf_flags,
        .xdp_flags = xsk->xdp_flags
    };

    ret = xsk_socket__create(&xsk->socket, net->ifname, net->qid, umem->umem,
        &xsk->rx, &xsk->tx, &xsk_config);
    if (ret) {
        return ret;
    }

    ret = bpf_get_link_xdp_id(net->ifindex, &xdp_prog, xsk->xdp_flags);
    if (ret) {
        return ret;
    }
    struct xdp_program* program = xdp_program__from_id(xdp_prog);
    enum xdp_attach_mode mode = xdp_program__is_attached(program, net->ifindex);

    printf("XDP Program ID: %d Mode: %d\n", xdp_prog, mode);

    return 0;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
    /* add up 16-bit and 16-bit for 16+c bit */
    x = (x & 0xffff) + (x >> 16);
    /* add up carry.. */
    x = (x & 0xffff) + (x >> 16);
    return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static unsigned int inet_csum(const unsigned char* buff, int len)
{
    unsigned int result = 0;
    int odd;

    if (len <= 0)
        goto out;
    odd = 1 & (unsigned long)buff;
    if (odd) {
#ifdef __LITTLE_ENDIAN
        result += (*buff << 8);
#else
        result = *buff;
#endif
        len--;
        buff++;
    }
    if (len >= 2) {
        if (2 & (unsigned long)buff) {
            result += *(unsigned short*)buff;
            len -= 2;
            buff += 2;
        }
        if (len >= 4) {
            const unsigned char* end = buff + ((unsigned int)len & ~3);
            unsigned int carry = 0;

            do {
                unsigned int w = *(unsigned int*)buff;

                buff += 4;
                result += carry;
                result += w;
                carry = (w > result);
            } while (buff < end);
            result += carry;
            result = (result & 0xffff) + (result >> 16);
        }
        if (len & 2) {
            result += *(unsigned short*)buff;
            buff += 2;
        }
    }
    if (len & 1)
#ifdef __LITTLE_ENDIAN
        result += *buff;
#else
        result += (*buff << 8);
#endif
    result = from32to16(result);
    if (odd)
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
    return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *	This function code has been taken from
 *	Linux kernel lib/checksum.c
 */
static inline __sum16 ip_fast_csum(const void* iph, unsigned int ihl)
{
    return (__sum16)~inet_csum(iph, ihl * 4);
}

void log_pingpong(struct iphdr* packet)
{
    __u32 saddr = ntohl(packet->saddr);
    __u32 daddr = ntohl(packet->daddr);
    printf("[PING]: %i.%i.%i.%i is pinging %i.%i.%i.%i\n", (saddr >> 24) & 0xFF,
        (saddr >> 16) & 0xFF, (saddr >> 8) & 0xFF, saddr & 0xFF,
        (daddr >> 24) & 0xFF, (daddr >> 16) & 0xFF, (daddr >> 8) & 0xFF,
        daddr & 0xFF);
}

void log_frame(struct ethhdr* frame)
{
    int ethertype = ntohs(frame->h_proto);
    printf("[SRC MAC] %02X:%02X:%02X:%02X:%02X:%02X - [DST MAC] %02X:%02X:%02X:%02X:%02X:%02X - [PROTO] 0x%04X\n",
        frame->h_source[0], frame->h_source[1], frame->h_source[2], frame->h_source[3], frame->h_source[4], frame->h_source[5],
        frame->h_dest[0], frame->h_dest[1], frame->h_dest[2], frame->h_dest[3], frame->h_dest[4], frame->h_dest[5], ethertype);
}

static __u8 pong_reply[FRAME_SIZE];

struct reply {
    struct icmphdr hdr;
    __u8 buffer[56];
};

__u8* construct_pong(struct ethhdr* frame, __u32 len)
{
    struct iphdr* packet = (struct iphdr*)(frame + 1);
    struct icmphdr* icmp = (struct icmphdr*)(packet + 1);
    __u8* data = (__u8*)(icmp + 1);

    int datalen = len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct icmphdr);

    memset(pong_reply, 0, FRAME_SIZE);
    printf("Data len: %d\n", datalen);
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

__u8* process_frame(__u8* buffer, __u32 len)
{
    (void)len;
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
    default:
        return NULL;
    }
}

#define BATCH_SIZE 1000

void log_icmp(__u8* frame)
{
    struct ethhdr* framehdr = (struct ethhdr*)frame;
    struct iphdr* packet = (struct iphdr*)(((struct ethhdr*)framehdr) + 1);
    log_frame(framehdr);
    log_pingpong(packet);
}

int xdp_pingpong(xsk_info* xsk, umem_info* umem)
{
    __u32 idx_rx, idx_tx, idx_fq, idx_cq;

    int recvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, &idx_rx);
    if (!recvd) {
        return ECOMM;
    }

    int ret = xsk_ring_prod__reserve(&umem->fill_ring, recvd, &idx_fq);
    if (ret < 0) {
        return -ret;
    }

    // while (ret != recvd) {
    //     if (ret < 0) {
    //         return -ret;
    //     }

    //     ret = xsk_ring_prod__reserve(&umem->fill_ring, recvd, &idx_fq);
    // }

    ret = xsk_ring_cons__peek(&umem->comp_ring, BATCH_SIZE, &idx_cq);
    if (ret > 0) {
        xsk_ring_cons__release(&umem->comp_ring, recvd);
        for (int i = 0; i < ret; i++)
            *xsk_ring_prod__fill_addr(&umem->fill_ring, idx_fq++) = *xsk_ring_cons__comp_addr(&umem->comp_ring, idx_cq++);
        xsk_ring_prod__submit(&umem->fill_ring, recvd);
    }

    ret = xsk_ring_prod__reserve(&xsk->tx, recvd, &idx_tx);
    if (ret < 0) {
        return -ret;
    }

    // while (ret != recvd) {
    //     if (ret < 0) {
    //         return -ret;
    //     }
    //     // TODO: empty completion ring!!!
    //     ret = xsk_ring_prod__reserve(&xsk->tx, recvd, &idx_tx);
    // }

    for (int i = 0; i < recvd; i++) {
        __u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        __u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
        __u64 orig = xsk_umem__extract_addr(addr);

        addr = xsk_umem__add_offset_to_addr(addr);

        __u8* frame = xsk_umem__get_data(umem->buffer, addr);

        log_icmp(frame);

        __u8* pong = process_frame(frame, len);

        if (pong != NULL) {
            memcpy(frame, pong, FRAME_SIZE);
            log_icmp(pong);

            xsk_ring_prod__tx_desc(&xsk->tx, idx_tx)->addr = orig;
            xsk_ring_prod__tx_desc(&xsk->tx, idx_tx)->len = len;
            idx_tx++;
        }
        idx_rx++;
        idx_fq++;
    }

    xsk_ring_cons__release(&xsk->rx, recvd);
    xsk_ring_prod__submit(&xsk->tx, recvd);
    return 0;
}

struct rx_ctx {
    xsk_info* xsk;
    umem_info* umem;
};

void* poll_rx(void* rxctx_ptr)
{
    xsk_info* xsk = ((struct rx_ctx*)rxctx_ptr)->xsk;
    umem_info* umem = ((struct rx_ctx*)rxctx_ptr)->umem;
    struct pollfd fds[1];
    memset(fds, 0, sizeof(fds));

    fds[0].fd = xsk_socket__fd(xsk->socket);
    fds[0].events = POLLIN;
    while (!break_flag) {
        int ret = poll(fds, 1, 1000);
        if (ret < 0) {
            printf("[Poll-%d] %s\n", __LINE__, strerror(errno));
        } else if (ret == 0) {
            printf("[Poll] Timeout\n");
        } else if (fds[0].revents == POLLIN) {
            xdp_pingpong(xsk, umem);
        }
    }

    return NULL;
}

void signal_handler(int sig)
{
    printf("signal: %d\n", sig);
    switch (sig) {
    case SIGINT:
    case SIGTERM:
    case SIGABRT:
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

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    int ifindex = if_nametoindex(NETIF), ret;
    enum xdp_attach_mode mode = XDP_MODE;
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    libbpf_set_print(infoprint);

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
            strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct xdp_program* kern_prog = xdp_program__open_file("./bpf/xsk.bpf.o", NULL, NULL);

    ret = xdp_program__attach(kern_prog, ifindex, mode, 0);
    if (ret) {
        goto error;
    }

    xsk_info* xsk = (xsk_info*)calloc(1, sizeof(xsk_info));
    xsk->libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    xsk->xdp_flags = 0;
    xsk->bind_flags = 0;

    net_info net = {
        .ifname = NETIF,
        .qid = QUEUE_ID,
        .ifindex = ifindex
    };

    umem_info* umem = umem_info_create();
    ret = xsk_configure(xsk, &net, umem);

    if (ret) {
        goto error;
    }
    struct bpf_object* obj = xdp_program__bpf_obj(kern_prog);
    int mapfd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    printf("mapfd: %d\n", mapfd);
    ret = xsk_socket__update_xskmap(xsk->socket, mapfd);
    printf("xsk_socket__update_xskmap says: %d\n", ret);

    struct rx_ctx ctx = { .umem = umem, .xsk = xsk };
    pthread_t poller;
    pthread_create(&poller, NULL, poll_rx, (void*)&ctx);
    pthread_join(poller, NULL);

    goto cleanup;
error:
    perror("Error");
    printf("Return Code: %d, Errno %d\n", ret, errno);

cleanup:
    xdp_program__detach(kern_prog, ifindex, mode, 0);
    xdp_program__close(kern_prog);
    if (xsk != NULL) {
        xsk_socket__delete(xsk->socket);
        free(xsk);
    }

    if (umem != NULL) {
        umem_info_free(umem);
    }
}
