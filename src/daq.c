// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#define UMEM_LEN 1000
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define UMEM_SIZE (UMEM_LEN * FRAME_SIZE)
#define FRAME_INVALID -1

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
        // if (info->umem != NULL) {
        //     free(info->umem);
        // }
    }
}

#define NONZERO(x)                         \
    do {                                   \
        if (x) {                           \
            printf("Line %d\n", __LINE__); \
            return x;                      \
        }                                  \
    } while (0)

static int xsk_configure(xsk_info* xsk, net_info* net, umem_info* umem)
{
    int ret = 0;
    __u32 xdp_prog = -1;

    if (umem == NULL) {
        return EINVAL;
    }

    const struct xsk_umem_config cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0
    };

    ret = xsk_umem__create(&umem->umem, umem->buffer, UMEM_SIZE,
        &umem->fill_ring, &umem->comp_ring, &cfg);
    NONZERO(ret);
    if (ret) {
        return ret;
    }

    const struct xsk_socket_config xsk_config = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .bind_flags = xsk->bind_flags,
        .libbpf_flags = xsk->libbpf_flags,
        .xdp_flags = xsk->xdp_flags
    };

    ret = xsk_socket__create(&xsk->socket, net->ifname, net->qid, umem->umem,
        &xsk->rx, &xsk->tx, &xsk_config);
    NONZERO(ret);
    if (ret) {
        return ret;
    }

    int ifindex = if_nametoindex(net->ifname);
    ret = bpf_get_link_xdp_id(ifindex, &xdp_prog, xsk->xdp_flags);
    NONZERO(ret);
    if (ret) {
        return ret;
    }

    printf("XDP Program ID: %d\n", xdp_prog);

    // push all frames to fill ring
    __u32 idx;
    ret = xsk_ring_prod__reserve(&umem->fill_ring, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        return EIO;
    }

    // fill them with something
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
        *xsk_ring_prod__fill_addr(&umem->fill_ring, idx++) = FRAME_INVALID;
    }

    xsk_ring_prod__submit(&umem->fill_ring, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return 0;
}

int process_packet(xsk_info* xsk, umem_info* umem, const struct xdp_desc* desc)
{
    (void)xsk;
    struct ethhdr* frame = (struct ethhdr*)xsk_umem__get_data(umem->buffer, desc->addr);
    printf("[SRC MAC] %s - [DST MAC] %s\n", frame->h_source, frame->h_dest);
    return 0;
}

void do_rx(xsk_info* xsk, umem_info* umem)
{
    __u32 idx, recvd;
    recvd = xsk_ring_cons__peek(&xsk->rx, 1000, &idx);
    if (!recvd) {
        return;
    }

    for (__u32 i = 0; i < recvd; i++) {
        const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk->rx, idx);
        process_packet(xsk, umem, desc);
        idx++;
    }
    xsk_ring_cons__release(&xsk->rx, recvd);
}

void process_rx(xsk_info* xsk, umem_info* umem)
{
    struct pollfd fds[2];
    memset(fds, 0, sizeof(fds));

    fds[0].fd = xsk_socket__fd(xsk->socket);
    fds[0].events = POLLIN;
    while (!break_flag) {
        int ret = poll(fds, 1, 1000);
        if (ret < 0) {
            printf("[Poll-%d] %s\n", __LINE__, strerror(errno));
        } else if (ret == 0) {
            printf("[Poll] Timeout\n");
        } else {
            do_rx(xsk, umem);
        }
    }
}

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    xsk_info xsk = {
        // .bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
        .bind_flags = XDP_USE_NEED_WAKEUP,
        .libbpf_flags = 0,
        // .xdp_flags = XDP_FLAGS_DRV_MODE,
        .xdp_flags = 0
    };

    net_info net = {
        .ifname = "veth0",
        .qid = 1
    };

    umem_info* umem = umem_info_create();
    int ret = xsk_configure(&xsk, &net, umem);

    if (ret) {
        goto error;
    }

    goto cleanup;
error:
    perror("Error");
    printf("Return Code: %d, Errno %d\n", ret, errno);

cleanup:
    xsk_socket__delete(xsk.socket);
    umem_info_free(umem);
}
