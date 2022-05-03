// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
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
#define NETIF "xdptut-2d45"

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
    if (ret) {
        return ret;
    }

    ret = bpf_get_link_xdp_id(net->ifindex, &xdp_prog, xsk->xdp_flags);
    struct xdp_program* program = xdp_program__from_id(xdp_prog);
    enum xdp_attach_mode mode = xdp_program__is_attached(program, net->ifindex);
    if (ret) {
        return ret;
    }

    printf("XDP Program ID: %d Mode: %d\n", xdp_prog, mode);

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
    printf("[SRC MAC] %s - [DST MAC] %s - [PROTO] %d\n", frame->h_source, frame->h_dest, frame->h_proto);
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

struct rx_ctx {
    xsk_info* xsk;
    umem_info* umem;
};

void* process_rx(void* rxctx_ptr)
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
        } else {
            do_rx(xsk, umem);
        }

        if (fds[0].revents != 0)
            printf("fds[0].revents=%d\n", fds[0].revents);
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
    enum xdp_attach_mode mode = XDP_MODE_NATIVE;
    int loaded = 0;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);
    libbpf_set_print(infoprint);

    printf("xdp_program__open_file errno: %d\n", errno);
    struct xdp_program* kern_prog = xdp_program__open_file("/home/jalal/ebpf-daq/src/daq.bpf.o", NULL, NULL);
    printf("xdp_program__open_file errno: %d, %p\n", errno, kern_prog);

    printf("xdp_program__attach errno: %d\n", errno);
    ret = loaded = xdp_program__attach(kern_prog, ifindex, mode, 0);
    printf("xdp_program__attach ret %d errno: %d\n", ret, errno);
    if (ret) {
        goto error;
    }

    xsk_info* xsk = (xsk_info*)calloc(1, sizeof(xsk_info));
    xsk->bind_flags = XDP_USE_NEED_WAKEUP;
    xsk->libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    // xsk->xdp_flags = XDP_FLAGS_DRV_MODE;

    net_info net = {
        .ifname = NETIF,
        .qid = 0,
        .ifindex = ifindex
    };

    umem_info* umem = umem_info_create();
    ret = xsk_configure(xsk, &net, umem);

    if (ret) {
        goto error;
    }

    struct bpf_object* obj = xdp_program__bpf_obj(kern_prog);
    int mapfd = bpf_object__find_map_fd_by_name(obj, "xsks_maps");
    printf("mapfd: %d\n", mapfd);
    if (mapfd) {
        int fd = xsk_socket__fd(xsk->socket);
        ret = bpf_map_update_elem(mapfd, &ifindex, &fd, 0);
    }

    struct rx_ctx ctx = { .umem = umem, .xsk = xsk };
    pthread_t poller;
    pthread_create(&poller, NULL, process_rx, (void*)&ctx);
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
