// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/sysinfo.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>
#include <time.h>
#include <unistd.h>

#include "dqdk.h"
#include "xsk.h"
#include "dlog.h"

u32 break_flag = 0;

#ifdef DEBUG
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

void log_icmp(__u8* frame)
{
    struct ethhdr* framehdr = (struct ethhdr*)frame;
    struct iphdr* packet = (struct iphdr*)(((struct ethhdr*)framehdr) + 1);
    log_frame(framehdr);
    log_pingpong(packet);
}
#endif

void* poll_rx(void* rxctx_ptr)
{
    xsk_t* xsk = (xsk_t*)rxctx_ptr;
    int mtu = get_if_mtu(xsk->opts.ifname);
    u8* pkt_buf = huge_malloc(mtu);
    struct pollfd fds = {
        .fd = xsk_socket__fd(xsk->socket),
        .events = POLLIN
    };

    while (!break_flag) {
        int ret = poll(&fds, 1, 20);
        if (ret < 0) {
            dlog_error2("poll", ret);
        } else if (ret == 0) {
            dlog_error("poll timeout");
        } else if (fds.revents == POLLIN) {
            xsk_ip4(xsk, pkt_buf);
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
        break_flag = 1;
        break;
    default:
        break;
    }
}

void showusage()
{
    printf("daq [options]\n"
           "Options:\n"
           "    -v              Verbose (enable libbpf logging)\n"
           "    -i <nic_name>   Network interface name to work on\n"
           "    -q <queue_id>   Network interface queue id to use\n"
           "    -n <queue_size> Selected queue size\n"
           "    -m <mode>       XDP mode to use: 'native' or 'generic' (default: 'native')\n"
           "    -c              Use XDP copy mode. (default: zero-copy)\n"
           "    -b <batch_size> Batch size\n"
           "    -w              Use XDP need wake up flag\n"
           "    -u              Enable UDP networking\n");
}

#define TIMESPEC_TO_NSECS(t) ((t->tv_sec * 1e9) + t->tv_nsec)

u64 compute_nsecs(struct timespec* t0, struct timespec* t1)
{
    return TIMESPEC_TO_NSECS(t1) - TIMESPEC_TO_NSECS(t0);
}

int main(int argc, char** argv)
{
    int ifindex, ret, opt;
    char* opt_ifname = NULL;
    enum xdp_attach_mode opt_mode = XDP_MODE_NATIVE;
    u32 opt_queueid = -1, opt_batchsize = 64;
    u64 opt_queuesize = 4 * 1024;
    u8 opt_need_wakeup = 0, opt_verbose = 0, opt_zcopy = 1, opt_udpmode = 0;
    pthread_t poller;
    u32 zero_copy_working = 0;

    int nprocs = get_nprocs();
    cpu_set_t cpus;
    pthread_attr_t attrs;
    struct sched_param schedparams;
    struct timespec t_0, t_end;
    u64 duration;

    if (argc <= 1) {
        dlog_error("Invalid Number of Arguments");
        showusage();
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGABRT, signal_handler);

    while ((opt = getopt(argc, argv, "hcb:i:q:m:n:vw")) != -1) {
        switch (opt) {
        case 'i':
            opt_ifname = optarg;
            ifindex = if_nametoindex(opt_ifname);
            break;
        case 'q':
            opt_queueid = atoi(optarg);
            break;
        case 'm':
            char* marg = optarg;
            if (strcmp("native", marg) == 0) {
                opt_mode = XDP_MODE_NATIVE;
            } else if (strcmp("generic", marg) == 0) {
                opt_mode = XDP_MODE_SKB;
            } else {
                dlog_error("Invalid XDP Mode");
                exit(EXIT_FAILURE);
            }
            break;
        case 'c':
            opt_zcopy = 0;
            break;
        case 'n':
            opt_queuesize = atol(optarg);
            break;
        case 'v':
            opt_verbose = 1;
            break;
        case 'b':
            opt_batchsize = atoi(optarg);
            break;
        case 'w':
            opt_need_wakeup = 1;
            break;
        case 'u':
            opt_udpmode = 1;
            break;
        case 'h':
            showusage();
            break;
        default:
            showusage();
            dlog_error("Invalid Arg\n");
            exit(EXIT_SUCCESS);
        }
    }

    if (opt_zcopy && opt_mode == XDP_MODE_SKB) {
        dlog_info("Turning off zero-copy for XDP generic mode");
        opt_zcopy = 0;
    }

    struct xdp_opts opts = {
        .ifindex = ifindex,
        .ifname = opt_ifname,
        .queue_id = opt_queueid,
        .queue_size = opt_queuesize,
        .verbose = opt_verbose,
        .need_wakeup = opt_need_wakeup,
        .mode = opt_mode,
        .zcopy = opt_zcopy,
        .udp_mode = opt_udpmode,
        .batch_size = opt_batchsize
    };

    xsk_t* xsk = xsk_init(&opts);
    ret = xsk_open(xsk);
    if (ret) {
        dlog_error2("xsk_open", ret);
        goto exit;
    }

    u32 socklen = sizeof(zero_copy_working);
    getsockopt(xsk_socket__fd(xsk->socket), XDP_OPTIONS, XDP_OPTIONS_ZEROCOPY,
        (void*)&zero_copy_working, &socklen);

    if (zero_copy_working) {
        dlog_info("Zero copy is used");
    } else {
        dlog_info("No zero copy");
    }

    pthread_attr_init(&attrs);
    pthread_attr_setinheritsched(&attrs, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&attrs, SCHED_FIFO);

    schedparams.sched_priority = sched_get_priority_max(SCHED_FIFO);
    pthread_attr_setschedparam(&attrs, &schedparams);

    CPU_ZERO(&cpus);
    CPU_SET(rand() % nprocs, &cpus);

    clock_gettime(CLOCK_MONOTONIC, &t_0);
    pthread_create(&poller, &attrs, poll_rx, xsk);
    pthread_setaffinity_np(poller, sizeof(cpus), &cpus);
    pthread_getaffinity_np(poller, sizeof(cpus), &cpus);

    for (int j = 0; j < CPU_SETSIZE; j++)
        if (CPU_ISSET(j, &cpus))
            dlog("Affinity set to CPU %d\n", j);

    pthread_join(poller, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t_end);
    duration = compute_nsecs(&t_0, &t_end);
    dlog("Runtime %lld\n", duration);
    dlog("Packet Rate: %f\n", xsk->stats.rcvd_pkts * 1.0 / duration);
    dlog("UDP Segment Rate: %f\n", xsk->stats.rcvd_udps * 1.0 / duration);
    struct xdp_statistics dbg_stat;
    u32 xdp_statistics_len = sizeof(struct xdp_statistics);
    getsockopt(xsk_socket__fd(xsk->socket), SOL_XDP, XDP_STATISTICS, &dbg_stat, &xdp_statistics_len);
    printf("rx_dropped (other): %lld, rx_invalid_descs: %lld, rx_ring_full: %lld, rx_fill_ring_empty_descs: %lld\n",
        dbg_stat.rx_dropped, dbg_stat.rx_invalid_descs, dbg_stat.rx_ring_full, dbg_stat.rx_fill_ring_empty_descs);
    pthread_attr_destroy(&attrs);
exit:
    xsk_cleanup(xsk);
    set_hugepages(0);
}
