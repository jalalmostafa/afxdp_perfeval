// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <xdp/xdp_helpers.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define MAX_SOCKS 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";
__uint(xsk_prog_version, 1) SEC("xdp_metadata");
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_SOCKS);
} xsks_map SEC(".maps");

struct {
    __uint(priority, 1);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(acquire);

SEC("xdp/acquire")
int acquire(struct xdp_md* ctx)
{
    unsigned short srcp, dstp;
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if (data >= data_end)
        return XDP_DROP;

    if (data + ETH_HLEN >= data_end)
        return XDP_DROP;

    struct ethhdr* eth = (struct ethhdr*)data;
    if (eth + 1 >= data_end)
        return XDP_DROP;

    if (ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr* ip = (struct iphdr*)eth + 1;

    if (ip + 1 >= data_end)
        return XDP_DROP;

    // if (ip->protocol != IPPROTO_UDP)
    //     return XDP_PASS;

    struct udphdr* udp = (struct udphdr*)ip + 1;
    if (udp + 1 >= data_end)
        return XDP_DROP;

    dstp = ntohs(udp->dest);
    srcp = ntohs(udp->source);
    bpf_printk("Srcp %d -- Destp %d\n", srcp, dstp);
    if (dstp == 5000 || srcp == 5000) {
        return XDP_PASS;
    }

    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_DROP);
}
