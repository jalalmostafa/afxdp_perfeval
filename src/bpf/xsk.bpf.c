
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <xdp/xdp_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
__uint(xsk_prog_version, 1) SEC("xdp_metadata");
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(acquire);

SEC("xdp/acquire")
int acquire(struct xdp_md* ctx)
{
    __u32 rx_idx = ctx->rx_queue_index;
    __u32* exists = (__u32*)bpf_map_lookup_elem(&xsks_map, &rx_idx);
    bpf_printk("***** ACQUIRE ******* RX Queue ID: %d Exists %p - %d\n", rx_idx, exists, exists != NULL ? *exists : -1);

    if (exists) {
        long ret = bpf_redirect_map(&xsks_map, rx_idx, XDP_DROP);
        if (ret == XDP_REDIRECT) {
            bpf_printk("***** ACQUIRE ******* Redirect to: %d\n", *exists);
        } else {
            bpf_printk("***** ACQUIRE ******* NO Redirect\n");
        }

        return ret;
    }

    return XDP_PASS;
}
