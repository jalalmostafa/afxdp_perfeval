// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} xsks_maps SEC(".maps");

SEC("xdp/acquire")
int acquire(struct xdp_md* ctx)
{
    __u32 rx_idx = ctx->rx_queue_index;
    if (bpf_map_lookup_elem(&xsks_maps, &rx_idx)) {
        return bpf_redirect_map(&xsks_maps, rx_idx, 0);
    }

    return XDP_PASS;
}
