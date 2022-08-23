// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <xdp/xdp_helpers.h>

#define MAX_SOCKS 4

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

static __u32 rr = 0;

SEC("xdp/acquire")
int acquire(struct xdp_md* ctx)
{
    rr = (rr + 1) & (MAX_SOCKS - 1);
    return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
}
