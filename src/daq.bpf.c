// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("xdp/acquire")
int acquire(struct xdp_md* ctx)
{
	bpf_printk("BPF triggered from PID %d.\n", 1);
	return XDP_PASS;
}
