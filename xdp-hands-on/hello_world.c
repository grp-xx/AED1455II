#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    bpf_printk("Passed packet");
    return XDP_PASS;
}

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    bpf_printk("Dropped packet");
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";