#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

SEC("xdp")
int log_ip(struct xdp_md *ctx) {
//     bpf_printk("Passed packet");
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;

    __u16 ethertype = eth->h_proto;

//    __u16 ethertype = bpf_ntohs(eth->h_proto);
//    bpf_printk("Ethertype: %d", ethertype);

    if (ethertype == bpf_htons(ETH_P_IP)) {
        bpf_printk("Received an IP Packet");
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";