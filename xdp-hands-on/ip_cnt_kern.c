#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, long);
    __uint(max_entries,2);
} rxcnt SEC(".maps");

SEC("xdp")
int count_ipv4(struct xdp_md *ctx) {
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
        // The packet is an IPv4 packet, increment the counter
        // bpf_printk("Received an IP Packet");
        __u32 key = 0;
        long *value = bpf_map_lookup_elem(&rxcnt, &key);
        if (value) {
           // (*value)++;  // Race Condition!!
           __sync_fetch_and_add(value,1);  // Thread safe
        }
    } else {
        __u32 key = 1;
        long *value = bpf_map_lookup_elem(&rxcnt, &key);
        if (value) {
           __sync_fetch_and_add(value,1);  // Thread safe
        }
    };

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";