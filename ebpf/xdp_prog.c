#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} packet_map SEC(".maps");

struct packet_info {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

__always_inline
static int process_packet(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct packet_info pinfo = {};

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    pinfo.src_ip = ip->saddr;
    pinfo.dst_ip = ip->daddr;
    pinfo.src_port = tcp->source;
    pinfo.dst_port = tcp->dest;

    bpf_perf_event_output(ctx, &packet_map, BPF_F_CURRENT_CPU, &pinfo, sizeof(pinfo));

    return XDP_PASS;
}

SEC("xdp")
int xdp_prog_main(struct xdp_md *ctx)
{
    return process_packet(ctx);
}

char _license[] SEC("license") = "GPL";
