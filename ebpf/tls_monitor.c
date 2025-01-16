#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "tls_monitor.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, struct flow_tuple);
    __type(value, struct stream_state);
} streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} events SEC(".maps");

static __always_inline int process_tls_header(struct xdp_md *ctx, void *data_start, 
    void *data_end, struct tls_info *tls) {
    
    void *pos = data_start;
    
    // Ensure we can read the TLS record header
    if (pos + 5 > data_end)
        return 0;
        
    tls->content_type = *((__u8 *)pos);
    pos += 1;
    tls->version = bpf_ntohs(*((__u16 *)pos));
    pos += 2;
    tls->length = bpf_ntohs(*((__u16 *)pos));
    
    if (tls->content_type != TLS_HANDSHAKE)
        return 0;
        
    // Process handshake header
    pos += 2;
    if (pos + 4 > data_end)
        return 0;
        
    tls->handshake_type = *((__u8 *)pos);
    pos += 1;
    tls->handshake_len = (*((__u8 *)pos) << 16) | 
                         (*((__u8 *)(pos + 1)) << 8) | 
                         *((__u8 *)(pos + 2));
    
    switch (tls->handshake_type) {
        case TLS_CLIENT_HELLO:
            tls->is_client_hello = 1;
            break;
        case TLS_SERVER_HELLO:
            tls->is_server_hello = 1;
            break;
        case TLS_CERTIFICATE:
            tls->is_certificate = 1;
            break;
    }
    
    return 1;
}

SEC("xdp")
int tls_monitor(struct xdp_md *ctx) {
    void *data_start = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data_start;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
        
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
        
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
        
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
        
    // Process potential TLS data
    void *payload = (void *)(tcp + 1);
    struct tls_info tls = {};
    
    if (process_tls_header(ctx, payload, data_end, &tls)) {
        struct flow_tuple flow = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = tcp->source,
            .dst_port = tcp->dest,
            .protocol = ip->protocol
        };
        
        // Update stream state
        struct stream_state new_state = {};
        struct stream_state *state = bpf_map_lookup_elem(&streams, &flow);
        if (!state) {
            state = &new_state;
        }
        
        // Send event to userspace if needed
        if (tls.is_certificate || tls.is_client_hello || tls.is_server_hello) {
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &tls, sizeof(tls));
        }
        
        // Update stream state
        bpf_map_update_elem(&streams, &flow, state, BPF_ANY);
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
