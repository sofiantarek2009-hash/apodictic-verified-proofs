// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
/* Copyright (c) 2026 Noesis AI Inc. */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define POSTGRES_DEFAULT_PORT 5432
#define ODOO_RPC_DEFAULT_PORT 8069
#define NOESIS_PROXY_LOCAL_PORT 5433

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // Client IPv4 address
    __type(value, __u64); // Interception counter & flags
} client_flow_table SEC(".maps");

SEC("xdp")
int noesis_xdp_packet_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)((__u32 *)ip + ip->ihl);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 dest_port = bpf_ntohs(tcp->dest);

    // Trap incoming PostgreSQL or Odoo TCP connections for inline hardware inspection
    if (dest_port == POSTGRES_DEFAULT_PORT || dest_port == ODOO_RPC_DEFAULT_PORT) {
        __u32 src_ip = ip->saddr;
        __u64 init_val = 1;
        __u64 *val = bpf_map_lookup_elem(&client_flow_table, &src_ip);
        if (val) {
            __sync_fetch_and_add(val, 1);
        } else {
            bpf_map_update_elem(&client_flow_table, &src_ip, &init_val, BPF_ANY);
        }
        // Redirect to local wire inspection socket
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
