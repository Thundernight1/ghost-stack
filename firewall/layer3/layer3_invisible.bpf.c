//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// GHOST-STACK CORE — Layer 3: INVISIBLE WALL (XDP, NIC driver level)
//
// Technology: XDP BPF program in native mode (kernel bypass speed)
//
// Behavior:
//   - Attached at NIC driver level — BEFORE kernel network stack
//   - LPM trie allowlist: only cryptographically verified source IPs pass
//   - Everything NOT in allowlist: XDP_DROP — ABSOLUTE SILENCE
//     No RST, no ICMP unreachable, no TCP reset, nothing.
//   - Attacker's connection hangs forever — cannot distinguish from packet loss
//   - Drop counters: BPF_MAP_TYPE_LRU_PERCPU_HASH (in kernel memory only)
//   - AGENT-BETA reads drop counters via BPF map poll every 500ms
//   - Allowlist updates require Ed25519-signed update from orchestrator
//
// Attached via: ip link set dev eth0 xdpdrv obj layer3_invisible.bpf.o sec xdp
//
// Compiled with: clang -O2 -g -target bpf -c layer3_invisible.bpf.c -o layer3_invisible.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806

// XDP actions.
#define XDP_ABORTED  0
#define XDP_DROP     1
#define XDP_PASS     2
#define XDP_TX       3
#define XDP_REDIRECT 4

// Maximum entries in allowlist and drop counter.
#define MAX_ALLOWLIST   4096
#define MAX_DROP_TRACK  65536

// --- BPF Maps ---

// LPM trie allowlist: only IPs in this trie are allowed through.
// Supports CIDR notation (e.g., 10.200.0.0/16).
// Managed by orchestrator via signed updates ONLY.
struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ALLOWLIST);
    __type(key, struct lpm_key);
    __type(value, __u32);  // 1 = allowed, 0 = blocked
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowlist SEC(".maps");

// IPv6 allowlist (separate trie).
struct lpm_key_v6 {
    __u32 prefixlen;
    __u8  addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_ALLOWLIST);
    __type(key, struct lpm_key_v6);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowlist_v6 SEC(".maps");

// Drop counter: per-CPU LRU hash for tracking dropped IPs.
// In kernel memory ONLY — never written to disk.
// AGENT-BETA polls this map every 500ms.
struct drop_stats {
    __u64 count;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u16 last_dst_port;
    __u8  last_proto;
    __u8  _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_DROP_TRACK);
    __type(key, __u32);      // source IPv4 address
    __type(value, struct drop_stats);
} drop_counters SEC(".maps");

// Global statistics counter.
struct global_stats {
    __u64 total_packets;
    __u64 total_allowed;
    __u64 total_dropped;
    __u64 total_arp_passed;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats);
} stats SEC(".maps");

// Configuration: enable/disable the firewall.
// Key 0: enabled (1) or disabled (0).
// Key 1: log_level (0=none, 1=drops, 2=all).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// --- Helper functions ---

// Update global statistics.
static __always_inline void update_stats(int allowed)
{
    __u32 key = 0;
    struct global_stats *s = bpf_map_lookup_elem(&stats, &key);
    if (s) {
        s->total_packets++;
        if (allowed)
            s->total_allowed++;
        else
            s->total_dropped++;
    }
}

// Update drop counter for a specific source IP.
static __always_inline void record_drop(__u32 src_ip, __u16 dst_port, __u8 proto)
{
    struct drop_stats *existing = bpf_map_lookup_elem(&drop_counters, &src_ip);
    __u64 now = bpf_ktime_get_ns();

    if (existing) {
        existing->count++;
        existing->last_seen_ns = now;
        existing->last_dst_port = dst_port;
        existing->last_proto = proto;
    } else {
        struct drop_stats new_stats = {};
        new_stats.count = 1;
        new_stats.first_seen_ns = now;
        new_stats.last_seen_ns = now;
        new_stats.last_dst_port = dst_port;
        new_stats.last_proto = proto;
        bpf_map_update_elem(&drop_counters, &src_ip, &new_stats, BPF_NOEXIST);
    }
}

// Check if the firewall is enabled.
static __always_inline int is_enabled(void)
{
    __u32 key = 0;
    __u32 *enabled = bpf_map_lookup_elem(&config, &key);
    if (!enabled)
        return 1;  // Default: enabled.
    return *enabled;
}

// --- XDP Program ---

// xdp_invisible_wall: The INVISIBLE WALL.
//
// Attached at NIC driver level — before the kernel network stack.
// Only cryptographically verified source IPs pass.
// Everything else: XDP_DROP — ABSOLUTE SILENCE.
//
// No RST, no ICMP unreachable, no TCP reset, no ICMP port unreachable, NOTHING.
// Attacker's connection hangs forever — they cannot distinguish from packet loss.
SEC("xdp")
int xdp_invisible_wall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check if firewall is enabled.
    if (!is_enabled())
        return XDP_PASS;

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    // Always pass ARP — required for basic network functionality.
    // Blocking ARP would make the host unreachable even for legitimate traffic.
    if (eth_proto == ETH_P_ARP) {
        __u32 key = 0;
        struct global_stats *s = bpf_map_lookup_elem(&stats, &key);
        if (s)
            s->total_arp_passed++;
        return XDP_PASS;
    }

    // --- IPv4 handling ---
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_DROP;

        __u32 src_ip = ip->saddr;
        __u8 proto = ip->protocol;

        // Extract destination port for logging.
        __u16 dst_port = 0;
        if (proto == 6 || proto == 17) {  // TCP or UDP
            // Parse port from transport header.
            void *transport = (void *)ip + (ip->ihl * 4);
            if (transport + 4 <= data_end) {
                // Destination port is at offset 2 in both TCP and UDP headers.
                dst_port = bpf_ntohs(*(__u16 *)(transport + 2));
            }
        }

        // Lookup source IP in LPM trie allowlist.
        struct lpm_key key = {
            .prefixlen = 32,
            .addr = src_ip,
        };

        __u32 *allowed = bpf_map_lookup_elem(&allowlist, &key);

        if (allowed && *allowed == 1) {
            // IP is in allowlist — let it through.
            update_stats(1);
            return XDP_PASS;
        }

        // NOT in allowlist: ABSOLUTE SILENCE.
        // XDP_DROP — packet is silently discarded at NIC driver level.
        // No RST, no ICMP unreachable, NOTHING.
        // Attacker's connection hangs forever.
        record_drop(src_ip, dst_port, proto);
        update_stats(0);
        return XDP_DROP;
    }

    // --- IPv6 handling ---
    if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_DROP;

        // Lookup source IPv6 in LPM trie.
        struct lpm_key_v6 key = {
            .prefixlen = 128,
        };
        __builtin_memcpy(key.addr, &ip6->saddr, 16);

        __u32 *allowed = bpf_map_lookup_elem(&allowlist_v6, &key);

        if (allowed && *allowed == 1) {
            update_stats(1);
            return XDP_PASS;
        }

        // ABSOLUTE SILENCE for IPv6 too.
        update_stats(0);
        return XDP_DROP;
    }

    // Unknown protocol: drop silently.
    update_stats(0);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
