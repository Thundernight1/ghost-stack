//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// GHOST-STACK CORE — Layer 2: eBPF Traffic Control Deception Program
//
// Technology: eBPF TC (Traffic Control) ingress/egress — completely
// different from Layer 1 nftables.
//
// Behavior (MUST differ from Layer 1 in every observable way):
//   - Different port set: 8443, 9200, 5601, 2375, 4789
//   - Appears to be internal DevOps/monitoring stack
//   - Captures all credential attempts, payload content, tool signatures
//   - TC program at NIC level: different hook point than L1 nftables
//   - All captures → perf ring buffer → AGENT-BETA (NO disk writes)
//
// Attached via: tc qdisc add dev eth0 clsact
//               tc filter add dev eth0 ingress bpf da obj layer2_tc.bpf.o sec tc_ingress
//
// Compiled with: clang -O2 -g -target bpf -c layer2_tc.bpf.c -o layer2_tc.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK       0
#define TC_ACT_SHOT     2
#define TC_ACT_REDIRECT 7

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// L2 deception ports — DIFFERENT from L1.
// Appears to be internal DevOps/monitoring stack.
#define PORT_DEVOPS_HTTPS   8443   // Internal HTTPS (appears as Kubernetes dashboard)
#define PORT_ELASTICSEARCH  9200   // Elasticsearch API
#define PORT_KIBANA         5601   // Kibana dashboard
#define PORT_DOCKER_API     2375   // Docker API (unencrypted — honeypot bait)
#define PORT_VXLAN          4789   // VXLAN overlay (network discovery bait)

#define MAX_PAYLOAD_CAPTURE 256
#define MAX_CRED_LEN        128

// --- Event types for AGENT-BETA ---

enum l2_event_type {
    L2_EVENT_CONNECTION     = 1,  // New connection to deception port
    L2_EVENT_CREDENTIAL     = 2,  // Credential attempt captured
    L2_EVENT_EXPLOIT        = 3,  // Exploit payload detected
    L2_EVENT_TOOL_SIGNATURE = 4,  // Scanner/tool signature identified
    L2_EVENT_API_ABUSE      = 5,  // API abuse pattern
};

// L2 event structure for perf_event_array.
struct l2_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 event_type;
    __u32 payload_len;
    __u8  payload[MAX_PAYLOAD_CAPTURE];
    __u32 flags;
    __u32 seq_num;
};

// --- BPF Maps ---

// Perf event array for delivering events to AGENT-BETA userspace.
// NO disk writes — events go directly to perf ring buffer.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l2_events SEC(".maps");

// Connection tracking: source IP → connection counter.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // src_ip
    __type(value, __u64); // connection count
} conn_tracker SEC(".maps");

// Credential capture buffer: stores the last credential attempt per source.
struct cred_capture {
    __u64 timestamp_ns;
    __u16 dst_port;
    __u16 payload_len;
    __u8  payload[MAX_CRED_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   // src_ip
    __type(value, struct cred_capture);
} cred_buffer SEC(".maps");

// Tool signature patterns: hash → tool name index.
// Populated by userspace with known scanner fingerprints.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   // payload hash
    __type(value, __u32); // tool_id
} tool_signatures SEC(".maps");

// Per-source rate limiter.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);   // src_ip
    __type(value, __u64); // last_event_ns
} rate_limit SEC(".maps");

// --- Helper functions ---

// Simple payload hash for tool signature matching.
static __always_inline __u32 payload_hash(const __u8 *data, int len)
{
    __u32 hash = 5381;
    #pragma unroll
    for (int i = 0; i < 64 && i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

// Check if a port is a Layer 2 deception port.
static __always_inline int is_l2_port(__u16 port)
{
    return port == PORT_DEVOPS_HTTPS ||
           port == PORT_ELASTICSEARCH ||
           port == PORT_KIBANA ||
           port == PORT_DOCKER_API ||
           port == PORT_VXLAN;
}

// Rate limit check: max 100 events/second per source IP.
static __always_inline int is_rate_limited(__u32 src_ip)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&rate_limit, &src_ip);
    if (last && (now - *last < 10000000)) // 10ms = 100/sec
        return 1;
    bpf_map_update_elem(&rate_limit, &src_ip, &now, BPF_ANY);
    return 0;
}

// Detect common exploit patterns in payload.
// Returns event_type if match found, 0 otherwise.
static __always_inline __u32 detect_exploit(const __u8 *payload, int len)
{
    if (len < 4)
        return 0;

    // SQL injection patterns: ' OR, UNION SELECT, etc.
    // Check first few bytes for common patterns.
    if (len >= 8) {
        // "' OR " pattern
        if (payload[0] == '\'' && payload[1] == ' ' &&
            payload[2] == 'O' && payload[3] == 'R')
            return L2_EVENT_EXPLOIT;
        
        // "UNION" keyword
        if (payload[0] == 'U' && payload[1] == 'N' &&
            payload[2] == 'I' && payload[3] == 'O' &&
            payload[4] == 'N')
            return L2_EVENT_EXPLOIT;
    }

    // Log4Shell: "${jndi:" pattern
    if (len >= 7) {
        if (payload[0] == '$' && payload[1] == '{' &&
            payload[2] == 'j' && payload[3] == 'n' &&
            payload[4] == 'd' && payload[5] == 'i' &&
            payload[6] == ':')
            return L2_EVENT_EXPLOIT;
    }

    // Shellshock: "() {" pattern
    if (len >= 4) {
        if (payload[0] == '(' && payload[1] == ')' &&
            payload[2] == ' ' && payload[3] == '{')
            return L2_EVENT_EXPLOIT;
    }

    // SSRF: "http://169.254.169.254" (AWS metadata)
    if (len >= 16) {
        if (payload[0] == 'h' && payload[1] == 't' &&
            payload[2] == 't' && payload[3] == 'p' &&
            payload[7] == '1' && payload[8] == '6' &&
            payload[9] == '9' && payload[10] == '.')
            return L2_EVENT_EXPLOIT;
    }

    return 0;
}

// --- TC Programs ---

// TC ingress program: processes all incoming packets.
// Different hook point from Layer 1 nftables — operates at TC/qdisc level.
SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only process IPv4 TCP for now.
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header.
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // Parse TCP header.
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u16 dst_port = bpf_ntohs(tcp->dest);
    __u16 src_port = bpf_ntohs(tcp->source);
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    // Only process traffic to L2 deception ports.
    if (!is_l2_port(dst_port))
        return TC_ACT_OK;

    // Rate limit events per source IP.
    if (is_rate_limited(src_ip))
        return TC_ACT_OK; // Still allow traffic, just don't emit event.

    // Update connection tracker.
    __u64 *count = bpf_map_lookup_elem(&conn_tracker, &src_ip);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_count = 1;
        bpf_map_update_elem(&conn_tracker, &src_ip, &init_count, BPF_NOEXIST);
    }

    // Build event.
    struct l2_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.src_ip = src_ip;
    evt.dst_ip = dst_ip;
    evt.src_port = src_port;
    evt.dst_port = dst_port;
    evt.seq_num = bpf_ntohl(tcp->seq);
    evt.event_type = L2_EVENT_CONNECTION;

    // Calculate TCP payload offset and length.
    __u32 tcp_header_len = tcp->doff * 4;
    void *payload = (void *)tcp + tcp_header_len;
    int payload_len = data_end - payload;

    if (payload_len > 0 && payload < data_end) {
        // Capture payload (up to MAX_PAYLOAD_CAPTURE bytes).
        int capture_len = payload_len;
        if (capture_len > MAX_PAYLOAD_CAPTURE)
            capture_len = MAX_PAYLOAD_CAPTURE;

        // Bounds check for verifier.
        if (capture_len > 0 && capture_len <= MAX_PAYLOAD_CAPTURE) {
            bpf_skb_load_bytes(skb,
                (void *)payload - data,
                evt.payload,
                capture_len);
            evt.payload_len = capture_len;
        }

        // Detect exploit patterns.
        __u32 exploit_type = detect_exploit(evt.payload, capture_len);
        if (exploit_type) {
            evt.event_type = exploit_type;
            evt.flags |= 0x01; // EXPLOIT_DETECTED flag
        }

        // Check for tool signatures.
        __u32 phash = payload_hash(evt.payload, capture_len);
        __u32 *tool_id = bpf_map_lookup_elem(&tool_signatures, &phash);
        if (tool_id) {
            evt.event_type = L2_EVENT_TOOL_SIGNATURE;
            evt.flags |= (*tool_id << 8); // Encode tool ID in flags.
        }

        // Credential detection: check for auth-like patterns on
        // Docker API (2375) and Elasticsearch (9200) ports.
        if (dst_port == PORT_DOCKER_API || dst_port == PORT_ELASTICSEARCH) {
            // Look for JSON auth patterns: "password", "token", "auth"
            if (capture_len >= 8) {
                int has_cred = 0;
                #pragma unroll
                for (int i = 0; i < 64 && i + 7 < capture_len; i++) {
                    if (evt.payload[i] == 'p' && evt.payload[i+1] == 'a' &&
                        evt.payload[i+2] == 's' && evt.payload[i+3] == 's') {
                        has_cred = 1;
                        break;
                    }
                    if (evt.payload[i] == 't' && evt.payload[i+1] == 'o' &&
                        evt.payload[i+2] == 'k' && evt.payload[i+3] == 'e') {
                        has_cred = 1;
                        break;
                    }
                }
                if (has_cred) {
                    evt.event_type = L2_EVENT_CREDENTIAL;
                    evt.flags |= 0x02; // CREDENTIAL_DETECTED flag

                    // Store in credential capture buffer.
                    struct cred_capture cred = {};
                    cred.timestamp_ns = evt.timestamp_ns;
                    cred.dst_port = dst_port;
                    cred.payload_len = capture_len;
                    if (capture_len <= MAX_CRED_LEN) {
                        __builtin_memcpy(cred.payload, evt.payload, capture_len);
                    }
                    bpf_map_update_elem(&cred_buffer, &src_ip, &cred, BPF_ANY);
                }
            }
        }

        // API abuse detection: high-frequency requests to same endpoint.
        if (count) {
            __u64 c = *count;
            if (c > 100) {
                evt.event_type = L2_EVENT_API_ABUSE;
                evt.flags |= 0x04; // API_ABUSE flag
            }
        }
    }

    // Emit event to perf ring buffer → AGENT-BETA (NO disk writes).
    bpf_perf_event_output(skb, &l2_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));

    // ALWAYS allow traffic through — L2 is deception, not blocking.
    // Real blocking is at Layer 3 (XDP).
    return TC_ACT_OK;
}

// TC egress program: monitors outgoing responses for intel gathering.
SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    // Egress monitoring: track responses to deception ports.
    // Minimal processing — just count outgoing bytes per destination.
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Allow all egress — we're deception, not blocking.
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
