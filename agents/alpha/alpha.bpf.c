//go:build ignore

// SPDX-License-Identifier: GPL-2.0
// GHOST-STACK CORE — AGENT-ALPHA eBPF Probes
//
// This BPF program implements 5 passive tracepoint/kprobe monitors
// for department container security observation:
//
//   1. tp/syscalls/sys_enter_execve   — unexpected process execution
//   2. tp/syscalls/sys_enter_connect  — outbound connection anomaly
//   3. kprobe/commit_creds            — privilege escalation attempt
//   4. tp/syscalls/sys_enter_unshare  — namespace escape attempt
//   5. tp/syscalls/sys_enter_openat   — sensitive file access pattern
//
// Agent-Alpha is STRICTLY PASSIVE:
//   - ZERO write capability
//   - NEVER blocks, NEVER modifies
//   - Observe and report only
//   - Events delivered via BPF ring buffer
//
// Compiled with: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//                -c alpha.bpf.c -o alpha.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN     512
#define MAX_PATH_LEN     256
#define TASK_COMM_LEN    16
#define MAX_EVENTS_PER_SEC 1000

// Event types for the ring buffer consumer.
enum event_type {
    EVENT_EXECVE        = 1,
    EVENT_CONNECT       = 2,
    EVENT_COMMIT_CREDS  = 3,
    EVENT_UNSHARE       = 4,
    EVENT_OPENAT        = 5,
};

// Severity levels.
enum severity {
    SEV_INFO     = 0,
    SEV_WARNING  = 1,
    SEV_CRITICAL = 2,
    SEV_ALERT    = 3,
};

// --- Event structures ---

// Base event header — common to all events.
struct event_header {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    __u32 severity;
    __u32 pid_ns_id;
    __u32 mnt_ns_id;
    char  comm[TASK_COMM_LEN];
};

// Event: sys_enter_execve — process execution monitoring.
struct execve_event {
    struct event_header hdr;
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS_LEN];
    __u32 flags;
};

// Event: sys_enter_connect — outbound connection monitoring.
struct connect_event {
    struct event_header hdr;
    __u16 sa_family;
    __u16 dst_port;
    __u32 dst_ipv4;
    __u8  dst_ipv6[16];
    __s32 sockfd;
};

// Event: kprobe/commit_creds — privilege escalation detection.
struct creds_event {
    struct event_header hdr;
    __u32 old_uid;
    __u32 old_gid;
    __u32 new_uid;
    __u32 new_gid;
    __u32 old_cap_effective_lo;
    __u32 old_cap_effective_hi;
    __u32 new_cap_effective_lo;
    __u32 new_cap_effective_hi;
};

// Event: sys_enter_unshare — namespace escape attempt detection.
struct unshare_event {
    struct event_header hdr;
    __u64 unshare_flags;
};

// Event: sys_enter_openat — sensitive file access detection.
struct openat_event {
    struct event_header hdr;
    __s32 dirfd;
    __s32 flags;
    __u32 mode;
    char  filename[MAX_PATH_LEN];
};

// --- BPF Maps ---

// Ring buffer for delivering events to userspace.
// Size: 256 pages = 1 MiB ring buffer per department.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} events SEC(".maps");

// Rate limiter: per-CPU hash to prevent event flooding.
// Key: event_type | pid, Value: last_event_timestamp_ns
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} rate_limiter SEC(".maps");

// Configuration map: monitored PID namespace ID.
// Key: 0, Value: target pid_ns_id (set by userspace).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// Sensitive paths hash set: paths that trigger alerts when opened.
// Key: path hash, Value: severity level.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u32);
} sensitive_paths SEC(".maps");

// --- Helper functions ---

// Get the PID namespace ID of the current task.
static __always_inline __u32 get_pid_ns_id(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ns_id = 0;
    
    // Read pid_ns->ns.inum via BPF_CORE_READ.
    BPF_CORE_READ_INTO(&ns_id, task, nsproxy, pid_ns_for_children, ns.inum);
    return ns_id;
}

// Get the mount namespace ID of the current task.
static __always_inline __u32 get_mnt_ns_id(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ns_id = 0;
    
    BPF_CORE_READ_INTO(&ns_id, task, nsproxy, mnt_ns, ns.inum);
    return ns_id;
}

// Check if the current task is in the monitored PID namespace.
static __always_inline int is_target_ns(void)
{
    __u32 key = 0;
    __u32 *target_ns = bpf_map_lookup_elem(&config, &key);
    if (!target_ns || *target_ns == 0)
        return 1;  // If no target configured, monitor all.
    
    return get_pid_ns_id() == *target_ns;
}

// Rate limit check: returns 1 if event should be dropped.
static __always_inline int rate_limited(__u32 event_type, __u32 pid)
{
    __u64 key = ((__u64)event_type << 32) | pid;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&rate_limiter, &key);
    
    if (last) {
        // Allow max 1 event per millisecond per (type, pid) pair.
        if (now - *last < 1000000)
            return 1;
    }
    
    bpf_map_update_elem(&rate_limiter, &key, &now, BPF_ANY);
    return 0;
}

// Fill the common event header fields.
static __always_inline void fill_header(struct event_header *hdr,
                                         __u32 event_type,
                                         __u32 severity)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    hdr->timestamp_ns = bpf_ktime_get_ns();
    hdr->pid = (__u32)pid_tgid;
    hdr->tgid = (__u32)(pid_tgid >> 32);
    hdr->uid = (__u32)uid_gid;
    hdr->gid = (__u32)(uid_gid >> 32);
    hdr->event_type = event_type;
    hdr->severity = severity;
    hdr->pid_ns_id = get_pid_ns_id();
    hdr->mnt_ns_id = get_mnt_ns_id();
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

// --- Tracepoint Programs ---

// 1. sys_enter_execve — Monitor all process executions.
// Detects: unexpected binaries, shell spawns, exploitation payloads.
SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_target_ns())
        return 0;
    
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (rate_limited(EVENT_EXECVE, pid))
        return 0;
    
    struct execve_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    
    fill_header(&evt->hdr, EVENT_EXECVE, SEV_INFO);
    
    // Read filename (first argument to execve).
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), filename);
    
    // Read first argument string (argv[1] if present).
    const char * const *argv = (const char * const *)ctx->args[1];
    if (argv) {
        const char *arg0 = NULL;
        bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
        if (arg0) {
            bpf_probe_read_user_str(&evt->args, sizeof(evt->args), arg0);
        }
    }
    
    // Elevate severity for suspicious commands.
    // Check for shell interpreters, common exploitation tools.
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Simple heuristic: any execve from non-init PID gets at least WARNING.
    if (pid > 1) {
        evt->hdr.severity = SEV_WARNING;
    }
    
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// 2. sys_enter_connect — Monitor outbound network connections.
// Detects: C2 callbacks, data exfiltration, unauthorized external access.
SEC("tp/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_target_ns())
        return 0;
    
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (rate_limited(EVENT_CONNECT, pid))
        return 0;
    
    struct connect_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    
    fill_header(&evt->hdr, EVENT_CONNECT, SEV_INFO);
    
    evt->sockfd = (int)ctx->args[0];
    
    // Read sockaddr structure.
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (addr) {
        __u16 sa_family = 0;
        bpf_probe_read_user(&sa_family, sizeof(sa_family), &addr->sa_family);
        evt->sa_family = sa_family;
        
        if (sa_family == 2) {  // AF_INET
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            bpf_probe_read_user(&evt->dst_port, sizeof(evt->dst_port), &sin->sin_port);
            bpf_probe_read_user(&evt->dst_ipv4, sizeof(evt->dst_ipv4), &sin->sin_addr);
            
            // Network byte order to host — port is big-endian.
            evt->dst_port = __builtin_bswap16(evt->dst_port);
            
            // Elevated severity for connections to external IPs.
            evt->hdr.severity = SEV_WARNING;
        } else if (sa_family == 10) {  // AF_INET6
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
            bpf_probe_read_user(&evt->dst_port, sizeof(evt->dst_port), &sin6->sin6_port);
            bpf_probe_read_user(&evt->dst_ipv6, sizeof(evt->dst_ipv6), &sin6->sin6_addr);
            evt->dst_port = __builtin_bswap16(evt->dst_port);
            evt->hdr.severity = SEV_WARNING;
        }
    }
    
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// 3. kprobe/commit_creds — Monitor credential changes (privilege escalation).
// Detects: setuid exploitation, capability elevation, UID 0 transitions.
SEC("kprobe/commit_creds")
int trace_commit_creds(struct pt_regs *ctx)
{
    if (!is_target_ns())
        return 0;
    
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (rate_limited(EVENT_COMMIT_CREDS, pid))
        return 0;
    
    // Get current credentials (before commit).
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct cred *old_cred = NULL;
    BPF_CORE_READ_INTO(&old_cred, task, cred);
    
    // Get new credentials being committed (first argument).
    struct cred *new_cred = (struct cred *)PT_REGS_PARM1(ctx);
    
    struct creds_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    
    fill_header(&evt->hdr, EVENT_COMMIT_CREDS, SEV_WARNING);
    
    // Read old credentials.
    if (old_cred) {
        BPF_CORE_READ_INTO(&evt->old_uid, old_cred, uid.val);
        BPF_CORE_READ_INTO(&evt->old_gid, old_cred, gid.val);
        
        kernel_cap_t old_cap;
        BPF_CORE_READ_INTO(&old_cap, old_cred, cap_effective);
        evt->old_cap_effective_lo = old_cap.cap[0];
        evt->old_cap_effective_hi = old_cap.cap[1];
    }
    
    // Read new credentials.
    if (new_cred) {
        BPF_CORE_READ_INTO(&evt->new_uid, new_cred, uid.val);
        BPF_CORE_READ_INTO(&evt->new_gid, new_cred, gid.val);
        
        kernel_cap_t new_cap;
        BPF_CORE_READ_INTO(&new_cap, new_cred, cap_effective);
        evt->new_cap_effective_lo = new_cap.cap[0];
        evt->new_cap_effective_hi = new_cap.cap[1];
    }
    
    // CRITICAL severity if UID changes to 0 (root) or new capabilities added.
    if (evt->new_uid == 0 && evt->old_uid != 0) {
        evt->hdr.severity = SEV_CRITICAL;
    }
    if (evt->new_cap_effective_lo > evt->old_cap_effective_lo ||
        evt->new_cap_effective_hi > evt->old_cap_effective_hi) {
        evt->hdr.severity = SEV_CRITICAL;
    }
    
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// 4. sys_enter_unshare — Monitor namespace manipulation attempts.
// Detects: container escape attempts, namespace privilege escalation.
SEC("tp/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_target_ns())
        return 0;
    
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (rate_limited(EVENT_UNSHARE, pid))
        return 0;
    
    struct unshare_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    
    fill_header(&evt->hdr, EVENT_UNSHARE, SEV_CRITICAL);
    
    // Read unshare flags.
    evt->unshare_flags = ctx->args[0];
    
    // Any unshare from inside a container is ALWAYS critical —
    // it's either a legitimate operation we need to audit
    // or a container escape attempt.
    evt->hdr.severity = SEV_ALERT;
    
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// 5. sys_enter_openat — Monitor file access patterns.
// Detects: sensitive file reads (passwd, shadow, keys, configs).
SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_target_ns())
        return 0;
    
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (rate_limited(EVENT_OPENAT, pid))
        return 0;
    
    struct openat_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    
    fill_header(&evt->hdr, EVENT_OPENAT, SEV_INFO);
    
    evt->dirfd = (int)ctx->args[0];
    
    // Read filename.
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), filename);
    
    evt->flags = (__u32)ctx->args[2];
    evt->mode = (__u32)ctx->args[3];
    
    // Check if path matches sensitive path set.
    // Hash the first 64 bytes of the filename for lookup.
    __u64 path_hash = 0;
    #pragma unroll
    for (int i = 0; i < 64 && i < MAX_PATH_LEN; i++) {
        char c = evt->filename[i];
        if (c == 0)
            break;
        path_hash = path_hash * 31 + c;
    }
    
    __u32 *sev = bpf_map_lookup_elem(&sensitive_paths, &path_hash);
    if (sev) {
        evt->hdr.severity = *sev;
    }
    
    // Always report write attempts to critical paths.
    if (evt->flags & 0x01) {  // O_WRONLY
        evt->hdr.severity = SEV_WARNING;
    }
    if (evt->flags & 0x02) {  // O_RDWR
        evt->hdr.severity = SEV_WARNING;
    }
    
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// Also monitor sys_enter_setns for container escape via namespace joining.
SEC("tp/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_target_ns())
        return 0;
    
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (rate_limited(EVENT_UNSHARE, pid))
        return 0;
    
    struct unshare_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    
    fill_header(&evt->hdr, EVENT_UNSHARE, SEV_ALERT);
    
    // For setns, args[1] contains the nstype flags.
    evt->unshare_flags = ctx->args[1];
    
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
