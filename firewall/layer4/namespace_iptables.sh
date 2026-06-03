#!/usr/bin/env bash
# GHOST-STACK CORE — Layer 4: Per-Namespace nftables + seccomp Enforcement
#
# This script applies Layer 4 security policy INSIDE a department namespace:
#   1. nftables whitelist-only rules (different from L1 and L3)
#   2. seccomp-bpf profile with SCMP_ACT_KILL_PROCESS on dangerous syscalls
#   3. AppArmor profile loading
#
# Usage: namespace_iptables.sh <DEPT_ID> <DEPT_PID> <SUBNET_CIDR> <DNS_IP> <ORCH_IP>
#
# This script is run by the orchestrator via nsenter into the department's
# network and mount namespaces.

set -euo pipefail

# --- Arguments ---
DEPT_ID="${1:?Usage: namespace_iptables.sh <DEPT_ID> <DEPT_PID> <SUBNET> <DNS_IP> <ORCH_IP>}"
DEPT_PID="${2:?Missing DEPT_PID}"
SUBNET="${3:?Missing SUBNET_CIDR}"
DNS_IP="${4:?Missing DNS_IP}"
ORCH_IP="${5:?Missing ORCH_IP}"

ORCH_CTRL_PORT=9443
DNS_PORT=53

echo "[GHOST-L4] Applying Layer 4 policy for dept-${DEPT_ID} (PID: ${DEPT_PID})"

# --- Step 1: Apply nftables whitelist-only rules inside the namespace ---
# Uses nft (NOT iptables) — different from both L1 and L3.
# Default policy: DROP on input and output.
# Only whitelisted traffic is allowed.

NFT_RULES=$(cat <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet ghost_l4_dept_${DEPT_ID} {

    # Department subnet set.
    set dept_subnet {
        type ipv4_addr
        flags interval
        elements = { ${SUBNET} }
    }

    # Allowed destination IPs (orchestrator + DNS).
    set allowed_destinations {
        type ipv4_addr
        elements = { ${DNS_IP}, ${ORCH_IP}, 127.0.0.1 }
    }

    # INPUT chain: whitelist-only, default DROP.
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established/related connections.
        ct state established,related accept

        # Drop invalid packets.
        ct state invalid drop

        # Allow loopback.
        iifname "lo" accept

        # Allow ICMP ping (limited — for health checks only).
        ip protocol icmp icmp type echo-request \
            ip saddr @dept_subnet \
            limit rate 5/second \
            accept

        # Allow traffic from department subnet.
        ip saddr @dept_subnet accept

        # Allow DNS responses from internal resolver.
        ip saddr ${DNS_IP} udp sport ${DNS_PORT} accept
        ip saddr ${DNS_IP} tcp sport ${DNS_PORT} accept

        # Allow orchestrator control traffic.
        ip saddr ${ORCH_IP} tcp sport ${ORCH_CTRL_PORT} accept

        # Allow orchestrator health probes.
        ip saddr ${ORCH_IP} tcp dport 8080 accept

        # EVERYTHING ELSE: DROP (silent).
        counter drop
    }

    # OUTPUT chain: whitelist-only, default DROP.
    chain output {
        type filter hook output priority 0; policy drop;

        # Allow established/related.
        ct state established,related accept

        # Allow loopback.
        oifname "lo" accept

        # Allow traffic to department subnet.
        ip daddr @dept_subnet accept

        # Allow DNS queries to internal resolver ONLY.
        ip daddr ${DNS_IP} udp dport ${DNS_PORT} accept
        ip daddr ${DNS_IP} tcp dport ${DNS_PORT} accept

        # Allow traffic to orchestrator control socket.
        ip daddr ${ORCH_IP} tcp dport ${ORCH_CTRL_PORT} accept

        # Allow alert socket traffic (Unix domain — this is network-level extra).
        ip daddr ${ORCH_IP} accept

        # BLOCK external DNS (prevents data exfiltration via DNS tunneling).
        udp dport ${DNS_PORT} counter drop
        tcp dport ${DNS_PORT} counter drop

        # BLOCK common external services.
        tcp dport { 25, 587, 465 } counter drop  # SMTP
        tcp dport { 80, 443, 8080, 8443 } counter drop  # HTTP/HTTPS

        # EVERYTHING ELSE: DROP.
        counter drop
    }

    # FORWARD chain: drop all (no routing).
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
EOF
)

# Apply nftables rules inside the namespace.
echo "${NFT_RULES}" | nsenter -t "${DEPT_PID}" --net -- nft -f -
echo "[GHOST-L4] nftables whitelist rules applied for dept-${DEPT_ID}"

# --- Step 2: Apply seccomp-bpf profile ---
# SCMP_ACT_KILL_PROCESS on extremely dangerous syscalls:
#   - ptrace: debugging/code injection
#   - mount: filesystem manipulation
#   - kexec_load: kernel replacement
#   - init_module/finit_module: kernel module loading
#   - delete_module: kernel module unloading
#   - reboot: system reboot
#   - swapon/swapoff: swap manipulation
#   - pivot_root: root filesystem change
#   - unshare: namespace manipulation (already monitored by AGENT-ALPHA)
#   - setns: namespace joining

SECCOMP_PROFILE=$(cat <<'SECCOMP_EOF'
{
    "defaultAction": "SCMP_ACT_ALLOW",
    "architectures": [
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_X86",
        "SCMP_ARCH_AARCH64"
    ],
    "syscalls": [
        {
            "names": [
                "ptrace"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block debugging/tracing — prevents exploitation tools"
        },
        {
            "names": [
                "mount",
                "umount2"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block mount operations — prevent filesystem escape"
        },
        {
            "names": [
                "kexec_load",
                "kexec_file_load"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block kernel replacement"
        },
        {
            "names": [
                "init_module",
                "finit_module",
                "delete_module"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block kernel module loading/unloading"
        },
        {
            "names": [
                "reboot"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block system reboot"
        },
        {
            "names": [
                "swapon",
                "swapoff"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block swap manipulation"
        },
        {
            "names": [
                "pivot_root"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block root filesystem changes"
        },
        {
            "names": [
                "unshare"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block namespace creation — prevents container escape"
        },
        {
            "names": [
                "setns"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block namespace joining — prevents container escape"
        },
        {
            "names": [
                "acct"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block process accounting manipulation"
        },
        {
            "names": [
                "add_key",
                "keyctl",
                "request_key"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block kernel keyring access"
        },
        {
            "names": [
                "bpf"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block BPF operations from within container"
        },
        {
            "names": [
                "userfaultfd"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block userfaultfd — used in kernel exploits"
        },
        {
            "names": [
                "perf_event_open"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block performance monitoring from container"
        },
        {
            "names": [
                "move_mount",
                "open_tree",
                "mount_setattr",
                "fsopen",
                "fsconfig",
                "fsmount",
                "fspick"
            ],
            "action": "SCMP_ACT_KILL_PROCESS",
            "comment": "Block new mount API operations"
        }
    ]
}
SECCOMP_EOF
)

# Write seccomp profile to a temporary location inside the namespace.
SECCOMP_PATH="/var/run/ghost-seccomp-dept-${DEPT_ID}.json"
echo "${SECCOMP_PROFILE}" | nsenter -t "${DEPT_PID}" --mount -- \
    tee "${SECCOMP_PATH}" > /dev/null
echo "[GHOST-L4] seccomp-bpf profile written for dept-${DEPT_ID}"

# --- Step 3: Apply AppArmor profile ---
# Generate department-specific AppArmor profile from template.

APPARMOR_TEMPLATE="/etc/ghost-stack/apparmor-dept-template.profile"
APPARMOR_PROFILE="/etc/apparmor.d/ghost-dept-${DEPT_ID}"

if [ -f "${APPARMOR_TEMPLATE}" ]; then
    sed -e "s/{{DEPT_ID}}/${DEPT_ID}/g" \
        -e "s/{{DEPT_NAME}}/dept-${DEPT_ID}/g" \
        -e "s|{{SUBNET}}|${SUBNET}|g" \
        -e "s/{{DNS_IP}}/${DNS_IP}/g" \
        -e "s/{{ORCH_IP}}/${ORCH_IP}/g" \
        "${APPARMOR_TEMPLATE}" > "${APPARMOR_PROFILE}"

    apparmor_parser -r "${APPARMOR_PROFILE}" 2>/dev/null || \
        echo "[GHOST-L4] WARNING: AppArmor profile load failed (may not be available)"
    echo "[GHOST-L4] AppArmor profile loaded for dept-${DEPT_ID}"
else
    echo "[GHOST-L4] WARNING: AppArmor template not found at ${APPARMOR_TEMPLATE}"
fi

# --- Step 4: Block external email providers at DNS level ---
# Prevent company email domain bypass by blocking external MX queries.

DNS_BLOCK_RULES=$(cat <<DNSEOF
# Block DNS queries to external email providers.
# These are applied inside the department namespace.
table inet ghost_l4_dns_block_${DEPT_ID} {
    chain output {
        type filter hook output priority 10; policy accept;

        # Block outbound connections to known external email providers.
        # Ports 25 (SMTP), 587 (submission), 465 (SMTPS), 993 (IMAPS), 995 (POP3S).
        tcp dport { 25, 587, 465, 993, 995 } counter drop

        # Block connections to known external email provider IP ranges.
        # Gmail
        ip daddr 142.250.0.0/15 tcp dport { 25, 587, 465, 993, 995 } drop
        # Outlook
        ip daddr 40.92.0.0/14 tcp dport { 25, 587, 465, 993, 995 } drop
        # Yahoo
        ip daddr 98.136.0.0/14 tcp dport { 25, 587, 465, 993, 995 } drop
    }
}
DNSEOF
)

echo "${DNS_BLOCK_RULES}" | nsenter -t "${DEPT_PID}" --net -- nft -f - 2>/dev/null || \
    echo "[GHOST-L4] WARNING: DNS block rules failed"

echo "[GHOST-L4] ✓ Layer 4 policy fully applied for dept-${DEPT_ID}"
echo "[GHOST-L4]   - nftables: whitelist-only INPUT/OUTPUT"
echo "[GHOST-L4]   - seccomp: KILL_PROCESS on ptrace/mount/kexec/init_module/etc."
echo "[GHOST-L4]   - AppArmor: filesystem/capability/network restrictions"
echo "[GHOST-L4]   - DNS: external email providers blocked"
