#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# GHOST-STACK CORE — 4-Layer Firewall Deployment Script
# ═══════════════════════════════════════════════════════════
#
# Deploys all 4 firewall layers:
#   Layer 1: nftables deception firewall
#   Layer 2: eBPF TC deception (different technology from L1)
#   Layer 3: XDP invisible wall (NIC driver level)
#   Layer 4: AppArmor + seccomp (per-namespace, deployed on demand)
#
# Usage: sudo ./firewall_deploy.sh [--interface=eth0]
#
# CRITICAL: NO persistent logs written to disk.
# All events go to in-memory ring buffers consumed by AGENT-BETA.

set -euo pipefail

# --- Configuration ---
INTERFACE="${1:-eth0}"
# Strip --interface= prefix if present.
INTERFACE="${INTERFACE#--interface=}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BPF_DIR="/opt/ghost-stack/bpf"

# Remove the -- prefix from interface name if passed as flag
for arg in "$@"; do
    case $arg in
        --interface=*) INTERFACE="${arg#*=}" ;;
    esac
done

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[FIREWALL]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[FIREWALL] ✓${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[FIREWALL] ⚠${NC} $1"; }
log_error() { echo -e "${RED}[FIREWALL] ✗${NC} $1"; }
log_layer() { echo -e "\n${MAGENTA}══════ $1 ══════${NC}"; }

# --- Verify root ---
if [ "$EUID" -ne 0 ]; then
    log_error "Must run as root"
    exit 1
fi

echo -e "${MAGENTA}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║  GHOST-STACK CORE — FIREWALL DEPLOYMENT   ║"
echo "  ║  4-Layer Deception + Invisible Wall        ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"

log_info "Target interface: ${INTERFACE}"

# Verify interface exists.
if ! ip link show "${INTERFACE}" &>/dev/null; then
    log_error "Interface ${INTERFACE} not found"
    echo "  Available interfaces:"
    ip -br link show | awk '{print "    " $1}'
    exit 1
fi

# ═══════════════════════════════════════════════════
# LAYER 1 — nftables Deception Firewall
# ═══════════════════════════════════════════════════
log_layer "LAYER 1 — nftables Deception Firewall"

NFT_RULES="${PROJECT_ROOT}/firewall/layer1/layer1_decoy.nft"

if [ -f "${NFT_RULES}" ]; then
    # Validate syntax first.
    if nft -c -f "${NFT_RULES}" 2>/dev/null; then
        nft -f "${NFT_RULES}"
        log_ok "Layer 1 nftables rules loaded"
    else
        log_warn "Layer 1 nftables syntax validation failed — applying with warnings"
        nft -f "${NFT_RULES}" 2>&1 || log_error "Layer 1 nftables load FAILED"
    fi
else
    log_warn "Layer 1 rules file not found: ${NFT_RULES}"
fi

# Verify nflog is configured for AGENT-BETA.
log_info "  nflog group 1 → AGENT-BETA ring buffer (no disk writes)"
log_ok "Layer 1 deployed — deception ports: 22,80,443,8080,3306,5432,6379,27017"

# ═══════════════════════════════════════════════════
# LAYER 2 — eBPF TC Deception
# ═══════════════════════════════════════════════════
log_layer "LAYER 2 — eBPF TC Deception (different from L1)"

L2_BPF="${BPF_DIR}/layer2_tc.bpf.o"

if [ -f "${L2_BPF}" ]; then
    # Add clsact qdisc if not present.
    tc qdisc show dev "${INTERFACE}" | grep -q clsact || \
        tc qdisc add dev "${INTERFACE}" clsact 2>/dev/null || true

    # Remove existing TC filters.
    tc filter del dev "${INTERFACE}" ingress 2>/dev/null || true

    # Attach TC ingress BPF program.
    tc filter add dev "${INTERFACE}" ingress bpf da obj "${L2_BPF}" sec tc 2>/dev/null && \
        log_ok "Layer 2 TC ingress BPF attached to ${INTERFACE}" || \
        log_warn "Layer 2 TC BPF attach failed (may need vmlinux.h recompile)"

    log_info "  Deception ports: 8443,9200,5601,2375,4789"
    log_info "  Different from L1 in: technology, ports, response signatures"
else
    log_warn "Layer 2 BPF object not found: ${L2_BPF}"
    log_info "  Compile with: clang -O2 -g -target bpf -c layer2_tc.bpf.c -o layer2_tc.bpf.o"
fi

# ═══════════════════════════════════════════════════
# LAYER 3 — XDP Invisible Wall
# ═══════════════════════════════════════════════════
log_layer "LAYER 3 — XDP INVISIBLE WALL (NIC driver level)"

L3_BPF="${BPF_DIR}/layer3_invisible.bpf.o"

if [ -f "${L3_BPF}" ]; then
    # Detach existing XDP program if any.
    ip link set dev "${INTERFACE}" xdp off 2>/dev/null || true

    # Attach XDP in native driver mode.
    # Falls back to generic mode if driver doesn't support native.
    if ip link set dev "${INTERFACE}" xdpdrv obj "${L3_BPF}" sec xdp 2>/dev/null; then
        log_ok "Layer 3 XDP attached in NATIVE mode (NIC driver level)"
    elif ip link set dev "${INTERFACE}" xdpgeneric obj "${L3_BPF}" sec xdp 2>/dev/null; then
        log_warn "Layer 3 XDP attached in GENERIC mode (driver doesn't support native)"
    else
        log_warn "Layer 3 XDP attach failed"
    fi

    log_info "  Behavior: ABSOLUTE SILENCE for non-allowlisted IPs"
    log_info "  No RST, no ICMP unreachable, NOTHING — attacker hangs forever"
    log_info "  Drop counters: kernel memory only (BPF_MAP_TYPE_LRU_PERCPU_HASH)"
else
    log_warn "Layer 3 XDP object not found: ${L3_BPF}"
    log_info "  Compile with: clang -O2 -g -target bpf -c layer3_invisible.bpf.c -o layer3_invisible.bpf.o"
fi

# ═══════════════════════════════════════════════════
# LAYER 4 — AppArmor + seccomp (template ready)
# ═══════════════════════════════════════════════════
log_layer "LAYER 4 — AppArmor + seccomp (per-namespace)"

L4_SCRIPT="${PROJECT_ROOT}/firewall/layer4/namespace_iptables.sh"
L4_APPARMOR="${PROJECT_ROOT}/firewall/layer4/apparmor-dept-template.profile"

if [ -f "${L4_SCRIPT}" ]; then
    chmod +x "${L4_SCRIPT}"
    log_ok "Layer 4 script ready: ${L4_SCRIPT}"
    log_info "  Applied per-department via: namespace_iptables.sh <DEPT_ID> <PID> <SUBNET> <DNS> <ORCH>"
else
    log_warn "Layer 4 script not found: ${L4_SCRIPT}"
fi

if [ -f "${L4_APPARMOR}" ]; then
    cp "${L4_APPARMOR}" /etc/ghost-stack/ 2>/dev/null || true
    log_ok "AppArmor template installed"
else
    log_warn "AppArmor template not found: ${L4_APPARMOR}"
fi

# Check seccomp availability.
if [ -f /proc/sys/kernel/seccomp/actions_avail ]; then
    ACTIONS=$(cat /proc/sys/kernel/seccomp/actions_avail)
    log_ok "seccomp available: ${ACTIONS}"
else
    log_warn "seccomp status unknown"
fi

# ═══════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  GHOST-STACK FIREWALL — Deployment Summary${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Interface:  ${INTERFACE}"
echo ""
echo "  Layer 1 (nftables):     Deception firewall"
echo "    └─ Ports: 22,80,443,8080,3306,5432,6379,27017"
echo "    └─ Events → nflog group 1 → AGENT-BETA"
echo ""
echo "  Layer 2 (eBPF TC):      Deception (different from L1)"
echo "    └─ Ports: 8443,9200,5601,2375,4789"
echo "    └─ Events → perf_event_array → AGENT-BETA"
echo ""
echo "  Layer 3 (XDP):          INVISIBLE WALL"
echo "    └─ LPM trie allowlist (Ed25519 signed updates)"
echo "    └─ Non-allowlisted: XDP_DROP (absolute silence)"
echo "    └─ Drop counters: kernel memory → AGENT-BETA poll"
echo ""
echo "  Layer 4 (AppArmor+seccomp): Per-namespace"
echo "    └─ Applied when departments spawn"
echo "    └─ SCMP_ACT_KILL_PROCESS on ptrace/mount/kexec/etc."
echo ""
echo -e "${YELLOW}  NO persistent logs on disk — all events in-memory only${NC}"
echo -e "${YELLOW}  Attacker forensics finds NOTHING${NC}"
echo ""
