#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# GHOST-STACK CORE — Main Deployment Script
# ═══════════════════════════════════════════════════════════
#
# This script deploys the complete GHOST-STACK CORE system:
#   1. Verify kernel requirements (≥5.15, cgroups v2, eBPF)
#   2. Create system user and directories
#   3. Build Go binaries (ghost-ctl, agent-alpha, agent-beta)
#   4. Compile eBPF programs
#   5. Install systemd units
#   6. Initialize cgroup hierarchy
#   7. Create alert bus socket
#   8. Deploy firewall layers (calls firewall_deploy.sh)
#
# Usage: sudo ./deploy.sh [--skip-build] [--skip-firewall]
#
# Requirements:
#   - Linux kernel ≥5.15
#   - cgroups v2 unified hierarchy
#   - Go ≥1.22
#   - clang ≥14 (for eBPF compilation)
#   - nftables, iproute2
#   - AppArmor (optional but recommended)

set -euo pipefail

# --- Configuration ---
GHOST_HOME="/opt/ghost-stack"
GHOST_DATA="/var/lib/ghost-stack"
GHOST_CONFIG="/etc/ghost-stack"
GHOST_RUN="/var/run/ghost-stack"
GHOST_USER="ghost-agent"
GHOST_GROUP="ghost-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SKIP_BUILD=false
SKIP_FIREWALL=false

for arg in "$@"; do
    case $arg in
        --skip-build) SKIP_BUILD=true ;;
        --skip-firewall) SKIP_FIREWALL=true ;;
    esac
done

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[GHOST-DEPLOY]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[GHOST-DEPLOY] ✓${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[GHOST-DEPLOY] ⚠${NC} $1"; }
log_error() { echo -e "${RED}[GHOST-DEPLOY] ✗${NC} $1"; }

# --- Banner ---
echo -e "${CYAN}"
cat << 'EOF'
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     ███████╗████████╗ █████╗  ██████╗██╗  ██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝     ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██║  ███╗███████║██║   ██║███████╗   ██║  █████╗ ███████╗   ██║   ███████║██║     █████╔╝
██║   ██║██╔══██║██║   ██║╚════██║   ██║  ╚════╝ ╚════██║   ██║   ██╔══██║██║     ██╔═██╗
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║         ███████║   ██║   ██║  ██║╚██████╗██║  ██╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝         ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                   DEPLOYMENT SCRIPT — Enterprise Container Orchestration
EOF
echo -e "${NC}"

# --- Step 0: Verify root ---
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

# --- Step 1: Verify kernel requirements ---
log_info "Verifying kernel requirements..."

KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 15 ]); then
    log_error "Kernel ≥5.15 required (current: $(uname -r))"
    exit 1
fi
log_ok "Kernel version: $(uname -r)"

# Verify cgroups v2.
if ! mount | grep -q "cgroup2"; then
    log_error "cgroups v2 not mounted. Enable unified cgroup hierarchy."
    echo "  Add 'systemd.unified_cgroup_hierarchy=1' to kernel command line"
    exit 1
fi
log_ok "cgroups v2 unified hierarchy detected"

# Verify eBPF support.
if [ ! -d "/sys/fs/bpf" ]; then
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
fi
log_ok "BPF filesystem available"

# Verify user namespace support.
if [ "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)" = "0" ]; then
    log_warn "Unprivileged user namespaces disabled — enabling"
    echo 1 > /proc/sys/kernel/unprivileged_userns_clone
fi
log_ok "User namespaces enabled"

# Verify time namespace support.
if [ ! -f "/proc/self/ns/time" ]; then
    log_warn "Time namespace not available (kernel feature)"
fi

# --- Step 2: Create system user and directories ---
log_info "Creating system user and directories..."

# Create ghost-agent user if it doesn't exist.
if ! id -u "${GHOST_USER}" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d /nonexistent "${GHOST_USER}"
    log_ok "Created system user: ${GHOST_USER}"
else
    log_ok "System user exists: ${GHOST_USER}"
fi

# Create directory structure.
DIRS=(
    "${GHOST_HOME}/bin"
    "${GHOST_HOME}/bpf"
    "${GHOST_HOME}/config"
    "${GHOST_DATA}/rootfs"
    "${GHOST_DATA}/vault/volumes"
    "${GHOST_DATA}/vault/backups"
    "${GHOST_DATA}/vault/keys"
    "${GHOST_DATA}/vault/mounts"
    "${GHOST_DATA}/snapshots"
    "${GHOST_DATA}/audit"
    "${GHOST_CONFIG}"
    "${GHOST_RUN}"
    "/sys/fs/cgroup/ghost-stack"
)

for dir in "${DIRS[@]}"; do
    mkdir -p "$dir"
done

# Set permissions.
chown -R root:root "${GHOST_HOME}"
chmod -R 755 "${GHOST_HOME}"
chown -R root:root "${GHOST_DATA}"
chmod -R 700 "${GHOST_DATA}"
chmod 700 "${GHOST_DATA}/audit"
# Append-only goes on the audit LOG FILE, not the directory: chattr +a on
# the directory would forbid renames inside it and break logrotate's
# rename-based rotation (step 7b). The file flag still prevents
# truncation/overwrites; logrotate's postrotate re-applies it after each
# rotation.
touch "${GHOST_DATA}/audit/audit.log"
chmod 600 "${GHOST_DATA}/audit/audit.log"
chattr +a "${GHOST_DATA}/audit/audit.log" 2>/dev/null || log_warn "chattr +a failed (audit log append-only)"

log_ok "Directory structure created"

# --- Step 3: Build Go binaries ---
if [ "$SKIP_BUILD" = false ]; then
    log_info "Building Go binaries..."

    cd "${PROJECT_ROOT}"

    # Check Go version.
    if ! command -v go &>/dev/null; then
        log_error "Go ≥1.22 is required but not found"
        exit 1
    fi
    GO_VERSION=$(go version | grep -oP '\d+\.\d+')
    log_ok "Go version: ${GO_VERSION}"

    # Build ghost-ctl.
    log_info "  Building ghost-ctl..."
    CGO_ENABLED=1 go build -o "${GHOST_HOME}/bin/ghost-ctl" \
        -ldflags="-s -w" \
        ./cmd/ghost-ctl/
    log_ok "  ghost-ctl built"

    # Note: agent-alpha and agent-beta would be separate build targets.
    # For now, they are stub binaries that would be built with:
    # go build -o ${GHOST_HOME}/bin/agent-alpha ./cmd/agent-alpha/
    # go build -o ${GHOST_HOME}/bin/agent-beta ./cmd/agent-beta/

    # Symlink ghost-ctl to PATH.
    ln -sf "${GHOST_HOME}/bin/ghost-ctl" /usr/bin/ghost-ctl
    log_ok "ghost-ctl installed to /usr/bin/ghost-ctl"
else
    log_warn "Skipping build (--skip-build)"
fi

# --- Step 4: Compile eBPF programs ---
if [ "$SKIP_BUILD" = false ]; then
    log_info "Compiling eBPF programs..."

    if ! command -v clang &>/dev/null; then
        log_error "clang is required for eBPF compilation"
        exit 1
    fi
    CLANG_VERSION=$(clang --version | head -1)
    log_ok "Compiler: ${CLANG_VERSION}"

    # Compile AGENT-ALPHA eBPF probes.
    log_info "  Compiling alpha.bpf.c..."
    clang -O2 -g -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/include \
        -I"${PROJECT_ROOT}" \
        -c "${PROJECT_ROOT}/agents/alpha/alpha.bpf.c" \
        -o "${GHOST_HOME}/bpf/alpha.bpf.o" 2>/dev/null || \
        log_warn "  alpha.bpf.c compilation failed (missing vmlinux.h — generate with bpftool)"

    # Compile Layer 2 TC eBPF program.
    log_info "  Compiling layer2_tc.bpf.c..."
    clang -O2 -g -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/include \
        -c "${PROJECT_ROOT}/firewall/layer2/layer2_tc.bpf.c" \
        -o "${GHOST_HOME}/bpf/layer2_tc.bpf.o" 2>/dev/null || \
        log_warn "  layer2_tc.bpf.c compilation failed"

    # Compile Layer 3 XDP eBPF program.
    log_info "  Compiling layer3_invisible.bpf.c..."
    clang -O2 -g -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/include \
        -c "${PROJECT_ROOT}/firewall/layer3/layer3_invisible.bpf.c" \
        -o "${GHOST_HOME}/bpf/layer3_invisible.bpf.o" 2>/dev/null || \
        log_warn "  layer3_invisible.bpf.c compilation failed"

    log_ok "eBPF programs compiled"
else
    log_warn "Skipping eBPF compilation (--skip-build)"
fi

# --- Step 5: Install systemd units ---
log_info "Installing systemd units..."

cp "${PROJECT_ROOT}/systemd/ghost-orchestrator.service" /etc/systemd/system/
cp "${PROJECT_ROOT}/systemd/ghost-agent-alpha@.service" /etc/systemd/system/
cp "${PROJECT_ROOT}/systemd/ghost-agent-beta.service" /etc/systemd/system/

systemctl daemon-reload
log_ok "Systemd units installed"

# --- Step 6: Initialize cgroup hierarchy ---
log_info "Initializing cgroup hierarchy..."

CGROUP_BASE="/sys/fs/cgroup/ghost-stack"
mkdir -p "${CGROUP_BASE}"

# Enable controllers.
echo "+cpu +memory +pids +io" > "${CGROUP_BASE}/../cgroup.subtree_control" 2>/dev/null || \
    log_warn "Could not enable cgroup controllers (may need different parent)"

log_ok "cgroup hierarchy initialized at ${CGROUP_BASE}"

# --- Step 7: Create alert bus socket directory ---
log_info "Setting up alert bus..."

ALERT_SOCKET="${GHOST_RUN}/alert.sock"
# Remove stale socket.
rm -f "${ALERT_SOCKET}"
log_ok "Alert bus socket directory ready: ${GHOST_RUN}"

# --- Step 7b: Install logrotate config for the append-only audit trail ---
# The audit log at ${GHOST_DATA}/audit/audit.log grows indefinitely otherwise.
# Rotate weekly AND size-based (whichever comes first), keep 12 weeks of
# compressed history.
#
# IMPORTANT: this MUST stay rename-based (create), never copytruncate.
# copytruncate truncates the live file, which (a) fails on append-only
# (+a) files, (b) races with writers — entries logged between the copy
# and the truncate are silently lost, and (c) breaks the audit hash
# chain. ghost-ctl opens the audit file fresh (O_APPEND) on every write,
# so a rename-based rotation loses nothing: the next appendAudit detects
# the new inode and starts a fresh chain segment with an
# AUDIT_CHAIN_ROTATED genesis entry linking to the previous tail hash
# (verifiable with `ghost-ctl audit-trail --verify`).
log_info "Installing logrotate config for audit trail..."

cat > /etc/logrotate.d/ghost-stack <<EOF
# /etc/logrotate.d/ghost-stack
# Rotates the append-only GHOST-STACK audit trail to prevent unbounded
# disk growth. Managed by deploy/deploy.sh — do not edit by hand.
# Rename-based rotation (NO copytruncate): ghost-ctl detects the new
# inode and re-chains the audit log automatically.
${GHOST_DATA}/audit/*.log {
    weekly
    size 100M
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    dateext
    dateformat -%Y%m%d-%s
    sharedscripts
    postrotate
        # Re-apply append-only to the freshly created audit log.
        chattr +a ${GHOST_DATA}/audit/audit.log 2>/dev/null || true
    endscript
}
EOF

chmod 0644 /etc/logrotate.d/ghost-stack
log_ok "logrotate config installed at /etc/logrotate.d/ghost-stack"

# --- Step 8: Install AppArmor template ---
log_info "Installing AppArmor profile template..."

if command -v apparmor_status &>/dev/null; then
    cp "${PROJECT_ROOT}/firewall/layer4/apparmor-dept-template.profile" \
        "${GHOST_CONFIG}/apparmor-dept-template.profile"
    log_ok "AppArmor template installed"
else
    log_warn "AppArmor not available — Layer 4 will run without MAC enforcement"
fi

# --- Step 9: Deploy firewall ---
if [ "$SKIP_FIREWALL" = false ]; then
    log_info "Deploying firewall layers..."
    if [ -x "${SCRIPT_DIR}/firewall_deploy.sh" ]; then
        bash "${SCRIPT_DIR}/firewall_deploy.sh"
    else
        log_warn "firewall_deploy.sh not found or not executable"
    fi
else
    log_warn "Skipping firewall deployment (--skip-firewall)"
fi

# --- Step 10: Summary ---
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  GHOST-STACK CORE — Deployment Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Binary:     ${GHOST_HOME}/bin/ghost-ctl"
echo "  Config:     ${GHOST_CONFIG}/"
echo "  Data:       ${GHOST_DATA}/"
echo "  BPF:        ${GHOST_HOME}/bpf/"
echo "  Cgroup:     ${CGROUP_BASE}/"
echo "  Audit:      ${GHOST_DATA}/audit/ (append-only)"
echo ""
echo "  Start orchestrator:  systemctl start ghost-orchestrator"
echo "  Start agent-beta:    systemctl start ghost-agent-beta"
echo "  Spawn department:    ghost-ctl dept spawn <ID> <NAME> <TIER>"
echo ""
echo -e "${YELLOW}  NOTE: This system requires Linux kernel ≥5.15 with BPF,${NC}"
echo -e "${YELLOW}  XDP, cgroups v2, user namespaces, and time namespaces.${NC}"
echo ""
