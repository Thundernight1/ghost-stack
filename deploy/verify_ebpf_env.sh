#!/bin/bash
# ═══════════════════════════════════════════════════════════
# GHOST-STACK CORE — eBPF Environment Verification Script
# ═══════════════════════════════════════════════════════════

set -e

echo "==> Verifying eBPF Environment for GHOST-STACK CORE"

# 1. Check Kernel Version
KERNEL_VERSION=$(uname -r)
echo "[*] Kernel Version: $KERNEL_VERSION"
# Simple check for 6.1+ (we expect major version >= 6)
MAJOR_VERSION=$(echo "$KERNEL_VERSION" | cut -d. -f1)
MINOR_VERSION=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$MAJOR_VERSION" -lt 6 ] || ( [ "$MAJOR_VERSION" -eq 6 ] && [ "$MINOR_VERSION" -lt 1 ] ); then
    echo "[!] WARNING: Kernel version is less than 6.1. eBPF features may not be fully supported."
else
    echo "[✓] Kernel version is >= 6.1"
fi

# 2. Check /sys/kernel/btf/vmlinux
if [ -f "/sys/kernel/btf/vmlinux" ]; then
    echo "[✓] Kernel BTF (/sys/kernel/btf/vmlinux) is available"
else
    echo "[!] ERROR: Kernel BTF (/sys/kernel/btf/vmlinux) is MISSING. Ensure CONFIG_DEBUG_INFO_BTF is enabled."
    # Exit replaced with echo to avoid breaking sandbox
    exit 1
fi

# 3. Check Clang version
if command -v clang-17 >/dev/null 2>&1; then
    CLANG_BIN="clang-17"
elif command -v clang >/dev/null 2>&1; then
    CLANG_BIN="clang"
else
    echo "[!] ERROR: clang is not installed."
    exit 1
fi

if [ -n "$CLANG_BIN" ]; then
    CLANG_VERSION=$($CLANG_BIN --version | head -n 1)
    echo "[*] Found Clang: $CLANG_VERSION"
fi

# 4. Check bpftool
if command -v bpftool >/dev/null 2>&1; then
    echo "[✓] bpftool is available"
else
    echo "[!] ERROR: bpftool is not installed. Install linux-tools-common / linux-tools-generic."
    exit 1
fi

echo "==> Environment Verification Complete [✓]"
