# GHOST-STACK CORE

<div align="center">

```
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗       ███████╗████████╗ █████╗  ██████╗██╗  ██╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝       ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
 ██║  ███╗███████║██║   ██║███████╗   ██║          ███████╗   ██║   ███████║██║     █████╔╝ 
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║          ╚════██║   ██║   ██╔══██║██║     ██╔═██╗ 
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║          ███████║   ██║   ██║  ██║╚██████╗██║  ██╗
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝  ╚═╝          ╚══════╝  ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

### Kernel-Level Deception Security Orchestrator

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Proprietary%20%7C%20All%20Rights%20Reserved-red?style=flat-square)](./LICENSE)
[![eBPF](https://img.shields.io/badge/eBPF-XDP%20%7C%20TC%20%7C%20kprobe-orange?style=flat-square)](https://ebpf.io)
[![Platform](https://img.shields.io/badge/Platform-Linux%20Kernel%206.1+-informational?style=flat-square)](https://kernel.org)
[![Status](https://img.shields.io/badge/Status-Patent%20Pending-blueviolet?style=flat-square)]()
[![Access](https://img.shields.io/badge/Access-Closed%20Source%20%7C%20NDA%20Required-black?style=flat-square)](./LICENSE)

> **GHOST-STACK CORE** is a proprietary, closed-source kernel-level security orchestration platform. It deploys cryptographically isolated department containers governed by a 4-layer eBPF deception firewall. All enforcement occurs inside the Linux kernel — no userspace daemon can be tampered with, disabled, or bypassed.
>
> **Access to this repository is governed by a Non-Disclosure Agreement (NDA) and a Commercial Evaluation Agreement. Unauthorized access, reproduction, or distribution is strictly prohibited and subject to legal action.**

</div>

---

## Table of Contents

- [Confidentiality & Access Notice](#confidentiality--access-notice)
- [Overview](#overview)
- [Architecture](#architecture)
- [Firewall Layers](#firewall-layers)
- [Agents](#agents)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Build Commands](#build-commands)
- [Running the System](#running-the-system)
- [CLI Reference — ghost-ctl](#cli-reference--ghost-ctl)
- [Systemd Services](#systemd-services)
- [Configuration](#configuration)
- [Testing](#testing)
- [Security Model](#security-model)
- [Patent Notice](#patent-notice)
- [License & Legal](#license--legal)

---

## Confidentiality & Access Notice

> ⚠️ **THIS SOFTWARE IS PROPRIETARY AND CONFIDENTIAL**

This repository and all its contents — including source code, eBPF programs, architecture documentation, configuration files, and deployment scripts — constitute **trade secrets** and **proprietary intellectual property** owned exclusively by **Mehmet Zumrut**.

Access to this codebase is granted **only** under the following conditions:

1. **Signed NDA** — A fully executed Non-Disclosure Agreement between the accessing party and Mehmet Zumrut must be in place prior to any access.
2. **Signed Commercial Evaluation Agreement** — Any organization evaluating this software for integration, licensing, or procurement must execute a Commercial Evaluation Agreement defining the scope, duration, and permitted use of evaluation access.
3. **No Transfer** — The receiving party may not copy, share, forward, publish, or disclose any portion of this software or its documentation to any third party without prior written consent.
4. **IP Assignment** — All innovations, findings, or improvements derived during an evaluation period remain the exclusive intellectual property of Mehmet Zumrut.

To request access or initiate an evaluation agreement, contact the author directly (see [License & Legal](#license--legal)).

---

## Overview

GHOST-STACK CORE solves a critical problem in enterprise security: **traditional firewalls are visible**. A port scanner can map your network, enumerate open services, and chart your entire attack surface in seconds. Ghost-Stack takes the opposite approach — the network **literally does not exist** to unauthorized observers.

### Core Innovations

| Innovation | Description |
|---|---|
| **Invisible Wall (Layer 3)** | XDP NIC-driver-level packet drop with no RST/ICMP — attacker connections hang indefinitely with zero signal |
| **Deception Responder (Layer 2)** | TC eBPF crafts contextually accurate fake RST/TLS-error packets to actively misdirect scanners |
| **Passive eBPF Observation** | Agent-Alpha monitors 5 kernel tracepoints with zero write capability — tamper-proof by kernel design |
| **Kernel RBAC Enforcement** | 4-tier hierarchy (ROOT → DIRECTOR → MANAGER → STAFF) enforced via user namespace UID mapping at kernel level |
| **Ed25519 Signed Commands** | All orchestrator state changes require a cryptographic signature — no unsigned command can alter system state |
| **Immutable Audit Trail** | Append-only SQLite WAL partition — forensic log cannot be altered or deleted without the root key |
| **Department Namespace Isolation** | Each organizational unit runs in its own Linux user/network/mount namespace triplet |

---

## Architecture

```
+------------------------------------------------------------------+
|                    ghost-ctl  (Control Plane)                    |
|   dept spawn | dept quarantine | dept snapshot | hierarchy show  |
|                   Ed25519-signed command bus                     |
+-----------------------------+------------------------------------+
                              |
            +-----------------v------------------+
            |        AGENT-BETA  (Observer)       |
            |  L1 nflog  |  L2 perf_event  | L3 XDP  |
            |  L4 LSM audit  |  TTP mapper        |
            +-------+-------------------+---------+
                    |                   |
    +---------------v-----+   +---------v------------------+
    |    AGENT-ALPHA       |   |   4-Layer eBPF Firewall    |
    |    eBPF kprobes      |   |   L1  nftables decoy       |
    |    tp/execve         |   |   L2  TC deception BPF     |
    |    tp/connect        |   |   L3  XDP invisible wall   |
    |    kprobe/creds      |   |   L4  AppArmor + ns ipt    |
    |    tp/unshare        |   +----------------------------+
    |    tp/openat         |
    +----------+-----------+
               |
    +----------v-----------------------------------------+
    |              Department Containers                  |
    |   [ DEPT-A ]   [ DEPT-B ]   [ DEPT-C ]   ...       |
    |   user ns  /  net ns  /  mount ns                   |
    |   UID-mapped RBAC  (kernel enforced)                |
    +-----------------------------------------------------+
```

---

## Firewall Layers

### Layer 1 — Decoy Network (nftables)
File: `firewall/layer1/layer1_decoy.nft`

A synthetic service landscape deployed via nftables. Port scanners discover plausible-looking open ports that route to controlled honeypot handlers — real service endpoints are never exposed.

### Layer 2 — Deception Responder (TC eBPF)
File: `firewall/layer2/layer2_tc.bpf.c` + `deception_responder.go`

Attached at the Linux Traffic Control (TC) layer. Crafts contextually appropriate fake TCP RST, ICMP unreachable, and TLS `HANDSHAKE_FAILURE` responses to probe traffic, actively misdirecting both automated scanners and human operators.

### Layer 3 — Invisible Wall (XDP, NIC-driver level)
File: `firewall/layer3/layer3_invisible.bpf.c` + `allowlist_manager.go`

The core stealth primitive. Attached at XDP in native mode — **before** the kernel network stack processes any packet. An LPM-trie allowlist controls pass/drop decisions; every non-allowlisted source receives `XDP_DROP` with **absolute silence** (no RST, no ICMP, no TCP timeout signal). An unauthorized scanner cannot determine whether the host exists at all.

- Allowlist updates require an Ed25519-signed command from the orchestrator
- Drop counters reside in kernel BPF maps — never written to disk
- Agent-Beta polls counters every 500 ms via BPF map read

### Layer 4 — Process & Namespace Isolation (AppArmor + iptables)
Files: `firewall/layer4/apparmor-dept-template.profile` + `namespace_iptables.sh`

Per-department AppArmor profiles restrict filesystem access to the minimum required capability set. Combined with per-namespace iptables rules, cross-department traffic is made cryptographically impossible at the kernel level.

---

## Agents

### Agent-Alpha — eBPF Passive Observer
`agents/alpha/alpha.bpf.c` + `observer.go`

Passively monitors 5 kernel tracepoints and kprobes:

| Probe | Kernel Event | Detection Target |
|---|---|---|
| `tp/syscalls/sys_enter_execve` | Process execution | Unexpected binary spawn inside container |
| `tp/syscalls/sys_enter_connect` | Outbound TCP/UDP connection | C2 beacon or lateral movement |
| `kprobe/commit_creds` | Credential change | Privilege escalation attempt |
| `tp/syscalls/sys_enter_unshare` | Namespace unshare | Container escape attempt |
| `tp/syscalls/sys_enter_openat` | File open | Sensitive file access pattern |

**Design constraints:** ZERO write capability, NEVER blocks kernel execution, all events delivered via BPF ring buffer only.

### Agent-Beta — Firewall Observer & TTP Mapper
`agents/beta/beta.go` + `profiler.go` + `ttp_mapper.go`

Four goroutines read four independent data feeds concurrently:

```
goroutine-L1  -->  nflog ring buffer       (netlink socket)
goroutine-L2  -->  eBPF perf_event_array
goroutine-L3  -->  XDP drop counter BPF map (polled every 500 ms)
goroutine-L4  -->  LSM audit netlink socket
```

Observed behavior sequences are mapped in real-time to MITRE ATT&CK TTP identifiers. All event data is **in-memory only** — never written to disk unless the orchestrator issues a signed forensic export command.

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Linux Kernel | 6.1 (BPF CO-RE) | 6.6+ LTS |
| Go | 1.22 | 1.22+ |
| Clang / LLVM | 14 | 17+ |
| libbpf | 1.0 | 1.3+ |
| libbpf-dev headers | required | — |
| CGO | enabled | — |
| CAP_BPF / CAP_NET_ADMIN | required | run as root |

### Install System Dependencies

```bash
# Ubuntu / Debian
sudo apt update
sudo apt install -y \
    clang llvm libelf-dev \
    libbpf-dev linux-headers-$(uname -r) \
    nftables iproute2 apparmor apparmor-utils \
    build-essential pkg-config git

# Fedora / RHEL
sudo dnf install -y \
    clang llvm elfutils-libelf-devel \
    libbpf-devel kernel-devel \
    nftables iproute apparmor-utils \
    gcc make pkg-config git

# Arch Linux
sudo pacman -S --noconfirm \
    clang llvm libelf libbpf \
    linux-headers nftables iproute2 \
    apparmor base-devel git
```

### Install Go 1.22+

```bash
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version   # expected: go version go1.22.5 linux/amd64
```

---

## Installation

> ⚠️ Access to this repository requires a signed NDA. Do not clone or distribute without authorization.

```bash
# 1. Clone the repository (authorized parties only)
git clone https://github.com/ghost-stack/core.git
cd core

# 2. Download Go module dependencies
go mod download

# 3. Verify dependency integrity
go mod verify

# 4. Optional: install staticcheck linter
go install honnef.co/go/tools/cmd/staticcheck@latest
```

---

## Build Commands

All build targets are managed via `Makefile`. Run `make help` to list all available targets.

```bash
make help           # Display all build targets with descriptions
```

### Full Build Pipeline

```bash
make all            # Run lint --> tests --> build  (recommended before any deployment)
```

### Individual Targets

```bash
make build          # Compile the ghost-ctl binary  -->  build/ghost-ctl
make test           # Run all unit tests with race detector + coverage report
make test-short     # Run tests without verbose output (faster)
make test-bench     # Run benchmarks
make coverage-html  # Generate HTML coverage report  -->  coverage.html
make lint           # Run go vet + staticcheck
make fmt            # Format all Go source files
make ebpf           # Compile all eBPF programs (requires clang + vmlinux.h)
make clean          # Remove all build artifacts
make ci             # Run full CI pipeline locally (mirrors GitHub Actions)
```

### Manual Binary Build

```bash
CGO_ENABLED=1 go build \
    -ldflags="-s -w" \
    -o build/ghost-ctl \
    ./cmd/ghost-ctl/

ls -lh build/ghost-ctl
```

### Compile eBPF Programs Manually

```bash
# Agent-Alpha kernel probes
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c agents/alpha/alpha.bpf.c \
    -o build/bpf/alpha.bpf.o

# Layer 2 — TC deception BPF
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -c firewall/layer2/layer2_tc.bpf.c \
    -o build/bpf/layer2_tc.bpf.o

# Layer 3 — XDP invisible wall
clang -O2 -g -target bpf \
    -c firewall/layer3/layer3_invisible.bpf.c \
    -o build/bpf/layer3_invisible.bpf.o
```

---

## Running the System

### Step 1 — Deploy Firewall Layers

```bash
# Deploy all 4 firewall layers (requires root)
sudo bash deploy/deploy.sh

# Deploy firewall layers only
sudo bash deploy/firewall_deploy.sh

# Attach Layer 3 XDP to a network interface manually
sudo ip link set dev eth0 xdpdrv \
    obj build/bpf/layer3_invisible.bpf.o sec xdp
```

### Step 2 — Start Systemd Services

```bash
# Copy service unit files to systemd
sudo cp systemd/*.service /etc/systemd/system/

# Reload the systemd daemon
sudo systemctl daemon-reload

# Enable all services to start at boot
sudo systemctl enable ghost-orchestrator
sudo systemctl enable ghost-agent-beta
sudo systemctl enable "ghost-agent-alpha@eth0"

# Start all services
sudo systemctl start ghost-orchestrator
sudo systemctl start ghost-agent-beta
sudo systemctl start "ghost-agent-alpha@eth0"

# Verify service status
sudo systemctl status ghost-orchestrator
sudo systemctl status ghost-agent-beta
sudo systemctl status "ghost-agent-alpha@eth0"
```

### Step 3 — Launch ghost-ctl

```bash
# Start the orchestrator control plane
sudo ./build/ghost-ctl

# Display the department hierarchy tree
sudo ./build/ghost-ctl hierarchy show

# View the immutable audit trail
sudo ./build/ghost-ctl audit-trail
```

### Live Log Monitoring

```bash
# Follow all Ghost-Stack service logs in real time
sudo journalctl \
    -u ghost-orchestrator \
    -u ghost-agent-beta \
    -u "ghost-agent-alpha@eth0" \
    -f

# Stream Agent-Beta TTP events as JSON
sudo journalctl -u ghost-agent-beta -f --output=json

# Orchestrator command audit stream
sudo journalctl -u ghost-orchestrator -f
```

---

## CLI Reference — ghost-ctl

```
ghost-ctl [command] [flags]
```

| Command | Description |
|---|---|
| `dept spawn <name> <tier>` | Spawn a new department container with the specified RBAC tier |
| `dept quarantine <name>` | Isolate a running department (network cut + process freeze) |
| `dept snapshot <name>` | Capture full memory and state snapshot for forensic analysis |
| `dept status` | Display the status of all running department containers |
| `hierarchy show` | Render the full 4-tier RBAC hierarchy tree |
| `audit-trail` | Display the append-only immutable audit trail |
| `ipam list` | List IP address assignments for all departments |
| `threat-response <dept> <action>` | Execute a signed threat response command |

### Examples

```bash
# Spawn the engineering department at MANAGER tier
sudo ./build/ghost-ctl dept spawn engineering MANAGER

# Immediately quarantine a suspicious department
sudo ./build/ghost-ctl dept quarantine finance-dept

# Capture a forensic snapshot before teardown
sudo ./build/ghost-ctl dept snapshot proc-4821

# Display the live hierarchy tree
sudo ./build/ghost-ctl hierarchy show

# Inspect the append-only audit trail
sudo ./build/ghost-ctl audit-trail
```

---

## Systemd Services

| Service Unit | Description | Type |
|---|---|---|
| `ghost-orchestrator.service` | Control plane orchestrator daemon | notify |
| `ghost-agent-beta.service` | 4-layer firewall observer & TTP mapper | simple |
| `ghost-agent-alpha@.service` | Per-interface eBPF probe agent (templated) | simple |

```bash
# Check health of all services at once
sudo systemctl status ghost-orchestrator ghost-agent-beta "ghost-agent-alpha@eth0"

# Restart after a configuration change
sudo systemctl restart ghost-orchestrator

# Disable and stop all services
sudo systemctl disable --now \
    ghost-orchestrator \
    ghost-agent-beta \
    "ghost-agent-alpha@eth0"
```

---

## Configuration

### RBAC Hierarchy Tiers

```
TierRoot      --  Full system visibility across all namespaces
TierDirector  --  Read access to all subordinate container data
TierManager   --  Own department + direct reports only
TierStaff     --  Own container only; zero upward visibility
```

UID namespace mappings are auto-generated by the orchestrator and applied via kernel `newuidmap` / `newgidmap`. Cross-department UID collision is cryptographically prevented by the UID range allocator.

### Layer 3 Allowlist

Allowlist entries must be submitted as Ed25519-signed JSON payloads:

```json
{
  "op": "allowlist_add",
  "cidr": "10.0.10.0/24",
  "comment": "SOC team VPN range",
  "issued_at": "2026-01-15T09:00:00Z",
  "signature": "<ed25519_base64>"
}
```

Submit via:

```bash
sudo ./build/ghost-ctl allowlist add \
    --cidr 10.0.10.0/24 \
    --key /etc/ghost-stack/orchestrator.ed25519.priv
```

---

## Testing

```bash
# Run the full test suite with race detector
make test

# Test individual packages
go test -v -race ./auth/...
go test -v -race ./hierarchy/...
go test -v -race ./db/...
go test -v -race ./agents/beta/...

# Run all benchmarks
make test-bench

# Generate and open the HTML coverage report
make coverage-html
open coverage.html        # macOS
xdg-open coverage.html   # Linux
```

### CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) executes on every push and pull request:

```
lint  -->  go vet  -->  staticcheck  -->  test (race)  -->  build
```

To run the full pipeline locally:

```bash
make ci
```

---

## Security Model

### Threat Model Boundaries

GHOST-STACK CORE is designed against the following adversary capabilities:

1. **Network-level attacker** — full packet control on the wire; running Nmap, Masscan, Shodan probes
2. **Compromised container** — attacker has arbitrary code execution inside a department container
3. **Insider threat** — malicious actor with valid credentials attempting privilege escalation
4. **Forensic evasion** — attacker attempting to delete or tamper with audit evidence

### What Ghost-Stack Does NOT Do

- Does **not** provide DDoS mitigation or rate limiting
- Does **not** replace a WAF for application-layer (L7) attacks
- Does **not** inspect encrypted payload content (TLS termination is out of scope)
- Does **not** support Windows or macOS as deployment targets

### Key Security Primitives

```
Ed25519 signatures   -->  All state-change commands require cryptographic proof of origin
BPF CO-RE            -->  eBPF programs verified at load time; kernel rejects malformed probes
User namespace UIDs  -->  Cross-department privilege escalation blocked at kernel scheduler level
Append-only WAL      -->  SQLite WAL journal prevents in-place audit log modification
Zero write eBPF      -->  Agent-Alpha / Agent-Beta hold only BPF_PROG_TYPE_TRACEPOINT capabilities
```

---

## Patent Notice

**PATENT PENDING — All Rights Reserved**

The following innovations described and implemented in this codebase are the subject of one or more pending patent applications filed by **Mehmet Zumrut** with the United States Patent and Trademark Office (USPTO) and corresponding international filings:

- Multi-layer deception firewall architecture combining XDP, TC eBPF, nftables, and LSM in a unified, cryptographically-signed orchestration pipeline
- Kernel-level RBAC enforcement via user namespace UID range cryptographic isolation
- Passive eBPF observation architecture with verifier-enforced zero-write, zero-block capability guarantees
- Ed25519-signed command bus for immutable orchestrator state management with append-only forensic audit trail
- Real-time behavioral TTP correlation engine mapping kernel tracepoint event sequences to MITRE ATT&CK identifiers with zero disk I/O

Reproduction, reverse engineering, reimplementation, or commercial use of any of these techniques without explicit written authorization from the inventor is strictly prohibited and constitutes patent infringement.

---

## License & Legal

This software is licensed under the **GHOST-STACK CORE Proprietary License v1.0**.
See [LICENSE](./LICENSE) for the complete terms.

### Access Requirements

All access to this software — including evaluation, integration, and deployment — requires:

| Requirement | Description |
|---|---|
| **NDA** | Signed Non-Disclosure Agreement with Mehmet Zumrut |
| **Commercial Evaluation Agreement** | Signed prior to any demo, prototype review, or technical evaluation |
| **Written Authorization** | Explicit written consent for any reproduction or derivative use |

### Permitted Uses (Authorized Parties Only)

- Reading and evaluating source code under NDA
- Running the software in an authorized evaluation environment
- Security research conducted under a signed research agreement

### Prohibited Uses (All Parties)

- Redistribution, sublicensing, or resale in any form
- Commercial deployment without a fully executed Commercial License Agreement
- Filing patent applications that overlap with the innovations described herein
- Cloud or SaaS deployment accessible to third parties without a Commercial License
- Government or defense use without a separate Government Use License Agreement

### Contact for Licensing & NDA

```
Licensor  :  Mehmet Zumrut
Location  :  Seattle, Washington, USA
Subject   :  "GHOST-STACK CORE — NDA / Commercial License Inquiry"
```

---

<div align="center">

Built with precision by **Mehmet Zumrut** &nbsp;·&nbsp; Seattle, WA

© 2026 Mehmet Zumrut — All Rights Reserved &nbsp;·&nbsp; Patent Pending &nbsp;·&nbsp; Proprietary & Confidential

</div>
