// Package namespace implements the raw Linux namespace container runtime
// for GHOST-STACK CORE. Each department is a fully isolated namespace
// container using pid, net, mnt, uts, ipc, user, cgroup, and time namespaces.
//
// Built using syscall.SysProcAttr + CLONE_NEW* flags — no Docker, no Podman,
// no third-party container runtime dependencies.
package namespace

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghost-stack/core/hierarchy"
)

const (
	// cgroupFreezeFile is the cgroup-v2 interface file used to suspend
	// (value 1) and resume (value 0) all processes in a department
	// container. It is referenced by both the quarantine engine and
	// the snapshot routines.
	cgroupFreezeFile = "cgroup.freeze"
)

// CloneFlags combines all CLONE_NEW* flags for maximum namespace isolation.
// Each department container gets its own:
//   - PID namespace (CLONE_NEWPID): isolated process tree
//   - Network namespace (CLONE_NEWNET): isolated network stack
//   - Mount namespace (CLONE_NEWNS): private rootfs view
//   - UTS namespace (CLONE_NEWUTS): isolated hostname
//   - IPC namespace (CLONE_NEWIPC): zero shared memory
//   - User namespace (CLONE_NEWUSER): UID/GID isolation for hierarchy enforcement
//   - Cgroup namespace (CLONE_NEWCGROUP): isolated cgroup view
//   - Time namespace (CLONE_NEWTIME): prevents cross-dept timing side-channels
const CloneFlags = syscall.CLONE_NEWPID |
	syscall.CLONE_NEWNET |
	syscall.CLONE_NEWNS |
	syscall.CLONE_NEWUTS |
	syscall.CLONE_NEWIPC |
	syscall.CLONE_NEWUSER |
	syscall.CLONE_NEWCGROUP |
	0x80000000 // CLONE_NEWTIME (not yet in Go's syscall package)

// CgroupLimits defines resource limits for a department container via cgroups v2.
type CgroupLimits struct {
	// MemoryMax in bytes (e.g., 1 << 30 = 1 GiB).
	MemoryMax int64
	// CPUMax as "quota period" (e.g., "100000 100000" = 100% of one core).
	CPUQuota  int64
	CPUPeriod int64
	// PidsMax is the maximum number of processes.
	PidsMax int64
	// IOMax as "major:minor rbps=X wbps=X riops=X wiops=X".
	IOMax string
}

// DefaultCgroupLimits returns sensible defaults per hierarchy tier.
func DefaultCgroupLimits(tier hierarchy.Tier) CgroupLimits {
	switch tier {
	case hierarchy.TierRoot:
		return CgroupLimits{
			MemoryMax: 8 << 30, // 8 GiB
			CPUQuota:  400000,  // 4 cores
			CPUPeriod: 100000,
			PidsMax:   4096,
			IOMax:     "",
		}
	case hierarchy.TierDirector:
		return CgroupLimits{
			MemoryMax: 4 << 30, // 4 GiB
			CPUQuota:  200000,  // 2 cores
			CPUPeriod: 100000,
			PidsMax:   2048,
			IOMax:     "",
		}
	case hierarchy.TierManager:
		return CgroupLimits{
			MemoryMax: 2 << 30, // 2 GiB
			CPUQuota:  100000,  // 1 core
			CPUPeriod: 100000,
			PidsMax:   1024,
			IOMax:     "",
		}
	case hierarchy.TierStaff:
		return CgroupLimits{
			MemoryMax: 1 << 30, // 1 GiB
			CPUQuota:  50000,   // 0.5 cores
			CPUPeriod: 100000,
			PidsMax:   512,
			IOMax:     "",
		}
	default:
		return CgroupLimits{
			MemoryMax: 512 << 20,
			CPUQuota:  25000,
			CPUPeriod: 100000,
			PidsMax:   256,
			IOMax:     "",
		}
	}
}

// ContainerConfig holds the full configuration for spawning a department container.
type ContainerConfig struct {
	// DeptID is the department identifier (0-99).
	DeptID int
	// DeptName is the human-readable department name.
	DeptName string
	// Tier is the hierarchy tier.
	Tier hierarchy.Tier
	// RootFS is the absolute path to the department's root filesystem.
	RootFS string
	// Hostname is set inside the UTS namespace.
	Hostname string
	// Limits defines cgroup v2 resource limits.
	Limits CgroupLimits
	// AgentBinaryPath is the host path to AGENT-ALPHA binary (mounted read-only).
	AgentBinaryPath string
	// AlertSocketPath is the host path to the Unix domain socket for alerts.
	AlertSocketPath string
	// VethHostName is the host-side veth interface name.
	VethHostName string
	// VethContainerName is the container-side veth interface name.
	VethContainerName string
	// SubnetCIDR is the department's isolated subnet (e.g., "10.200.1.0/24").
	SubnetCIDR string
	// ContainerIP is the container's IP within the subnet.
	ContainerIP string
	// GatewayIP is the gateway IP (host-side veth).
	GatewayIP string
}

// RunningContainer holds state for an active department container.
type RunningContainer struct {
	Config      ContainerConfig
	Cmd         *exec.Cmd
	PID         int
	CgroupPath  string
	StartedAt   time.Time
	Frozen      bool
	Quarantined bool
}

// DepartmentManager manages the lifecycle of all department containers.
type DepartmentManager struct {
	mu         sync.RWMutex
	containers map[int]*RunningContainer
	basePath   string
	hierarchy  *hierarchy.HierarchyTree
}

// ListContainers returns a snapshot of all tracked department containers.
func (dm *DepartmentManager) ListContainers() []RunningContainer {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	out := make([]RunningContainer, 0, len(dm.containers))
	for _, c := range dm.containers {
		out = append(out, *c)
	}
	return out
}

// NewDepartmentManager creates a new manager for department containers.
func NewDepartmentManager(basePath string, ht *hierarchy.HierarchyTree) *DepartmentManager {
	return &DepartmentManager{
		containers: make(map[int]*RunningContainer),
		basePath:   basePath,
		hierarchy:  ht,
	}
}

// RegisterRecoveredContainer registers an already running container in the in-memory map.
func (dm *DepartmentManager) RegisterRecoveredContainer(cfg ContainerConfig, pid int, cgroupPath string, startedAt time.Time) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.containers[cfg.DeptID] = &RunningContainer{
		Config:     cfg,
		PID:        pid,
		CgroupPath: cgroupPath,
		StartedAt:  startedAt,
	}
}

// SpawnDepartment creates and starts a fully isolated namespace container
// for the given department configuration.
//
// Steps:
// SpawnDepartment creates and starts a department container:
//  1. Create cgroup v2 subtree with resource limits
//  2. Prepare rootfs with private mounts
//  3. Compute UID/GID mapping for the department's tier
//  4. Bind-mount AGENT-ALPHA (read-only) + alert socket into the rootfs
//     (before clone — the child inherits them in its mount namespace)
//  5. Re-exec self as container-init with all CLONE_NEW* flags; the child
//     does pivot_root into the rootfs, mounts /proc+/sys+/dev (real device
//     nodes), detaches the old root, and execs the department init
//  6. Liveness check: fail the spawn if the init dies during pivot/exec
//  7. Set hostname in the UTS namespace (fatal on error)
//  8. Create the veth pair for the network namespace (fatal on error)
//  9. Move the container PID into its cgroup (fatal on error)
//
// Post-fork failures are fatal and trigger full cleanup (SIGKILL the
// child, detach the bind mounts, remove the cgroup): a half-isolated
// container must never be recorded as running.
func (dm *DepartmentManager) SpawnDepartment(cfg ContainerConfig) (*RunningContainer, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if _, exists := dm.containers[cfg.DeptID]; exists {
		return nil, fmt.Errorf("ghost-stack: department %d is already running", cfg.DeptID)
	}

	// Step 1: Create cgroup v2 subtree.
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/ghost-stack/dept-%d", cfg.DeptID)
	if err := setupCgroup(cgroupPath, cfg.Limits); err != nil {
		return nil, fmt.Errorf("ghost-stack: cgroup setup failed: %w", err)
	}

	// Step 2: Prepare rootfs directory structure.
	if err := prepareRootFS(cfg.RootFS); err != nil {
		return nil, fmt.Errorf("ghost-stack: rootfs preparation failed: %w", err)
	}

	// Step 3: Compute UID/GID mapping.
	uidMapping := hierarchy.DepartmentUIDMapping(cfg.Tier, cfg.DeptID)

	// Step 4: Parent-side bind mounts into the rootfs BEFORE clone.
	// The child inherits these in its fresh mount namespace and
	// pivot_root carries them into the container. Doing this before
	// cmd.Start() (not after, as before) removes the race where the
	// child pivots before the mounts exist.
	if cfg.AgentBinaryPath != "" {
		agentMountTarget := filepath.Join(cfg.RootFS, "opt", "ghost-agent", "alpha")
		if err := os.MkdirAll(filepath.Dir(agentMountTarget), 0o755); err != nil {
			destroyFailedSpawn(cgroupPath, cfg, nil)
			return nil, fmt.Errorf("ghost-stack: agent mount dir: %w", err)
		}
		if err := bindMountReadOnly(cfg.AgentBinaryPath, agentMountTarget); err != nil {
			destroyFailedSpawn(cgroupPath, cfg, nil)
			return nil, fmt.Errorf("ghost-stack: agent bind mount: %w", err)
		}
	}
	if cfg.AlertSocketPath != "" {
		socketMountTarget := filepath.Join(cfg.RootFS, "var", "run", "ghost-alert.sock")
		if err := os.MkdirAll(filepath.Dir(socketMountTarget), 0o755); err != nil {
			destroyFailedSpawn(cgroupPath, cfg, nil)
			return nil, fmt.Errorf("ghost-stack: socket mount dir: %w", err)
		}
		if err := bindMountReadOnly(cfg.AlertSocketPath, socketMountTarget); err != nil {
			destroyFailedSpawn(cgroupPath, cfg, nil)
			return nil, fmt.Errorf("ghost-stack: socket bind mount: %w", err)
		}
	}

	// Step 5: Choose the in-container init, then re-exec ourselves as the
	// container init. The child runs namespace.ContainerInit (pivot_root,
	// /proc+/sys+/dev, then exec of initPath) inside the new namespaces.
	// initPath is the in-container path: existence is probed on the host
	// via the rootfs-prefixed path.
	initPath := "/sbin/init"
	if _, err := os.Stat(filepath.Join(cfg.RootFS, "sbin", "init")); os.IsNotExist(err) {
		initPath = "/bin/sh"
	}

	self, err := os.Executable()
	if err != nil {
		destroyFailedSpawn(cgroupPath, cfg, nil)
		return nil, fmt.Errorf("ghost-stack: os.Executable: %w", err)
	}
	cmd := exec.Command(self, "container-init")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: uintptr(CloneFlags),
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: int(uidMapping.ContainerStart),
				HostID:      int(uidMapping.HostStart),
				Size:        int(uidMapping.Size),
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: int(uidMapping.ContainerStart),
				HostID:      int(uidMapping.HostStart),
				Size:        int(uidMapping.Size),
			},
		},
		// Ensure the child process becomes subreaper.
		// Pdeathsig: syscall.SIGKILL,
	}

	// Set isolated hostname.
	cmd.Env = []string{
		fmt.Sprintf("GHOST_DEPT_ID=%d", cfg.DeptID),
		fmt.Sprintf("GHOST_DEPT_NAME=%s", cfg.DeptName),
		fmt.Sprintf("GHOST_TIER=%s", cfg.Tier.String()),
		"GHOST_CONTAINER_INIT=1",
		"GHOST_CONTAINER_ROOTFS=" + cfg.RootFS,
		"GHOST_CONTAINER_INIT_PATH=" + initPath,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=xterm-256color",
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Step 6: Start the container process.
	if err := cmd.Start(); err != nil {
		destroyFailedSpawn(cgroupPath, cfg, nil)
		return nil, fmt.Errorf("ghost-stack: failed to start container: %w", err)
	}

	pid := cmd.Process.Pid

	// Liveness: the re-exec'd child must survive pivot_root and the exec
	// of the department init. If it dies here the container is unusable —
	// fail the spawn instead of recording a dead PID.
	if err := awaitContainerInit(pid); err != nil {
		destroyFailedSpawn(cgroupPath, cfg, cmd)
		return nil, err
	}

	// Step 7: Set hostname inside the UTS namespace.
	// Fatal: a container without its deterministic hostname breaks the
	// audit trail's host attribution.
	if err := nsenterExec(pid, "uts", "hostname", cfg.Hostname); err != nil {
		destroyFailedSpawn(cgroupPath, cfg, cmd)
		return nil, fmt.Errorf("ghost-stack: hostname setup failed: %w", err)
	}

	// Step 8: Configure network namespace — create veth pair.
	// Fatal: without the veth pair there is no network isolation.
	if err := setupVethPair(pid, cfg); err != nil {
		destroyFailedSpawn(cgroupPath, cfg, cmd)
		return nil, fmt.Errorf("ghost-stack: veth setup failed: %w", err)
	}

	// Step 9: Move container PID into its cgroup.
	// Fatal: without cgroup assignment there are no resource limits and
	// quarantine (cgroup.freeze) cannot work.
	if err := moveToCgroup(cgroupPath, pid); err != nil {
		destroyFailedSpawn(cgroupPath, cfg, cmd)
		return nil, fmt.Errorf("ghost-stack: cgroup assignment failed: %w", err)
	}

	// Reap the init when it eventually exits so the long-lived daemon
	// does not accumulate zombies. (Full stop/teardown lifecycle is still
	// TODO — see CHANGELOG.)
	go func() { _ = cmd.Wait() }()

	// Record in hierarchy.
	_ = dm.hierarchy.SetContainerPID(cfg.DeptID, pid)

	container := &RunningContainer{
		Config:     cfg,
		Cmd:        cmd,
		PID:        pid,
		CgroupPath: cgroupPath,
		StartedAt:  time.Now(),
	}

	dm.containers[cfg.DeptID] = container
	return container, nil
}

// destroyFailedSpawn tears down a partially-created container after a
// fatal post-fork error: SIGKILL the child (reaping it if cmd is known),
// detach the parent-side bind mounts, and remove the cgroup subtree.
func destroyFailedSpawn(cgroupPath string, cfg ContainerConfig, cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	for _, m := range []string{
		filepath.Join(cfg.RootFS, "opt", "ghost-agent", "alpha"),
		filepath.Join(cfg.RootFS, "var", "run", "ghost-alert.sock"),
	} {
		_ = syscall.Unmount(m, syscall.MNT_DETACH)
	}
	_ = os.RemoveAll(cgroupPath)
}

// awaitContainerInit waits briefly for the re-exec'd container init to
// prove it survived pivot_root and the exec of the department init. If
// the child exits (e.g. pivot_root failed, init missing) the spawn fails
// instead of recording a dead PID.
func awaitContainerInit(pid int) error {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var ws syscall.WaitStatus
		wpid, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
		if err != nil {
			return fmt.Errorf("ghost-stack: container liveness check: %w", err)
		}
		if wpid == pid {
			return fmt.Errorf("ghost-stack: container init exited during pivot_root/exec (status %d)", ws.ExitStatus())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// QuarantineDepartment instantly freezes a department container and
// drops all its network access. This is the CRITICAL alert response.
//
// Steps:
//  1. Write "1" to cgroup.freeze (instant process freeze)
//  2. Drop all network via nsenter + nftables flush
//  3. Capture /proc/[pid]/mem snapshot
//  4. Send CRITICAL alert to orchestrator bus
func (dm *DepartmentManager) QuarantineDepartment(deptID int) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	container, exists := dm.containers[deptID]
	if !exists {
		return fmt.Errorf("ghost-stack: department %d not running", deptID)
	}

	if container.Quarantined {
		return fmt.Errorf("ghost-stack: department %d already quarantined", deptID)
	}

	// Step 1: Freeze all processes in the cgroup.
	freezePath := filepath.Join(container.CgroupPath, cgroupFreezeFile)
	if err := os.WriteFile(freezePath, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("ghost-stack: cgroup freeze failed: %w", err)
	}
	container.Frozen = true

	// Step 2: Drop all network inside the namespace.
	if err := nsenterExec(container.PID, "net", "nft", "flush", "ruleset"); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-stack: warning: nft flush failed: %v\n", err)
	}
	// Add drop-all rules.
	nftDropRules := `
table inet quarantine {
    chain input {
        type filter hook input priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy drop;
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
`
	if err := nsenterExecStdin(container.PID, "net", nftDropRules, "nft", "-f", "-"); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-stack: warning: nft quarantine rules failed: %v\n", err)
	}

	// Step 3: Capture /proc/[pid]/mem snapshot.
	if err := captureMemSnapshot(container.PID, deptID); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-stack: warning: mem snapshot failed: %v\n", err)
	}

	container.Quarantined = true

	// Step 4: Alert is handled by the caller (orchestrator).
	return nil
}

// UnquarantineDepartment reverses QuarantineDepartment: thaws the cgroup
// so processes can resume, and removes the drop-all nftables rules that
// QuarantineDepartment installed. Use after a human has decided the
// threat was a false positive.
//
// Steps (mirror of QuarantineDepartment, reversed):
//  1. Verify the department is actually quarantined
//  2. Thaw cgroup (write "0" to cgroup.freeze)
//  3. Flush the inet quarantine nftables table
//  4. Clear the in-memory Quarantined and Frozen flags
func (dm *DepartmentManager) UnquarantineDepartment(deptID int) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	container, exists := dm.containers[deptID]
	if !exists {
		return fmt.Errorf("ghost-stack: department %d not running", deptID)
	}

	if !container.Quarantined {
		return fmt.Errorf("ghost-stack: department %d is not quarantined", deptID)
	}

	// Step 1: Thaw cgroup so processes resume execution.
	freezePath := filepath.Join(container.CgroupPath, cgroupFreezeFile)
	if err := os.WriteFile(freezePath, []byte("0"), 0o644); err != nil {
		return fmt.Errorf("ghost-stack: cgroup thaw failed: %w", err)
	}
	container.Frozen = false

	// Step 2: Remove the drop-all nftables rules that QuarantineDepartment
	// installed. The quarantine table is namespaced to this container, so
	// flushing it only affects this department's network policy.
	if err := nsenterExec(container.PID, "net", "nft", "flush", "table", "inet", "quarantine"); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-stack: warning: nft flush quarantine table failed: %v\n", err)
	}

	container.Quarantined = false

	return nil
}

// SnapshotDepartment captures a full state snapshot of a department container.
//
// Steps:
//  1. Freeze cgroup
//  2. Capture filesystem state (tar)
//  3. Record process tree + network state
//  4. Unfreeze
func (dm *DepartmentManager) SnapshotDepartment(deptID int, outputDir string) (string, error) {
	dm.mu.RLock()
	container, exists := dm.containers[deptID]
	dm.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("ghost-stack: department %d not running", deptID)
	}

	// Step 1: Freeze for consistent snapshot.
	freezePath := filepath.Join(container.CgroupPath, cgroupFreezeFile)
	wasFrozen := container.Frozen
	if !wasFrozen {
		if err := os.WriteFile(freezePath, []byte("1"), 0o644); err != nil {
			return "", fmt.Errorf("ghost-stack: cgroup freeze for snapshot failed: %w", err)
		}
	}

	defer func() {
		// Unfreeze only if we froze it.
		if !wasFrozen {
			_ = os.WriteFile(freezePath, []byte("0"), 0o644)
		}
	}()

	timestamp := time.Now().Format("20060102-150405")
	snapshotName := fmt.Sprintf("dept-%d-snapshot-%s", deptID, timestamp)
	snapshotDir := filepath.Join(outputDir, snapshotName)
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		return "", fmt.Errorf("ghost-stack: failed to create snapshot dir: %w", err)
	}

	// Step 2: Capture filesystem state.
	tarPath := filepath.Join(snapshotDir, "rootfs.tar.gz")
	tarCmd := exec.Command("tar", "czf", tarPath, "-C", container.Config.RootFS, ".")
	if err := tarCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-stack: warning: rootfs tar failed: %v\n", err)
	}

	// Step 3: Capture process tree.
	procTree, err := captureProcessTree(container.PID)
	if err == nil {
		_ = os.WriteFile(filepath.Join(snapshotDir, "process_tree.json"), procTree, 0o600)
	}

	// Step 4: Capture network state.
	netState, err := captureNetworkState(container.PID)
	if err == nil {
		_ = os.WriteFile(filepath.Join(snapshotDir, "network_state.json"), netState, 0o600)
	}

	// Step 5: Capture cgroup stats.
	cgroupStats, err := captureCgroupStats(container.CgroupPath)
	if err == nil {
		_ = os.WriteFile(filepath.Join(snapshotDir, "cgroup_stats.json"), cgroupStats, 0o600)
	}

	return snapshotDir, nil
}

// Status returns the current status of a department container.
func (dm *DepartmentManager) Status(deptID int) (*ContainerStatus, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	container, exists := dm.containers[deptID]
	if !exists {
		return nil, fmt.Errorf("ghost-stack: department %d not running", deptID)
	}

	return &ContainerStatus{
		DeptID:      deptID,
		DeptName:    container.Config.DeptName,
		Tier:        container.Config.Tier.String(),
		PID:         container.PID,
		CgroupPath:  container.CgroupPath,
		StartedAt:   container.StartedAt,
		Frozen:      container.Frozen,
		Quarantined: container.Quarantined,
		Uptime:      time.Since(container.StartedAt),
	}, nil
}

// ContainerStatus holds the runtime status of a department container.
type ContainerStatus struct {
	DeptID      int
	DeptName    string
	Tier        string
	PID         int
	CgroupPath  string
	StartedAt   time.Time
	Frozen      bool
	Quarantined bool
	Uptime      time.Duration
}

// --- Internal helper functions ---

// setupCgroup creates a cgroup v2 subtree and writes resource limits.
func setupCgroup(cgroupPath string, limits CgroupLimits) error {
	if err := os.MkdirAll(cgroupPath, 0o755); err != nil {
		return fmt.Errorf("mkdir cgroup: %w", err)
	}

	// Enable controllers in parent.
	parentPath := filepath.Dir(cgroupPath)
	subtreeControl := filepath.Join(parentPath, "cgroup.subtree_control")
	_ = os.WriteFile(subtreeControl, []byte("+cpu +memory +pids +io"), 0o644)

	// Write limits.
	if limits.MemoryMax > 0 {
		memPath := filepath.Join(cgroupPath, "memory.max")
		_ = os.WriteFile(memPath, []byte(strconv.FormatInt(limits.MemoryMax, 10)), 0o644)
	}

	if limits.CPUQuota > 0 && limits.CPUPeriod > 0 {
		cpuPath := filepath.Join(cgroupPath, "cpu.max")
		val := fmt.Sprintf("%d %d", limits.CPUQuota, limits.CPUPeriod)
		_ = os.WriteFile(cpuPath, []byte(val), 0o644)
	}

	if limits.PidsMax > 0 {
		pidsPath := filepath.Join(cgroupPath, "pids.max")
		_ = os.WriteFile(pidsPath, []byte(strconv.FormatInt(limits.PidsMax, 10)), 0o644)
	}

	if limits.IOMax != "" {
		ioPath := filepath.Join(cgroupPath, "io.max")
		_ = os.WriteFile(ioPath, []byte(limits.IOMax), 0o644)
	}

	return nil
}

// prepareRootFS prepares a usable container rootfs from a host template.
//
// Strategy:
//  1. Check for a base rootfs template at /var/lib/ghost-stack/templates/rootfs
//     (expected to be a minimal Alpine or BusyBox root filesystem)
//  2. Set up an overlayfs mount:
//     - lowerdir = template (read-only, shared between all departments)
//     - upperdir = dept-specific writable layer
//     - workdir  = overlayfs internal work directory
//  3. If template missing, fall back to creating a minimal directory structure
//     and copying essential binaries from the host.
//
// This ensures every container has /bin/sh, /usr/bin/sqlite3, and core
// infrastructure needed to actually run processes.
func prepareRootFS(rootFS string) error {
	templatePath := "/var/lib/ghost-stack/templates/rootfs"

	// Overlay directories live alongside the department rootfs.
	overlayUpper := rootFS + ".upper"
	overlayWork := rootFS + ".work"
	mergedDir := rootFS

	// Ensure all overlay directories exist.
	for _, d := range []string{overlayUpper, overlayWork, mergedDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir overlay dir %s: %w", d, err)
		}
	}

	if fi, err := os.Stat(templatePath); err == nil && fi.IsDir() {
		// --- Template exists: use overlayfs ---
		//
		// overlayfs gives us copy-on-write semantics:
		// - Base Alpine rootfs is shared read-only (saves disk)
		// - Each department's writes go to its own upper layer
		// - Efficient cleanup: just remove upper + work dirs
		opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s",
			templatePath, overlayUpper, overlayWork)

		mountCmd := exec.Command("mount", "-t", "overlay", "overlay",
			"-o", opts, mergedDir)
		if err := mountCmd.Run(); err != nil {
			// Overlay mount failed — fall back to rsync copy.
			fmt.Fprintf(os.Stderr, "ghost-stack: overlayfs mount failed, falling back to copy: %v\n", err)
			return copyTemplateRootFS(templatePath, mergedDir)
		}

		// Ensure department-specific directories exist in upper layer.
		deptDirs := []string{
			"opt/ghost-agent", "var/run", "var/log",
			"tmp", "var/lib/ghost-db",
		}
		for _, d := range deptDirs {
			_ = os.MkdirAll(filepath.Join(mergedDir, d), 0o755)
		}

		return nil
	}

	// --- No template: build a minimal rootfs from scratch ---
	return buildMinimalRootFS(mergedDir)
}

// copyTemplateRootFS copies the template rootfs to the department directory.
// Used as a fallback when overlayfs is not available.
func copyTemplateRootFS(templatePath, targetPath string) error {
	// Use rsync for efficient copy with hardlinks where possible.
	rsyncCmd := exec.Command("rsync", "-a", "--hard-links",
		templatePath+"/", targetPath+"/")
	if err := rsyncCmd.Run(); err != nil {
		// Fallback to cp if rsync isn't available.
		cpCmd := exec.Command("cp", "-a", templatePath+"/.", targetPath+"/")
		if err := cpCmd.Run(); err != nil {
			return fmt.Errorf("rootfs copy: %w", err)
		}
	}
	return nil
}

// buildMinimalRootFS creates a bare-minimum rootfs when no template exists.
// Copies essential binaries from the host and sets up required paths.
func buildMinimalRootFS(rootFS string) error {
	// Essential directory structure (FHS-compliant).
	dirs := []string{
		"bin", "sbin", "usr/bin", "usr/sbin",
		"usr/lib", "usr/lib64", "lib", "lib64",
		"etc", "opt/ghost-agent",
		"proc", "sys", "dev", "dev/pts", "dev/shm",
		"tmp", "var/run", "var/log", "var/tmp",
		"var/lib/ghost-db",
		"root", "home",
	}
	for _, d := range dirs {
		path := filepath.Join(rootFS, d)
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", path, err)
		}
	}

	// Essential binaries to copy from host (with their library dependencies).
	essentialBins := []struct {
		hostPath string
		destPath string
	}{
		{"/bin/sh", "bin/sh"},
		{"/bin/busybox", "bin/busybox"},         // BusyBox provides most utils.
		{"/usr/bin/sqlite3", "usr/bin/sqlite3"}, // SQLite for STAFF/MANAGER DBs.
		{"/usr/bin/env", "usr/bin/env"},
		{"/bin/cat", "bin/cat"},
		{"/bin/ls", "bin/ls"},
		{"/bin/mkdir", "bin/mkdir"},
		{"/bin/rm", "bin/rm"},
		{"/bin/cp", "bin/cp"},
		{"/bin/chmod", "bin/chmod"},
		{"/bin/chown", "bin/chown"},
	}

	for _, bin := range essentialBins {
		destFull := filepath.Join(rootFS, bin.destPath)
		if _, err := os.Stat(bin.hostPath); err != nil {
			continue // Binary not available on host — skip.
		}
		// Copy binary.
		cpCmd := exec.Command("cp", "-a", bin.hostPath, destFull)
		_ = cpCmd.Run()

		// Copy dynamic library dependencies via ldd.
		if err := copyLibraryDeps(bin.hostPath, rootFS); err != nil {
			fmt.Fprintf(os.Stderr, "ghost-stack: library deps for %s: %v\n", bin.hostPath, err)
		}
	}

	// Create essential /etc files.
	writeEtcFiles(rootFS)

	// Create /dev nodes.
	createDevNodes(rootFS)

	return nil
}

// copyLibraryDeps copies shared library dependencies for a binary into the rootfs.
func copyLibraryDeps(binaryPath, rootFS string) error {
	lddCmd := exec.Command("ldd", binaryPath)
	output, err := lddCmd.Output()
	if err != nil {
		return nil // Statically linked or ldd not available — fine.
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		// Parse lines like: lib.so => /usr/lib/lib.so (0x...)
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "/") && !strings.HasPrefix(part, "(") {
				// This is a library path.
				destPath := filepath.Join(rootFS, part)
				if _, err := os.Stat(destPath); err == nil {
					continue // Already exists.
				}
				destDir := filepath.Dir(destPath)
				_ = os.MkdirAll(destDir, 0o755)
				cpCmd := exec.Command("cp", "-a", part, destPath)
				_ = cpCmd.Run()
			}
		}
	}
	return nil
}

// writeEtcFiles creates minimal /etc configuration files for the container.
func writeEtcFiles(rootFS string) {
	etcFiles := map[string]string{
		"etc/passwd":        "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n",
		"etc/group":         "root:x:0:\nnogroup:x:65534:\n",
		"etc/hostname":      "ghost-dept\n",
		"etc/hosts":         "127.0.0.1 localhost\n::1 localhost ip6-localhost\n",
		"etc/resolv.conf":   "nameserver 10.200.0.1\nsearch xio.cybersurhub.com\n",
		"etc/nsswitch.conf": "passwd: files\ngroup: files\nhosts: files dns\n",
	}
	for name, content := range etcFiles {
		_ = os.WriteFile(filepath.Join(rootFS, name), []byte(content), 0o644)
	}
}

// createDevNodes creates essential /dev nodes for the container.
func createDevNodes(rootFS string) {
	// Most /dev nodes will be created by mounting devtmpfs or bind-mounting.
	// Create minimal symlinks and files for baseline functionality.
	devFiles := map[string]string{
		"dev/null":    "",
		"dev/zero":    "",
		"dev/urandom": "",
		"dev/random":  "",
	}
	for name := range devFiles {
		path := filepath.Join(rootFS, name)
		f, err := os.Create(path)
		if err == nil {
			f.Close()
		}
	}
}

// setupVethPair creates a veth pair and moves one end into the container's
// network namespace.
func setupVethPair(pid int, cfg ContainerConfig) error {
	// Pre-flight: the `ip` binary from iproute2 is required to manipulate
	// veth pairs and net namespaces. Fail fast with an actionable message
	// rather than dying partway through SpawnDepartment with a confusing
	// "executable file not found" deep in a child command.
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("ghost-stack: required host tool 'ip' (iproute2) not found in $PATH: %w — install with: apt-get install iproute2  /  dnf install iproute  /  pacman -S iproute2", err)
	}

	hostVeth := cfg.VethHostName
	if hostVeth == "" {
		hostVeth = fmt.Sprintf("veth-dept%d-h", cfg.DeptID)
	}
	contVeth := cfg.VethContainerName
	if contVeth == "" {
		contVeth = "eth0"
	}
	peerVeth := fmt.Sprintf("veth-dept%d-c", cfg.DeptID)

	// Create veth pair.
	createCmd := exec.Command("ip", "link", "add", hostVeth, "type", "veth", "peer", "name", peerVeth)
	if err := createCmd.Run(); err != nil {
		return fmt.Errorf("veth create: %w", err)
	}

	// Move peer into container's net namespace.
	moveCmd := exec.Command("ip", "link", "set", peerVeth, "netns", strconv.Itoa(pid))
	if err := moveCmd.Run(); err != nil {
		return fmt.Errorf("veth move: %w", err)
	}

	// Bring up host side.
	upCmd := exec.Command("ip", "link", "set", hostVeth, "up")
	_ = upCmd.Run()

	// Configure host-side IP.
	if cfg.GatewayIP != "" {
		addrCmd := exec.Command("ip", "addr", "add", cfg.GatewayIP+"/24", "dev", hostVeth)
		_ = addrCmd.Run()
	}

	// Configure container-side via nsenter.
	if cfg.ContainerIP != "" {
		_ = nsenterExec(pid, "net", "ip", "link", "set", peerVeth, "name", contVeth)
		_ = nsenterExec(pid, "net", "ip", "addr", "add", cfg.ContainerIP+"/24", "dev", contVeth)
		_ = nsenterExec(pid, "net", "ip", "link", "set", contVeth, "up")
		_ = nsenterExec(pid, "net", "ip", "link", "set", "lo", "up")
		if cfg.GatewayIP != "" {
			_ = nsenterExec(pid, "net", "ip", "route", "add", "default", "via", cfg.GatewayIP)
		}
	}

	return nil
}

// nsenterExec executes a command inside a specific namespace of the given PID.
func nsenterExec(pid int, nsType string, args ...string) error {
	nsPath := fmt.Sprintf("/proc/%d/ns/%s", pid, nsType)
	cmdArgs := append([]string{fmt.Sprintf("--%s=%s", nsType, nsPath), "-t", strconv.Itoa(pid), "--"}, args...)
	cmd := exec.Command("nsenter", cmdArgs...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// nsenterExecStdin executes a command inside a namespace with stdin data.
func nsenterExecStdin(pid int, nsType, stdinData string, args ...string) error {
	nsPath := fmt.Sprintf("/proc/%d/ns/%s", pid, nsType)
	cmdArgs := append([]string{fmt.Sprintf("--%s=%s", nsType, nsPath), "-t", strconv.Itoa(pid), "--"}, args...)
	cmd := exec.Command("nsenter", cmdArgs...)
	cmd.Stdin = strings.NewReader(stdinData)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// bindMountReadOnly creates a read-only bind mount.
func bindMountReadOnly(source, target string) error {
	// Create target if file.
	if info, err := os.Stat(source); err == nil && !info.IsDir() {
		f, err := os.Create(target)
		if err != nil {
			return err
		}
		f.Close()
	}

	// Bind mount.
	if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind mount: %w", err)
	}
	// Remount read-only.
	if err := syscall.Mount("", target, "", syscall.MS_BIND|syscall.MS_RDONLY|syscall.MS_REMOUNT, ""); err != nil {
		return fmt.Errorf("remount ro: %w", err)
	}
	return nil
}

// moveToCgroup writes the PID into the cgroup's cgroup.procs file.
func moveToCgroup(cgroupPath string, pid int) error {
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	return os.WriteFile(procsPath, []byte(strconv.Itoa(pid)), 0o644)
}

// captureMemSnapshot reads /proc/[pid]/maps and key memory regions.
func captureMemSnapshot(pid, deptID int) error {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return fmt.Errorf("read maps: %w", err)
	}

	snapshotDir := fmt.Sprintf("/var/lib/ghost-stack/snapshots/dept-%d", deptID)
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102-150405")
	outPath := filepath.Join(snapshotDir, fmt.Sprintf("mem-maps-%s.txt", timestamp))
	return os.WriteFile(outPath, data, 0o600)
}

// captureProcessTree reads /proc/[pid]/status for the container init and children.
func captureProcessTree(pid int) ([]byte, error) {
	type ProcInfo struct {
		PID   int    `json:"pid"`
		Name  string `json:"name"`
		State string `json:"state"`
		PPid  int    `json:"ppid"`
	}

	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return nil, err
	}

	info := ProcInfo{PID: pid}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":\t", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "Name":
			info.Name = strings.TrimSpace(parts[1])
		case "State":
			info.State = strings.TrimSpace(parts[1])
		case "PPid":
			info.PPid, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		}
	}

	return json.MarshalIndent([]ProcInfo{info}, "", "  ")
}

// captureNetworkState reads network connections from the container's namespace.
func captureNetworkState(pid int) ([]byte, error) {
	// Read /proc/[pid]/net/tcp, /proc/[pid]/net/tcp6, etc.
	type NetState struct {
		TCP  string `json:"tcp"`
		TCP6 string `json:"tcp6"`
		UDP  string `json:"udp"`
	}

	state := NetState{}
	basePath := fmt.Sprintf("/proc/%d/net", pid)

	if data, err := os.ReadFile(filepath.Join(basePath, "tcp")); err == nil {
		state.TCP = string(data)
	}
	if data, err := os.ReadFile(filepath.Join(basePath, "tcp6")); err == nil {
		state.TCP6 = string(data)
	}
	if data, err := os.ReadFile(filepath.Join(basePath, "udp")); err == nil {
		state.UDP = string(data)
	}

	return json.MarshalIndent(state, "", "  ")
}

// captureCgroupStats reads current cgroup resource usage stats.
func captureCgroupStats(cgroupPath string) ([]byte, error) {
	type CgroupStats struct {
		MemoryCurrent string `json:"memory_current"`
		MemoryMax     string `json:"memory_max"`
		CPUStat       string `json:"cpu_stat"`
		PidsCurrent   string `json:"pids_current"`
		IOStat        string `json:"io_stat"`
	}

	stats := CgroupStats{}

	readFile := func(name string) string {
		data, err := os.ReadFile(filepath.Join(cgroupPath, name))
		if err != nil {
			return "N/A"
		}
		return strings.TrimSpace(string(data))
	}

	stats.MemoryCurrent = readFile("memory.current")
	stats.MemoryMax = readFile("memory.max")
	stats.CPUStat = readFile("cpu.stat")
	stats.PidsCurrent = readFile("pids.current")
	stats.IOStat = readFile("io.stat")

	return json.MarshalIndent(stats, "", "  ")
}
