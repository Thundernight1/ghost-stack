// Package auth — scanner.go implements the 100 automated integrity scans
// per day per container for GHOST-STACK CORE.
//
// 100 scans/day = 1 scan every ~14.4 minutes.
// Each scan cycle performs 5 checks:
//   1. Filesystem hash verification (SHA-256 on critical paths)
//   2. Process list anomaly check vs baseline
//   3. Network connection state audit
//   4. cgroup resource usage delta check
//   5. Seccomp violation counter poll
//
// Results are sent to the alert bus via Unix domain socket.
// NOTHING is logged to the container filesystem.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanInterval is the time between integrity scans.
// 100 scans/day ≈ 1 scan every 14 minutes 24 seconds.
const ScanInterval = 24 * time.Hour / 100 // 864 seconds = 14m24s

// ScanType identifies the type of integrity scan.
type ScanType int

const (
	ScanFilesystemHash ScanType = iota
	ScanProcessAnomaly
	ScanNetworkAudit
	ScanCgroupDelta
	ScanSeccompViolation
)

// String returns the scan type name.
func (st ScanType) String() string {
	switch st {
	case ScanFilesystemHash:
		return "FILESYSTEM_HASH"
	case ScanProcessAnomaly:
		return "PROCESS_ANOMALY"
	case ScanNetworkAudit:
		return "NETWORK_AUDIT"
	case ScanCgroupDelta:
		return "CGROUP_DELTA"
	case ScanSeccompViolation:
		return "SECCOMP_VIOLATION"
	default:
		return "UNKNOWN"
	}
}

// ScanResult holds the result of a single integrity scan.
type ScanResult struct {
	// DeptID is the department container being scanned.
	DeptID int `json:"dept_id"`
	// ScanType identifies which scan was performed.
	Type string `json:"type"`
	// Timestamp is when the scan was performed.
	Timestamp time.Time `json:"timestamp"`
	// Status is "OK", "WARNING", or "CRITICAL".
	Status string `json:"status"`
	// Details contains scan-specific result data.
	Details map[string]interface{} `json:"details"`
	// Anomalies lists any detected anomalies.
	Anomalies []string `json:"anomalies,omitempty"`
}

// FilesystemBaseline stores SHA-256 hashes of critical filesystem paths.
type FilesystemBaseline struct {
	mu     sync.RWMutex
	hashes map[string]string // path -> SHA-256 hex
}

// ProcessBaseline stores the expected process list for anomaly detection.
type ProcessBaseline struct {
	mu        sync.RWMutex
	processes map[string]ProcessInfo
}

// ProcessInfo holds information about a single process.
type ProcessInfo struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	UID  int    `json:"uid"`
	Comm string `json:"comm"`
}

// CgroupSnapshot holds a point-in-time cgroup resource usage snapshot.
type CgroupSnapshot struct {
	MemoryUsage int64  `json:"memory_usage"`
	MemoryMax   int64  `json:"memory_max"`
	CPUUsage    int64  `json:"cpu_usage_usec"`
	PidsCount   int64  `json:"pids_count"`
	IORead      int64  `json:"io_read_bytes"`
	IOWrite     int64  `json:"io_write_bytes"`
	Timestamp   int64  `json:"timestamp"`
}

// IntegrityScanner performs 100 daily integrity scans per department container.
type IntegrityScanner struct {
	mu sync.Mutex

	// deptID identifies the department container being scanned.
	deptID int
	// containerPID is the init PID of the container.
	containerPID int
	// rootFS is the container's root filesystem path.
	rootFS string
	// cgroupPath is the container's cgroup v2 path.
	cgroupPath string
	// alertSocketPath is the Unix domain socket for sending scan results.
	alertSocketPath string

	// Baselines for anomaly detection.
	fsBaseline      *FilesystemBaseline
	procBaseline    *ProcessBaseline
	lastCgroupSnap  *CgroupSnapshot

	// Scan counter.
	scanCount      int
	totalAnomalies int
}

// CriticalPaths are the filesystem paths monitored by SHA-256 hash verification.
var CriticalPaths = []string{
	"/bin/sh",
	"/bin/bash",
	"/sbin/init",
	"/usr/bin/env",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/hosts",
	"/etc/resolv.conf",
	"/etc/nsswitch.conf",
	"/etc/ld.so.conf",
	"/lib/x86_64-linux-gnu/libc.so.6",
	"/lib/x86_64-linux-gnu/libpthread.so.0",
	"/opt/ghost-agent/alpha",
}

// NewIntegrityScanner creates a new scanner for a department container.
func NewIntegrityScanner(deptID, containerPID int, rootFS, cgroupPath, alertSocket string) *IntegrityScanner {
	return &IntegrityScanner{
		deptID:          deptID,
		containerPID:    containerPID,
		rootFS:          rootFS,
		cgroupPath:      cgroupPath,
		alertSocketPath: alertSocket,
		fsBaseline: &FilesystemBaseline{
			hashes: make(map[string]string),
		},
		procBaseline: &ProcessBaseline{
			processes: make(map[string]ProcessInfo),
		},
	}
}

// CaptureBaseline takes the initial baseline for all scan types.
// This must be called once after the container is spawned and verified clean.
func (is *IntegrityScanner) CaptureBaseline() error {
	is.mu.Lock()
	defer is.mu.Unlock()

	// Filesystem baseline.
	for _, path := range CriticalPaths {
		fullPath := filepath.Join(is.rootFS, path)
		hash, err := hashFile(fullPath)
		if err != nil {
			continue // File may not exist in minimal rootfs.
		}
		is.fsBaseline.hashes[path] = hash
	}

	// Process baseline.
	procs, err := listProcesses(is.containerPID)
	if err == nil {
		for _, p := range procs {
			key := fmt.Sprintf("%s-%d", p.Comm, p.PID)
			is.procBaseline.processes[key] = p
		}
	}

	// Cgroup baseline snapshot.
	snap, err := readCgroupSnapshot(is.cgroupPath)
	if err == nil {
		is.lastCgroupSnap = snap
	}

	return nil
}

// Run starts the 100 daily scan loop. Blocks until stopCh is closed.
func (is *IntegrityScanner) Run(stopCh <-chan struct{}) {
	ticker := time.NewTicker(ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			is.runFullScanCycle()
		}
	}
}

// runFullScanCycle performs all 5 scan types in sequence.
func (is *IntegrityScanner) runFullScanCycle() {
	is.mu.Lock()
	is.scanCount++
	scanNum := is.scanCount
	is.mu.Unlock()

	_ = scanNum // Used for logging context.

	// Scan 1: Filesystem hash verification.
	result1 := is.scanFilesystemHashes()
	is.sendResult(result1)

	// Scan 2: Process list anomaly check.
	result2 := is.scanProcessAnomalies()
	is.sendResult(result2)

	// Scan 3: Network connection state audit.
	result3 := is.scanNetworkState()
	is.sendResult(result3)

	// Scan 4: cgroup resource usage delta check.
	result4 := is.scanCgroupDelta()
	is.sendResult(result4)

	// Scan 5: Seccomp violation counter poll.
	result5 := is.scanSeccompViolations()
	is.sendResult(result5)
}

// scanFilesystemHashes computes SHA-256 on critical paths and compares with baseline.
func (is *IntegrityScanner) scanFilesystemHashes() *ScanResult {
	result := &ScanResult{
		DeptID:    is.deptID,
		Type:      ScanFilesystemHash.String(),
		Timestamp: time.Now(),
		Status:    "OK",
		Details:   make(map[string]interface{}),
	}

	is.fsBaseline.mu.RLock()
	defer is.fsBaseline.mu.RUnlock()

	checkedCount := 0
	mismatchCount := 0

	for path, baselineHash := range is.fsBaseline.hashes {
		fullPath := filepath.Join(is.rootFS, path)
		currentHash, err := hashFile(fullPath)
		if err != nil {
			result.Anomalies = append(result.Anomalies,
				fmt.Sprintf("MISSING: %s (was present in baseline)", path))
			mismatchCount++
			continue
		}

		if currentHash != baselineHash {
			result.Anomalies = append(result.Anomalies,
				fmt.Sprintf("MODIFIED: %s (baseline=%s current=%s)", path, baselineHash[:16], currentHash[:16]))
			mismatchCount++
		}
		checkedCount++
	}

	result.Details["files_checked"] = checkedCount
	result.Details["mismatches"] = mismatchCount

	if mismatchCount > 0 {
		result.Status = "CRITICAL"
	}

	return result
}

// scanProcessAnomalies checks the current process list against the baseline.
func (is *IntegrityScanner) scanProcessAnomalies() *ScanResult {
	result := &ScanResult{
		DeptID:    is.deptID,
		Type:      ScanProcessAnomaly.String(),
		Timestamp: time.Now(),
		Status:    "OK",
		Details:   make(map[string]interface{}),
	}

	currentProcs, err := listProcesses(is.containerPID)
	if err != nil {
		result.Status = "WARNING"
		result.Anomalies = append(result.Anomalies, fmt.Sprintf("Failed to list processes: %v", err))
		return result
	}

	is.procBaseline.mu.RLock()
	baselineComms := make(map[string]bool)
	for _, p := range is.procBaseline.processes {
		baselineComms[p.Comm] = true
	}
	is.procBaseline.mu.RUnlock()

	// Check for unexpected processes.
	for _, p := range currentProcs {
		if !baselineComms[p.Comm] {
			result.Anomalies = append(result.Anomalies,
				fmt.Sprintf("UNEXPECTED_PROCESS: %s (PID=%d, UID=%d)", p.Comm, p.PID, p.UID))
		}
	}

	result.Details["current_count"] = len(currentProcs)
	result.Details["baseline_count"] = len(baselineComms)
	result.Details["unexpected"] = len(result.Anomalies)

	if len(result.Anomalies) > 0 {
		result.Status = "WARNING"
	}
	if len(result.Anomalies) > 3 {
		result.Status = "CRITICAL"
	}

	return result
}

// scanNetworkState audits current network connections in the container namespace.
func (is *IntegrityScanner) scanNetworkState() *ScanResult {
	result := &ScanResult{
		DeptID:    is.deptID,
		Type:      ScanNetworkAudit.String(),
		Timestamp: time.Now(),
		Status:    "OK",
		Details:   make(map[string]interface{}),
	}

	// Read TCP connections from the container's network namespace.
	tcpPath := fmt.Sprintf("/proc/%d/net/tcp", is.containerPID)
	tcpData, err := os.ReadFile(tcpPath)
	if err != nil {
		result.Status = "WARNING"
		result.Anomalies = append(result.Anomalies, fmt.Sprintf("Cannot read TCP state: %v", err))
		return result
	}

	lines := strings.Split(string(tcpData), "\n")
	connCount := 0
	listenCount := 0
	establishedCount := 0

	for _, line := range lines[1:] { // Skip header.
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		connCount++
		state := fields[3]
		switch state {
		case "0A": // LISTEN
			listenCount++
		case "01": // ESTABLISHED
			establishedCount++
		}
	}

	result.Details["total_connections"] = connCount
	result.Details["listening"] = listenCount
	result.Details["established"] = establishedCount

	// Anomaly: unexpected listening ports or high connection count.
	if listenCount > 10 {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("HIGH_LISTEN_COUNT: %d ports listening", listenCount))
		result.Status = "WARNING"
	}
	if establishedCount > 50 {
		result.Anomalies = append(result.Anomalies,
			fmt.Sprintf("HIGH_CONN_COUNT: %d established connections", establishedCount))
		result.Status = "WARNING"
	}

	return result
}

// scanCgroupDelta checks resource usage deltas against the last snapshot.
func (is *IntegrityScanner) scanCgroupDelta() *ScanResult {
	result := &ScanResult{
		DeptID:    is.deptID,
		Type:      ScanCgroupDelta.String(),
		Timestamp: time.Now(),
		Status:    "OK",
		Details:   make(map[string]interface{}),
	}

	currentSnap, err := readCgroupSnapshot(is.cgroupPath)
	if err != nil {
		result.Status = "WARNING"
		result.Anomalies = append(result.Anomalies, fmt.Sprintf("Cannot read cgroup stats: %v", err))
		return result
	}

	result.Details["memory_usage_mb"] = currentSnap.MemoryUsage / (1024 * 1024)
	result.Details["memory_max_mb"] = currentSnap.MemoryMax / (1024 * 1024)
	result.Details["pids_count"] = currentSnap.PidsCount
	result.Details["cpu_usage_sec"] = currentSnap.CPUUsage / 1000000

	if is.lastCgroupSnap != nil {
		// Check for memory spike.
		memDelta := currentSnap.MemoryUsage - is.lastCgroupSnap.MemoryUsage
		if currentSnap.MemoryMax > 0 {
			memPct := float64(currentSnap.MemoryUsage) / float64(currentSnap.MemoryMax) * 100
			result.Details["memory_pct"] = fmt.Sprintf("%.1f%%", memPct)
			if memPct > 90 {
				result.Anomalies = append(result.Anomalies,
					fmt.Sprintf("MEMORY_CRITICAL: %.1f%% of max", memPct))
				result.Status = "CRITICAL"
			} else if memPct > 75 {
				result.Anomalies = append(result.Anomalies,
					fmt.Sprintf("MEMORY_HIGH: %.1f%% of max", memPct))
				result.Status = "WARNING"
			}
		}
		result.Details["memory_delta_mb"] = memDelta / (1024 * 1024)

		// Check for PID spike.
		pidDelta := currentSnap.PidsCount - is.lastCgroupSnap.PidsCount
		if pidDelta > 50 {
			result.Anomalies = append(result.Anomalies,
				fmt.Sprintf("PID_SPIKE: %d new processes since last scan", pidDelta))
			result.Status = "WARNING"
		}
	}

	// Update last snapshot.
	is.mu.Lock()
	is.lastCgroupSnap = currentSnap
	is.mu.Unlock()

	return result
}

// scanSeccompViolations reads the seccomp violation counters.
func (is *IntegrityScanner) scanSeccompViolations() *ScanResult {
	result := &ScanResult{
		DeptID:    is.deptID,
		Type:      ScanSeccompViolation.String(),
		Timestamp: time.Now(),
		Status:    "OK",
		Details:   make(map[string]interface{}),
	}

	// Read seccomp notifier counts from /proc/[pid]/status.
	statusPath := fmt.Sprintf("/proc/%d/status", is.containerPID)
	data, err := os.ReadFile(statusPath)
	if err != nil {
		result.Status = "WARNING"
		result.Anomalies = append(result.Anomalies, fmt.Sprintf("Cannot read proc status: %v", err))
		return result
	}

	seccompFields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Seccomp:") || strings.HasPrefix(line, "Seccomp_filters:") {
			parts := strings.SplitN(line, ":\t", 2)
			if len(parts) == 2 {
				seccompFields[parts[0]] = strings.TrimSpace(parts[1])
			}
		}
	}

	result.Details["seccomp_status"] = seccompFields

	// Check for seccomp audit log entries.
	// In production, this reads from the kernel audit subsystem directly.
	auditLogPath := fmt.Sprintf("/var/log/ghost-stack/seccomp-dept-%d.log", is.deptID)
	if data, err := os.ReadFile(auditLogPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		violationCount := len(lines)
		result.Details["violation_count"] = violationCount

		if violationCount > 0 {
			result.Anomalies = append(result.Anomalies,
				fmt.Sprintf("SECCOMP_VIOLATIONS: %d violations detected", violationCount))
			result.Status = "CRITICAL"
		}
	}

	return result
}

// sendResult sends a scan result to the alert bus via Unix domain socket.
// Results are NEVER written to the container filesystem.
func (is *IntegrityScanner) sendResult(result *ScanResult) {
	if is.alertSocketPath == "" {
		return
	}

	data, err := json.Marshal(result)
	if err != nil {
		return
	}

	conn, err := net.Dial("unix", is.alertSocketPath)
	if err != nil {
		return
	}
	defer conn.Close()

	// Write length-prefixed message.
	header := fmt.Sprintf("SCAN:%d:", len(data))
	conn.Write([]byte(header))
	conn.Write(data)
}

// --- Helper functions ---

// hashFile computes SHA-256 of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// listProcesses reads the process list from /proc for a given container init PID.
func listProcesses(initPID int) ([]ProcessInfo, error) {
	// Read /proc/[pid]/task to find all threads,
	// then enumerate /proc to find children.
	var procs []ProcessInfo

	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		statusPath := filepath.Join(procDir, entry.Name(), "status")
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		info := ProcessInfo{PID: pid}
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":\t", 2)
			if len(parts) != 2 {
				continue
			}
			val := strings.TrimSpace(parts[1])
			switch parts[0] {
			case "Name":
				info.Name = val
				info.Comm = val
			case "PPid":
				info.PPID, _ = strconv.Atoi(val)
			case "Uid":
				fields := strings.Fields(val)
				if len(fields) > 0 {
					info.UID, _ = strconv.Atoi(fields[0])
				}
			}
		}

		// Check if this process is inside our container (child of init).
		if isChildOf(pid, initPID) {
			procs = append(procs, info)
		}
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}

// isChildOf checks if pid is a descendant of parentPID by walking PPid chain.
func isChildOf(pid, parentPID int) bool {
	current := pid
	for i := 0; i < 100; i++ { // Max depth to prevent loops.
		if current == parentPID {
			return true
		}
		if current <= 1 {
			return false
		}
		statusPath := fmt.Sprintf("/proc/%d/status", current)
		data, err := os.ReadFile(statusPath)
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				parts := strings.SplitN(line, ":\t", 2)
				if len(parts) == 2 {
					ppid, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
					current = ppid
					break
				}
			}
		}
	}
	return false
}

// readCgroupSnapshot reads current cgroup v2 resource usage.
func readCgroupSnapshot(cgroupPath string) (*CgroupSnapshot, error) {
	snap := &CgroupSnapshot{
		Timestamp: time.Now().Unix(),
	}

	readInt := func(filename string) int64 {
		data, err := os.ReadFile(filepath.Join(cgroupPath, filename))
		if err != nil {
			return 0
		}
		val, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		return val
	}

	snap.MemoryUsage = readInt("memory.current")
	snap.MemoryMax = readInt("memory.max")
	snap.PidsCount = readInt("pids.current")

	// Parse cpu.stat for usage_usec.
	cpuStatPath := filepath.Join(cgroupPath, "cpu.stat")
	if data, err := os.ReadFile(cpuStatPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "usage_usec") {
				parts := strings.Fields(line)
				if len(parts) == 2 {
					snap.CPUUsage, _ = strconv.ParseInt(parts[1], 10, 64)
				}
			}
		}
	}

	// Parse io.stat for read/write bytes.
	ioStatPath := filepath.Join(cgroupPath, "io.stat")
	if data, err := os.ReadFile(ioStatPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "rbytes=") {
					val, _ := strconv.ParseInt(strings.TrimPrefix(f, "rbytes="), 10, 64)
					snap.IORead += val
				}
				if strings.HasPrefix(f, "wbytes=") {
					val, _ := strconv.ParseInt(strings.TrimPrefix(f, "wbytes="), 10, 64)
					snap.IOWrite += val
				}
			}
		}
	}

	return snap, nil
}
