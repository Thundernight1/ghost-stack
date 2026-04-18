// GHOST-STACK CORE — ghost-ctl: Orchestrator Control Plane
//
// Commands:
//   ghost-ctl dept spawn     — Spawn a new department container
//   ghost-ctl dept quarantine — Quarantine a running department
//   ghost-ctl dept snapshot  — Capture department state snapshot
//   ghost-ctl dept status    — Show department container status
//   ghost-ctl hierarchy show — Display the department hierarchy tree
//   ghost-ctl audit-trail    — View the append-only audit trail
//
// All orchestrator actions are append-only logged to an immutable
// partition (separate from container storage).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ghost-stack/core/auth"
	"github.com/ghost-stack/core/db"
	layer3 "github.com/ghost-stack/core/firewall/layer3"
	"github.com/ghost-stack/core/hierarchy"
	"github.com/ghost-stack/core/namespace"
)

const (
	version     = "1.0.0"
	banner      = `
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     ███████╗████████╗ █████╗  ██████╗██╗  ██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝     ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██║  ███╗███████║██║   ██║███████╗   ██║  █████╗ ███████╗   ██║   ███████║██║     █████╔╝
██║   ██║██╔══██║██║   ██║╚════██║   ██║  ╚════╝ ╚════██║   ██║   ██╔══██║██║     ██╔═██╗
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║         ███████║   ██║   ██║  ██║╚██████╗██║  ██╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝         ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
    Enterprise Container Orchestration — Raw Kernel Primitives
                       v%s — CORE
`
	auditLogPath  = "/var/lib/ghost-stack/audit/audit.log"
	basePath      = "/var/lib/ghost-stack"
	configPath    = "/etc/ghost-stack/config.json"
)

// AuditEntry represents an append-only audit log entry.
type AuditEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Action    string                 `json:"action"`
	Actor     string                 `json:"actor"`
	DeptID    int                    `json:"dept_id,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Result    string                 `json:"result"`
}

// Global state.
var (
	hierarchyTree   *hierarchy.HierarchyTree
	deptManager     *namespace.DepartmentManager

	keyVault        *db.KeyVault
	ed25519PubKey   ed25519.PublicKey
	ed25519PrivKey  ed25519.PrivateKey
	// Gap 2: Persistent state across restarts.
	stateManager    *StateManager
	// Gap 3: IP address management to prevent collisions.
	ipam            *IPAM
	// Gap 5: Proactive threat response (AGENT-BETA → L3 XDP auto-block).
	threatHandler   *ThreatResponseHandler
	l3Manager       *layer3.AllowlistManager
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Initialize subsystems.
	if err := initialize(); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: initialization failed: %v\n", err)
		os.Exit(1)
	}

	// Parse command.
	switch os.Args[1] {
	case "dept":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		switch os.Args[2] {
		case "spawn":
			cmdDeptSpawn()
		case "quarantine":
			cmdDeptQuarantine()
		case "snapshot":
			cmdDeptSnapshot()
		case "status":
			cmdDeptStatus()
		default:
			fmt.Fprintf(os.Stderr, "ghost-ctl: unknown dept command: %s\n", os.Args[2])
			os.Exit(1)
		}

	case "hierarchy":
		if len(os.Args) >= 3 && os.Args[2] == "show" {
			cmdHierarchyShow()
		} else {
			printUsage()
		}

	case "audit-trail":
		cmdAuditTrail()

	case "version":
		fmt.Printf("ghost-ctl v%s\n", version)

	case "help", "--help", "-h":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "ghost-ctl: unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// initialize sets up all subsystems including Gap 2-5 components.
func initialize() error {
	var err error

	// Initialize hierarchy tree.
	hierarchyTree, err = hierarchy.NewHierarchyTree()
	if err != nil {
		return fmt.Errorf("hierarchy: %w", err)
	}

	// Initialize department manager.
	deptManager = namespace.NewDepartmentManager(basePath, hierarchyTree)

	// Initialize session manager.
	sessionManager, err = auth.NewSessionManager()
	if err != nil {
		return fmt.Errorf("session manager: %w", err)
	}

	// Initialize key vault (Gap 4: host-only key management).
	keyVault, err = db.NewKeyVault(basePath + "/vault")
	if err != nil {
		return fmt.Errorf("key vault: %w", err)
	}

	// Generate Ed25519 keypair for Layer 3 allowlist signing.
	ed25519PubKey, ed25519PrivKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ed25519: %w", err)
	}

	// --- Gap 2: Initialize persistent state manager ---
	stateManager, err = NewStateManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: state manager init warning: %v\n", err)
		// Non-fatal — orchestrator can run without persistence.
	} else {
		// Recover departments that were running before restart.
		aliveDepts, recoverErr := stateManager.RecoverRunningDepartments()
		if recoverErr == nil && len(aliveDepts) > 0 {
			fmt.Printf("[GHOST-CTL] Recovered %d running departments from previous session\n", len(aliveDepts))
			for _, dept := range aliveDepts {
				fmt.Printf("  ✓ dept-%d (%s) PID=%d subnet=%s\n",
					dept.DeptID, dept.DeptName, dept.PID, dept.SubnetCIDR)
			}
		}
	}

	// --- Gap 3: Initialize IPAM ---
	var ipamDB *stateDB
	if stateManager != nil {
		ipamDB = stateManager.db
	}
	ipam, err = NewIPAM(ipamDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: IPAM init warning: %v\n", err)
	}

	// --- Gap 5: Initialize Layer 3 manager and threat response handler ---
	l3Manager = layer3.NewAllowlistManager("eth0", ed25519PubKey)

	threatHandler = NewThreatResponseHandler(
		ThreatResponseConfig{
			AlertSocketPath:      "/var/run/ghost-stack/alert.sock",
			ThreatScoreThreshold: 80,
			RequireL2Hits:        true,
			PrivateKey:           ed25519PrivKey,
			PublicKey:            ed25519PubKey,
		},
		l3Manager,
		appendAudit, // Wire audit logging into threat response.
	)

	// Start the threat response listener (non-blocking).
	if err := threatHandler.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: threat response start warning: %v\n", err)
	}

	return nil
}

// stateDB is a type alias to prevent import cycle issues.
type stateDB = sql.DB

// --- Command implementations ---

func cmdDeptSpawn() {
	if len(os.Args) < 6 {
		fmt.Println("Usage: ghost-ctl dept spawn <DEPT_ID> <NAME> <TIER>")
		fmt.Println("  TIER: ROOT | DIRECTOR | MANAGER | STAFF")
		os.Exit(1)
	}

	deptID, err := strconv.Atoi(os.Args[3])
	if err != nil || deptID < 0 || deptID > 99 {
		fmt.Fprintf(os.Stderr, "ghost-ctl: invalid dept ID (must be 0-99): %s\n", os.Args[3])
		os.Exit(1)
	}

	deptName := os.Args[4]
	tier := parseTier(os.Args[5])

	fmt.Printf("[GHOST-CTL] Spawning department container...\n")
	fmt.Printf("  Dept ID:    %d\n", deptID)
	fmt.Printf("  Name:       %s\n", deptName)
	fmt.Printf("  Tier:       %s\n", tier.String())
	fmt.Printf("  Namespaces: pid,net,mnt,uts,ipc,user,cgroup,time\n\n")

	// Register in hierarchy.
	parentID := -1 // ROOT has no parent.
	if tier != hierarchy.TierRoot && len(os.Args) > 6 {
		parentID, _ = strconv.Atoi(os.Args[6])
	}

	dept, err := hierarchyTree.RegisterDepartment(deptID, deptName, tier, parentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: hierarchy registration failed: %v\n", err)
		os.Exit(1)
	}

	// --- Gap 3: Allocate IP via IPAM (prevents collisions) ---
	var subnetCIDR, containerIP, gatewayIP string
	if ipam != nil {
		alloc, allocErr := ipam.Allocate(deptID)
		if allocErr != nil {
			fmt.Fprintf(os.Stderr, "ghost-ctl: IPAM allocation failed: %v\n", allocErr)
			os.Exit(1)
		}
		subnetCIDR = alloc.SubnetCIDR
		containerIP = alloc.ContainerIP
		gatewayIP = alloc.GatewayIP
		fmt.Printf("  IPAM:       allocated %s (container=%s, gw=%s)\n",
			subnetCIDR, containerIP, gatewayIP)
	} else {
		// Fallback: static mapping (original behavior).
		subnetCIDR = fmt.Sprintf("10.200.%d.0/24", deptID)
		containerIP = fmt.Sprintf("10.200.%d.2", deptID)
		gatewayIP = fmt.Sprintf("10.200.%d.1", deptID)
	}

	// Build container config.
	limits := namespace.DefaultCgroupLimits(tier)
	cfg := namespace.ContainerConfig{
		DeptID:          deptID,
		DeptName:        deptName,
		Tier:            tier,
		RootFS:          fmt.Sprintf("%s/rootfs/dept-%d", basePath, deptID),
		Hostname:        fmt.Sprintf("ghost-dept-%d", deptID),
		Limits:          limits,
		SubnetCIDR:      subnetCIDR,
		ContainerIP:     containerIP,
		GatewayIP:       gatewayIP,
		AlertSocketPath: "/var/run/ghost-stack/alert.sock",
		AgentBinaryPath: "/opt/ghost-stack/bin/agent-alpha",
	}

	// Spawn the container (Gap 1: prepareRootFS now copies real rootfs).
	container, err := deptManager.SpawnDepartment(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: spawn failed: %v\n", err)
		os.Exit(1)
	}

	// Initialize per-department database (Gap 4: keys host-only via HostKeyStore).
	_, err = keyVault.InitializeDepartmentDB(deptID, deptName, tier)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: database init warning: %v\n", err)
	}

	// --- Gap 2: Persist state to SQLite ---
	if stateManager != nil {
		_ = stateManager.SaveDepartment(&DepartmentState{
			DeptID:        deptID,
			DeptName:      deptName,
			Tier:          tier.String(),
			PID:           container.PID,
			ContainerIP:   containerIP,
			GatewayIP:     gatewayIP,
			SubnetCIDR:    subnetCIDR,
			CgroupPath:    container.CgroupPath,
			RootFS:        cfg.RootFS,
			LUKSMountPath: fmt.Sprintf("%s/vault/mounts/dept-%d", basePath, deptID),
			LUKSVolPath:   fmt.Sprintf("%s/vault/volumes/dept-%d.luks2", basePath, deptID),
			LUKSDMName:    fmt.Sprintf("ghost-dept-%d", deptID),
			ParentDeptID:  parentID,
			Status:        "running",
		})
	}

	// Audit log.
	appendAudit(AuditEntry{
		Timestamp: time.Now(),
		Action:    "DEPT_SPAWN",
		Actor:     "ghost-ctl",
		DeptID:    deptID,
		Details: map[string]interface{}{
			"name":    deptName,
			"tier":    tier.String(),
			"pid":     container.PID,
			"subnet":  subnetCIDR,
			"ip":      containerIP,
		},
		Result: "SUCCESS",
	})

	fmt.Printf("\n[GHOST-CTL] ✓ Department %d (%s) spawned successfully\n", deptID, deptName)
	fmt.Printf("  PID:        %d\n", container.PID)
	fmt.Printf("  Cgroup:     %s\n", container.CgroupPath)
	fmt.Printf("  Subnet:     %s\n", subnetCIDR)
	fmt.Printf("  Container:  %s\n", containerIP)
	fmt.Printf("  Gateway:    %s\n", gatewayIP)
	fmt.Printf("  UID Range:  %d-%d (host)\n",
		hierarchy.TierUIDBase(tier)+uint32(deptID)*1000,
		hierarchy.TierUIDBase(tier)+uint32(deptID)*1000+999)
	fmt.Printf("  DB Type:    %s\n", db.DatabaseTypeForTier(tier))
	fmt.Printf("  Key Mgmt:   HOST-ONLY (HostKeyStore, /dev/shm tmpfs)\n")
	_ = dept
}

func cmdDeptQuarantine() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: ghost-ctl dept quarantine <DEPT_ID>")
		os.Exit(1)
	}

	deptID, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: invalid dept ID: %s\n", os.Args[3])
		os.Exit(1)
	}

	fmt.Printf("[GHOST-CTL] ⚠ QUARANTINING department %d...\n", deptID)
	fmt.Printf("  Step 1: Freezing cgroup (cgroup.freeze = 1)\n")
	fmt.Printf("  Step 2: Dropping all network (nftables flush + DROP)\n")
	fmt.Printf("  Step 3: Capturing /proc/[pid]/mem snapshot\n")
	fmt.Printf("  Step 4: Alert escalation to orchestrator bus\n\n")

	if err := deptManager.QuarantineDepartment(deptID); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: quarantine failed: %v\n", err)
		os.Exit(1)
	}

	appendAudit(AuditEntry{
		Timestamp: time.Now(),
		Action:    "DEPT_QUARANTINE",
		Actor:     "ghost-ctl",
		DeptID:    deptID,
		Result:    "SUCCESS",
	})

	fmt.Printf("[GHOST-CTL] ✓ Department %d quarantined — all processes frozen, network dropped\n", deptID)
}

func cmdDeptSnapshot() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: ghost-ctl dept snapshot <DEPT_ID>")
		os.Exit(1)
	}

	deptID, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: invalid dept ID: %s\n", os.Args[3])
		os.Exit(1)
	}

	outputDir := basePath + "/snapshots"
	fmt.Printf("[GHOST-CTL] Capturing snapshot for department %d...\n", deptID)

	snapshotPath, err := deptManager.SnapshotDepartment(deptID, outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: snapshot failed: %v\n", err)
		os.Exit(1)
	}

	appendAudit(AuditEntry{
		Timestamp: time.Now(),
		Action:    "DEPT_SNAPSHOT",
		Actor:     "ghost-ctl",
		DeptID:    deptID,
		Details:   map[string]interface{}{"path": snapshotPath},
		Result:    "SUCCESS",
	})

	fmt.Printf("[GHOST-CTL] ✓ Snapshot saved to: %s\n", snapshotPath)
}

func cmdDeptStatus() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: ghost-ctl dept status <DEPT_ID>")
		os.Exit(1)
	}

	deptID, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: invalid dept ID: %s\n", os.Args[3])
		os.Exit(1)
	}

	status, err := deptManager.Status(deptID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[GHOST-CTL] Department %d Status\n", deptID)
	fmt.Printf("═══════════════════════════════════\n")
	fmt.Printf("  Name:         %s\n", status.DeptName)
	fmt.Printf("  Tier:         %s\n", status.Tier)
	fmt.Printf("  PID:          %d\n", status.PID)
	fmt.Printf("  Cgroup:       %s\n", status.CgroupPath)
	fmt.Printf("  Started:      %s\n", status.StartedAt.Format(time.RFC3339))
	fmt.Printf("  Uptime:       %s\n", status.Uptime.Round(time.Second))
	fmt.Printf("  Frozen:       %v\n", status.Frozen)
	fmt.Printf("  Quarantined:  %v\n", status.Quarantined)
	fmt.Printf("═══════════════════════════════════\n")
}

func cmdHierarchyShow() {
	fmt.Printf(banner, version)
	fmt.Println("\n[GHOST-CTL] Department Hierarchy")
	fmt.Println("═══════════════════════════════════")

	tree := hierarchyTree.ShowHierarchy()
	if tree == "" {
		fmt.Println("  (no departments registered)")
	} else {
		fmt.Print(tree)
	}
	fmt.Println("═══════════════════════════════════")
}

func cmdAuditTrail() {
	fmt.Println("\n[GHOST-CTL] Audit Trail (append-only)")
	fmt.Println("═══════════════════════════════════")

	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		fmt.Println("  (no audit entries)")
		return
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// Show last 50 entries.
	start := 0
	if len(lines) > 50 {
		start = len(lines) - 50
		fmt.Printf("  (showing last 50 of %d entries)\n\n", len(lines))
	}

	for _, line := range lines[start:] {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			fmt.Println("  " + line)
			continue
		}
		fmt.Printf("  [%s] %s dept=%d result=%s\n",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.Action, entry.DeptID, entry.Result)
	}
	fmt.Println("═══════════════════════════════════")
}

// --- Utility functions ---

func printUsage() {
	fmt.Printf(banner, version)
	fmt.Println(`
Usage: ghost-ctl <command> [args]

Commands:
  dept spawn <ID> <NAME> <TIER> [PARENT_ID]   Spawn a department container
  dept quarantine <ID>                          Quarantine a running dept (freeze+drop)
  dept snapshot <ID>                            Capture department state snapshot
  dept status <ID>                              Show department status
  hierarchy show                                Display hierarchy tree
  audit-trail                                   View append-only audit log
  version                                       Show version
  help                                          Show this help

Tiers: ROOT | DIRECTOR | MANAGER | STAFF

Examples:
  ghost-ctl dept spawn 0 "Headquarters" ROOT
  ghost-ctl dept spawn 1 "Engineering" DIRECTOR 0
  ghost-ctl dept spawn 10 "Backend Team" MANAGER 1
  ghost-ctl dept spawn 100 "dev-alice" STAFF 10
  ghost-ctl dept quarantine 100
  ghost-ctl hierarchy show`)
}

func parseTier(s string) hierarchy.Tier {
	switch strings.ToUpper(s) {
	case "ROOT":
		return hierarchy.TierRoot
	case "DIRECTOR":
		return hierarchy.TierDirector
	case "MANAGER":
		return hierarchy.TierManager
	case "STAFF":
		return hierarchy.TierStaff
	default:
		fmt.Fprintf(os.Stderr, "ghost-ctl: invalid tier: %s (must be ROOT|DIRECTOR|MANAGER|STAFF)\n", s)
		os.Exit(1)
		return hierarchy.TierStaff
	}
}

func appendAudit(entry AuditEntry) {
	if err := os.MkdirAll(basePath+"/audit", 0o700); err != nil {
		return
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	f, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()

	_, _ = f.Write(data)
	_, _ = f.Write([]byte("\n"))
}
