// GHOST-STACK CORE — ghost-ctl: Orchestrator Control Plane
//
// Commands:
//
//	ghost-ctl dept spawn     — Spawn a new department container
//	ghost-ctl dept quarantine — Quarantine a running department
//	ghost-ctl dept unquarantine — Reverse a prior quarantine
//	ghost-ctl dept snapshot  — Capture department state snapshot
//	ghost-ctl dept status    — Show department container status
//	ghost-ctl hierarchy show — Display the department hierarchy tree
//	ghost-ctl audit-trail    — View the append-only audit trail
//
// All orchestrator actions are append-only logged (hash-chained, fsync'd,
// optional chattr +a) to a dedicated directory separate from container
// storage. "Immutable" is not claimed: root can rotate the log via the
// rename-based logrotate config, and each rotated segment stays
// self-verifying through its AUDIT_CHAIN_ROTATED genesis entry.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghost-stack/core/auth"
	"github.com/ghost-stack/core/db"
	layer3 "github.com/ghost-stack/core/firewall/layer3"
	"github.com/ghost-stack/core/hierarchy"
	"github.com/ghost-stack/core/namespace"
)

const (
	version = "1.0.0"
	banner  = `
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     ███████╗████████╗ █████╗  ██████╗██╗  ██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝     ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██║  ███╗███████║██║   ██║███████╗   ██║  █████╗ ███████╗   ██║   ███████║██║     █████╔╝
██║   ██║██╔══██║██║   ██║╚════██║   ██║  ╚════╝ ╚════██║   ██║   ██╔══██║██║     ██╔═██╗
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║         ███████║   ██║   ██║  ██║╚██████╗██║  ██╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝         ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
    Enterprise Container Orchestration — Raw Kernel Primitives
                       v%s — CORE`

	// helpFlag and hFlag are the well-known command-line flags for
	// requesting usage text. Extracted to avoid repeated string literals
	// in conditionals throughout the command parser.
	helpFlag = "--help"
	hFlag    = "-h"

	// alertSocketPath is the unix domain socket where AGENT-ALPHA and
	// AGENT-BETA deliver correlation alerts to the orchestrator's threat
	// handler. Kept as a constant so systemd units, agent configs, and
	// the orchestrator all source the same path without copy-paste drift.
	alertSocketPath = "/var/run/ghost-stack/alert.sock"

	// deptHostnameFmt is the template used to generate deterministic,
	// human-readable hostnames for department containers.
	deptHostnameFmt = "ghost-dept-%d"
)

// On-disk paths used by the orchestrator. These are package-level vars
// (not consts) so tests in this package can redirect them at t.TempDir()
// to avoid touching the host filesystem.
var (
	auditLogPath = ghostEnvOr("GHOST_AUDIT_PATH", "/var/lib/ghost-stack/audit/audit.log")
	basePath     = ghostEnvOr("GHOST_BASE_PATH", "/var/lib/ghost-stack")
)

// ghostEnvOr returns the environment variable or the default. Defined here
// (before its first use in the var block above) so on-disk paths honor the
// systemd unit's Environment= directives.
func ghostEnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// deptNamePattern restricts department names to a safe subset so they
// cannot smuggle whitespace, shell metacharacters, or path separators
// into downstream consumers (audit log, cgroup paths, BPF labels).
var deptNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// AuditEntry represents an append-only audit log entry.
// PrevHash chains each entry to the previous one (SHA-256 hex), giving the
// log tamper-evidence: any modification of history breaks the chain, which
// `ghost-ctl audit-trail --verify` detects.
type AuditEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Action    string                 `json:"action"`
	Actor     string                 `json:"actor"`
	DeptID    int                    `json:"dept_id,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Result    string                 `json:"result"`
	PrevHash  string                 `json:"prev_hash,omitempty"`
}

// Global state.
var (
	hierarchyTree *hierarchy.HierarchyTree
	deptManager   *namespace.DepartmentManager

	// sessionMgr is the orchestrator's auth session manager. It is created
	// once in initialize() and used by the daemon (token rotation, expiry
	// cleanup) and the `auth` commands — never discarded.
	sessionMgr *auth.SessionManager

	keyVault       *db.KeyVault
	ed25519PubKey  ed25519.PublicKey
	ed25519PrivKey ed25519.PrivateKey
	// Gap 2: Persistent state across restarts.
	stateManager *StateManager
	// Gap 3: IP address management to prevent collisions.
	ipam *IPAM
	// Gap 5: Proactive threat response (AGENT-BETA → L3 XDP auto-block).
	// threatHandler is created and started ONLY by the daemon
	// (startThreatListener); short-lived CLI commands never open the
	// alert socket.
	threatHandler *ThreatResponseHandler
	l3Manager     *layer3.AllowlistManager

	// initOnce makes initialize() idempotent: repeated calls return the
	// first call's result without re-running subsystem bring-up.
	initOnce sync.Once
	initErr  error

	// xdpObjectPath is the compiled Layer 3 XDP program. The attach is
	// best-effort: without it the allowlist still works in-memory.
	xdpObjectPath = "/opt/ghost-stack/bpf/layer3_invisible.bpf.o"
)

func main() {
	// Re-exec target for department containers (see namespace.ContainerInit).
	// SpawnDepartment starts /proc/self/exe with argv [..., "container-init"]
	// and CLONE_NEW* flags; this branch runs inside the child's fresh
	// namespaces and never touches daemon state — no initialize(), no
	// listeners, no sessions. On success ContainerInit execs the department
	// init and never returns.
	if len(os.Args) > 1 && os.Args[1] == "container-init" {
		if err := namespace.ContainerInit(); err != nil {
			fmt.Fprintf(os.Stderr, "ghost-ctl container-init: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0) // unreachable on success
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	// Top-level help interception. `ghost-ctl --help` / `-h` print the
	// general usage; subcommand forms like `ghost-ctl dept spawn --help`
	// are handled inside their respective subcommand dispatchers.
	if isHelpFlag(cmd) {
		printUsage()
		return
	}

	// Initialize subsystems unless it's a no-init command. self-check
	// is a preflight (systemd's ExecStartPre=) and must not open the
	// alert socket or start the threat handler — that's the daemon's
	// job. --help interception is already handled above and would have
	// exited, so "help" here is just for completeness.
	if needInitialize(cmd) {
		if err := initialize(); err != nil {
			fmt.Fprintf(os.Stderr, "ghost-ctl: initialization failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse command.
	switch cmd {
	case "dept":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		// Subcommand-level help interception.
		if isHelpFlag(os.Args[2]) {
			printUsage()
			return
		}
		switch os.Args[2] {
		case "spawn":
			cmdDeptSpawn()
		case "quarantine":
			cmdDeptQuarantine()
		case "unquarantine":
			cmdDeptUnquarantine()
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

	case "auth":
		if len(os.Args) >= 3 && os.Args[2] == "status" {
			cmdAuthStatus()
		} else {
			printUsage()
		}

	case "self-check":
		// systemd ExecStartPre=: exit fast with a clear code (see
		// cmdSelfCheck contract for code meanings).
		os.Exit(cmdSelfCheck())

	case "daemon":
		cmdDaemon()

	case "version":
		fmt.Printf("ghost-ctl v%s\n", version)

	case "help", helpFlag, hFlag:
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "ghost-ctl: unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// initialize sets up all subsystems including Gap 2-5 components.
// It is idempotent: the first call runs the full bring-up, later calls
// return the first call's result without repeating any work.
func initialize() error {
	initOnce.Do(func() {
		initErr = initializeOnce()
	})
	return initErr
}

// initializeOnce performs the actual one-time subsystem bring-up.
func initializeOnce() error {
	var err error

	// Initialize hierarchy tree.
	hierarchyTree, err = hierarchy.NewHierarchyTree()
	if err != nil {
		return fmt.Errorf("hierarchy: %w", err)
	}

	// Initialize department manager.
	deptManager = namespace.NewDepartmentManager(basePath, hierarchyTree)

	// Initialize session manager. Stored in the global sessionMgr — shared
	// by the daemon (rotation/cleanup loops) and the `auth` commands.
	sessionMgr, err = auth.NewSessionManager()
	if err != nil {
		return fmt.Errorf("session manager: %w", err)
	}

	// Initialize key vault (Gap 4: host-only key management).
	keyVault, err = db.NewKeyVault(basePath + "/vault")
	if err != nil {
		return fmt.Errorf("key vault: %w", err)
	}

	// Load or generate the Ed25519 orchestrator keypair.
	if err := loadOrGenerateEd25519Keys(); err != nil {
		return err
	}

	// --- Gap 2: Initialize persistent state manager ---
	stateManager, err = NewStateManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: state manager init failed: %v\n", err)
		os.Exit(1)
	}
	recoverRunningDepartments()

	// --- Gap 3: Initialize IPAM ---
	if err := initIPAM(); err != nil {
		// Warning already printed inside initIPAM.
	}

	// --- Gap 5: Initialize Layer 3 manager ---
	// NOTE: the AGENT-BETA threat listener is NOT started here — see
	// startThreatListener(), which the daemon calls. Short-lived CLI
	// commands share the allowlist manager in-memory but never open the
	// alert socket.
	l3Manager = layer3.NewAllowlistManager("eth0", ed25519PubKey)

	// Attach the Layer 3 XDP program if a compiled object is present.
	// Best-effort: in dev/CI environments there is no BPF object and no
	// privileges; the allowlist manager still works in-memory and the
	// orchestrator keeps running. Production needs CAP_BPF (or root) and
	// the compiled object at xdpObjectPath — see systemd units.
	if objPath := ghostEnvOr("GHOST_XDP_OBJECT", xdpObjectPath); objPath != "" {
		if _, statErr := os.Stat(objPath); statErr == nil {
			if err := l3Manager.LoadAndAttach(objPath); err != nil {
				fmt.Fprintf(os.Stderr, "ghost-ctl: XDP attach failed (continuing without kernel enforcement): %v\n", err)
			} else {
				fmt.Println("ghost-ctl: XDP program attached")
			}
		}
	}

	return nil
}

// startThreatListener creates and starts the AGENT-BETA threat response
// listener. Called ONLY by the daemon: short-lived CLI commands must not
// open (and thereby steal) the alert socket.
func startThreatListener() error {
	if threatHandler != nil {
		return nil // already running
	}
	threatHandler = NewThreatResponseHandler(
		ThreatResponseConfig{
			AlertSocketPath:      ghostEnvOr("GHOST_ALERT_SOCKET", alertSocketPath),
			ThreatScoreThreshold: 80,
			RequireL2Hits:        true,
			PrivateKey:           ed25519PrivKey,
			PublicKey:            ed25519PubKey,
		},
		l3Manager,
		appendAudit, // Wire audit logging into threat response.
	)
	if err := threatHandler.Start(); err != nil {
		threatHandler = nil
		return err
	}
	return nil
}

// stateDB is a type alias to prevent import cycle issues.
type stateDB = sql.DB

// --- Command implementations ---

func cmdDeptSpawn() {
	// Per-subcommand help: if --help / -h appears anywhere in the args
	// (typical forms: `ghost-ctl dept spawn --help` or `--help` as the
	// first arg after `spawn`), print the targeted usage and exit cleanly.
	for _, a := range os.Args {
		if a == helpFlag || a == hFlag {
			printSpawnUsage()
			return
		}
	}

	if len(os.Args) < 6 {
		printSpawnUsage()
		os.Exit(1)
	}

	deptID, err := strconv.Atoi(os.Args[3])
	if err != nil || deptID < 0 || deptID > 99 {
		fmt.Fprintf(os.Stderr, "ghost-ctl: invalid dept ID (must be 0-99): %s\n", os.Args[3])
		os.Exit(1)
	}

	deptName := os.Args[4]
	if !deptNamePattern.MatchString(deptName) {
		fmt.Fprintf(os.Stderr, "ghost-ctl: invalid department name %q (must match ^[a-zA-Z0-9_-]+$)\n", deptName)
		os.Exit(1)
	}
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

	// --- Gap 3: build config + spawn ---------------------------------------------------------------
	cfg, subnetCIDR, containerIP, gatewayIP, cfgErr := newSpawnConfig(deptID, deptName, tier, parentID)
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: spawn config failed: %v\n", cfgErr)
		os.Exit(1)
	}
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
	persistSpawnState(deptID, deptName, tier, parentID, container, subnetCIDR, containerIP, gatewayIP)

	// Audit log.
	appendAudit(AuditEntry{
		Timestamp: time.Now(),
		Action:    "DEPT_SPAWN",
		Actor:     "ghost-ctl",
		DeptID:    deptID,
		Details: map[string]interface{}{
			"name":   deptName,
			"tier":   tier.String(),
			"pid":    container.PID,
			"subnet": subnetCIDR,
			"ip":     containerIP,
		},
		Result: "SUCCESS",
	})

	printSpawnSuccess(deptID, deptName, container, subnetCIDR, containerIP, gatewayIP, tier)
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

func cmdDeptUnquarantine() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: ghost-ctl dept unquarantine <DEPT_ID>")
		os.Exit(1)
	}

	deptID, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: invalid dept ID: %s\n", os.Args[3])
		os.Exit(1)
	}

	fmt.Printf("[GHOST-CTL] ⚠ UNQUARANTINING department %d...\n", deptID)
	fmt.Printf("  Step 1: Thawing cgroup (cgroup.freeze = 0)\n")
	fmt.Printf("  Step 2: Removing drop-all nftables rules\n\n")

	if err := deptManager.UnquarantineDepartment(deptID); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: unquarantine failed: %v\n", err)
		os.Exit(1)
	}

	appendAudit(AuditEntry{
		Timestamp: time.Now(),
		Action:    "DEPT_UNQUARANTINE",
		Actor:     "ghost-ctl",
		DeptID:    deptID,
		Result:    "SUCCESS",
	})

	fmt.Printf("[GHOST-CTL] ✓ Department %d unquarantined — processes resumed, network restored\n", deptID)
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
	// --verify replays the hash chain and reports tampering.
	for _, a := range os.Args[2:] {
		if a == "--verify" {
			n, err := verifyAuditChain()
			if err != nil {
				fmt.Fprintf(os.Stderr, "audit-trail: VERIFY FAILED after %d entries: %v\n", n, err)
				os.Exit(1)
			}
			fmt.Printf("audit-trail: chain verified — %d entries, no tampering detected\n", n)
			return
		}
	}

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

// cmdAuthStatus reports auth subsystem state: active session count and
// registered device count. Proves the global session manager is live and
// wired into the command path (previously constructed and discarded).
func cmdAuthStatus() {
	fmt.Println("\n[GHOST-CTL] Auth Status")
	fmt.Println("═══════════════════════")
	fmt.Printf("  active sessions : %d\n", sessionMgr.ActiveSessionCount())
	fmt.Printf("  registered devs : %d\n", sessionMgr.RegisteredDeviceCount())
	fmt.Println("═══════════════════════")
}

func printUsage() {
	fmt.Printf(banner, version)
	fmt.Println(`
Usage: ghost-ctl <command> [args]

Commands:
  dept spawn <ID> <NAME> <TIER> [PARENT_ID]   Spawn a department container
  dept quarantine <ID>                          Quarantine a running dept (freeze+drop)
  dept unquarantine <ID>                        Reverse a prior quarantine (thaw+restore net)
  dept snapshot <ID>                            Capture department state snapshot
  dept status <ID>                              Show department status
  hierarchy show                                Display hierarchy tree
  audit-trail [--verify]                        View append-only audit log / verify hash chain
  auth status                                   Show auth session/device counts
  version                                       Show version
  help                                          Show this help

Tiers: ROOT | DIRECTOR | MANAGER | STAFF

Examples:
  ghost-ctl dept spawn 0 "Headquarters" ROOT
  ghost-ctl dept spawn 1 "Engineering" DIRECTOR 0
  ghost-ctl dept spawn 10 "Backend Team" MANAGER 1
  ghost-ctl dept spawn 100 "dev-alice" STAFF 10
  ghost-ctl dept quarantine 100
  ghost-ctl dept unquarantine 100
  ghost-ctl hierarchy show`)
}

// printSpawnUsage prints the targeted usage for the `dept spawn` subcommand,
// documenting the required ID, NAME, and TIER positional arguments. Shown
// by `ghost-ctl dept spawn --help` (or `-h`) and by the missing-arg path.
func printSpawnUsage() {
	fmt.Println("Usage: ghost-ctl dept spawn <DEPT_ID> <NAME> <TIER> [PARENT_ID]")
	fmt.Println("")
	fmt.Println("Spawn a new department container with its own cgroup, network,")
	fmt.Println("mount, PID, UTS, IPC, user, cgroup, and time namespaces.")
	fmt.Println("")
	fmt.Println("Arguments:")
	fmt.Println("  DEPT_ID    Unique numeric ID for the department (0-99).")
	fmt.Println("             0 is typically the ROOT department.")
	fmt.Println("  NAME       Human-readable name; must match ^[a-zA-Z0-9_-]+$")
	fmt.Println("             (letters, digits, underscore, hyphen; no spaces).")
	fmt.Println("  TIER       Hierarchy tier — one of:")
	fmt.Println("               ROOT     (top of the hierarchy, parent_id = -1)")
	fmt.Println("               DIRECTOR (must have a ROOT or DIRECTOR parent)")
	fmt.Println("               MANAGER  (must have a DIRECTOR or MANAGER parent)")
	fmt.Println("               STAFF    (must have a MANAGER or STAFF parent)")
	fmt.Println("  PARENT_ID  Optional parent department ID. Required unless TIER")
	fmt.Println("             is ROOT. Defaults to -1 (no parent) for ROOT.")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  ghost-ctl dept spawn 0 \"Headquarters\" ROOT")
	fmt.Println("  ghost-ctl dept spawn 1 \"Engineering\" DIRECTOR 0")
	fmt.Println("  ghost-ctl dept spawn 10 \"Backend Team\" MANAGER 1")
	fmt.Println("  ghost-ctl dept spawn 100 \"dev-alice\" STAFF 10")
}

// cmdSelfCheck runs a preflight check before systemd starts the
// daemon. It is designed to be called as ExecStartPre= in the
// ghost-orchestrator.service unit. Returns 0 on success, 1-9 for
// specific failure modes so systemd units can use OnFailure=
// triggers or logging with deterministic exit codes.
func cmdSelfCheck() int {
	fmt.Fprintln(os.Stderr, "ghost-ctl: self-check: verifying preconditions...")

	// 1. Base path must exist and be writable.
	if err := checkWritableDir(basePath); err != nil {
		fmt.Fprintf(os.Stderr, "self-check: base path %s: %v — create with: mkdir -p %s\n", basePath, err, basePath)
		return 1
	}

	// 2. Alert socket directory must exist (the daemon creates the
	// socket itself, but the parent dir must be there).
	if err := os.MkdirAll("/var/run/ghost-stack", 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "self-check: cannot create /var/run/ghost-stack: %v\n", err)
		return 3
	}

	// 3. BPF object directory (only if the host is already set up to
	// compile eBPF; don't fail if the directory is absent because the
	// deploy script creates it).
	bpfDir := "/opt/ghost-stack/bpf"
	if _, err := os.Stat(bpfDir); err == nil {
		if info, err := os.Stat(bpfDir); err != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "self-check: %s is not a directory: %v\n", bpfDir, err)
			return 4
		}
	}

	// 4. Agent binaries present (if the service units reference them).
	for _, agent := range []string{"agent-alpha", "agent-beta"} {
		path := "/opt/ghost-stack/bin/" + agent
		if _, err := os.Stat(path); err != nil {
			fmt.Fprintf(os.Stderr, "self-check: agent binary missing: %s (will be built by `make install`)\n", path)
		}
	}

	// 5. Kernel capabilities (CAP_BPF is Linux ≥ 5.8).
	// We can't test for CAP_BPF from unprivileged shell, but we can
	// check /proc/sys/kernel/bpf_stats_enabled exists.
	if _, err := os.Stat("/proc/sys/kernel/bpf_stats_enabled"); err != nil {
		fmt.Fprintf(os.Stderr, "self-check: BPF sysctl absent — kernel may be too old for eBPF (need >= 5.8)\n")
		return 5
	}

	// 6. Host tools the daemon's spawned departments need.
	if missing, err := checkHostTools([]string{"ip", "mount", "umount"}); err != nil {
		fmt.Fprintf(os.Stderr, "self-check: required host tool %q not found in $PATH: %v — install with: apt-get install iproute2 mount\n", missing, err)
		return 7
	}

	// 7. Orchestrator private key exists; if not, warn only — the
	// daemon will generate it on first run.
	keyPath := "/etc/ghost-stack/orchestrator.ed25519"
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "self-check: Ed25519 key not found at %s (daemon will generate on first run)\n", keyPath)
	}

	fmt.Fprintln(os.Stderr, "ghost-ctl: self-check: all preconditions satisfied")
	return 0
}

// cmdDaemon is the long-running orchestrator daemon, launched by
// systemd as ghost-orchestrator.service. It initializes the full
// subsystem stack (SQLite, hierarchy, state manager, threat
// response handler, alert socket), then blocks on a signal-aware
// loop until SIGTERM or SIGINT. On shutdown it closes the alert
// socket, drains the threat handler, and writes the final audit
// entry.
func cmdDaemon() {
	// initialize() was already run by main() before dispatch; the
	// sync.Once inside makes this second call a cheap no-op.
	if err := initialize(); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: daemon initialization failed: %v\n", err)
		os.Exit(1)
	}

	// Start the AGENT-BETA alert socket listener — daemon only.
	if err := startThreatListener(); err != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: threat listener failed: %v\n", err)
		os.Exit(1)
	}

	// Session maintenance loops (rotation + expiry cleanup).
	stopSessions := make(chan struct{})
	go sessionMgr.StartTokenRotationLoop(stopSessions)
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stopSessions:
				return
			case <-ticker.C:
				if n := sessionMgr.CleanupExpiredSessions(); n > 0 {
					fmt.Printf("daemon: cleaned up %d expired sessions\n", n)
				}
			}
		}
	}()

	// Read-only status API on localhost for the dashboard and operators.
	statusAddr := ghostEnvOr("GHOST_STATUS_ADDR", "127.0.0.1:9090")
	stopStatus := make(chan struct{})
	go serveStatusAPI(statusAddr, stopStatus)

	// Notify systemd Type=notify readiness.
	sdNotify("READY=1\n")

	// Block on signal-aware select until SIGTERM / SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	fmt.Println("daemon: running (waiting for SIGTERM/SIGINT)")
	sig := <-sigCh
	fmt.Fprintf(os.Stderr, "daemon: received %s — shutting down\n", sig)

	// Trigger the threat handler's accept loop to exit cleanly.
	if threatHandler != nil {
		threatHandler.Stop()
	}
	close(stopSessions)
	close(stopStatus)

	// Detach the XDP program on graceful shutdown.
	if l3Manager != nil && l3Manager.IsAttached() {
		if err := l3Manager.Detach(); err != nil {
			fmt.Fprintf(os.Stderr, "daemon: XDP detach: %v\n", err)
		}
	}

	// Write final audit entry so operators know the daemon exited
	// cleanly, not via a crash or OOM-kill.
	appendAudit(AuditEntry{
		Timestamp: time.Now().UTC(),
		Action:    "ORCHESTRATOR_STOP",
		Actor:     "daemon",
		Result:    sig.String(),
		Details:   map[string]interface{}{"pid": os.Getpid()},
	})

	// Persist state to SQLite so the next start recovers dept tree.
	if stateManager != nil {
		_ = stateManager.Close() // best-effort final flush
	}
}

// sdNotify sends a single state string to systemd via the
// NOTIFY_SOCKET unix datagram. Implements the sd_notify(3)
// protocol in pure Go — no third-party dependency.
func sdNotify(state string) {
	sockPath := os.Getenv("NOTIFY_SOCKET")
	if sockPath == "" {
		return
	}
	addr := &net.UnixAddr{
		Net:  "unixgram",
		Name: sockPath,
	}
	if strings.HasPrefix(sockPath, "@") {
		addr.Name = "\x00" + sockPath[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sd-notify: dial %s: %v\n", sockPath, err)
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		fmt.Fprintf(os.Stderr, "sd-notify: write %q: %v\n", strings.TrimSpace(state), err)
	}
}

// --- Helper functions extracted to reduce cognitive complexity ---

// isHelpFlag reports whether s is the documented help flag.
func isHelpFlag(s string) bool {
	return s == helpFlag || s == hFlag
}

// needInitialize reports whether a subcommand requires the full
// subsystem bring-up (alert socket, threat handler, DB, etc.).
func needInitialize(cmd string) bool {
	return cmd != "version" && cmd != "help" && cmd != helpFlag && cmd != hFlag && cmd != "self-check"
}

// loadOrGenerateEd25519Keys loads the orchestrator's Ed25519 keypair from
// disk; if absent, it generates a fresh pair and persists it atomically.
func loadOrGenerateEd25519Keys() error {
	ed25519KeyPath := "/etc/ghost-stack/orchestrator.ed25519"
	if data, readErr := os.ReadFile(ed25519KeyPath); readErr == nil {
		if len(data) != ed25519.PrivateKeySize {
			fmt.Fprintf(os.Stderr, "ghost-ctl: %s has invalid size (got %d, want %d)\n", ed25519KeyPath, len(data), ed25519.PrivateKeySize)
			os.Exit(1)
		}
		ed25519PrivKey = ed25519.PrivateKey(data)
		ed25519PubKey = ed25519PrivKey.Public().(ed25519.PublicKey)
		return nil
	}
	pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		return fmt.Errorf("ed25519 generate: %w", genErr)
	}
	if mkdirErr := os.MkdirAll("/etc/ghost-stack", 0o700); mkdirErr != nil {
		return fmt.Errorf("ed25519: mkdir %s: %w", "/etc/ghost-stack", mkdirErr)
	}
	if writeErr := os.WriteFile(ed25519KeyPath, priv, 0o600); writeErr != nil {
		return fmt.Errorf("ed25519: write %s: %w", ed25519KeyPath, writeErr)
	}
	ed25519PubKey = pub
	ed25519PrivKey = priv
	return nil
}

// recoverRunningDepartments restores dept state from SQLite after restart.
func recoverRunningDepartments() {
	if stateManager == nil {
		return
	}
	aliveDepts, recoverErr := stateManager.RecoverRunningDepartments()
	if recoverErr != nil || len(aliveDepts) == 0 {
		return
	}
	fmt.Printf("[GHOST-CTL] Recovered %d running departments from previous session\n", len(aliveDepts))
	for _, dept := range aliveDepts {
		fmt.Printf("  ✓ dept-%d (%s) PID=%d subnet=%s\n",
			dept.DeptID, dept.DeptName, dept.PID, dept.SubnetCIDR)
		tier := parseTier(dept.Tier)
		limits := namespace.DefaultCgroupLimits(tier)
		cfg := namespace.ContainerConfig{
			DeptID:          dept.DeptID,
			DeptName:        dept.DeptName,
			Tier:            tier,
			RootFS:          dept.RootFS,
			Hostname:        fmt.Sprintf(deptHostnameFmt, dept.DeptID),
			Limits:          limits,
			SubnetCIDR:      dept.SubnetCIDR,
			ContainerIP:     dept.ContainerIP,
			GatewayIP:       dept.GatewayIP,
			AlertSocketPath: alertSocketPath,
			AgentBinaryPath: "/opt/ghost-stack/bin/agent-alpha",
		}
		deptManager.RegisterRecoveredContainer(cfg, dept.PID, dept.CgroupPath, dept.CreatedAt)
		tier = parseTier(dept.Tier)
		if _, regErr := hierarchyTree.RegisterDepartment(dept.DeptID, dept.DeptName, tier, dept.ParentDeptID); regErr != nil {
			fmt.Fprintf(os.Stderr, "ghost-ctl: warning: hierarchy recovery skipped dept-%d: %v\n", dept.DeptID, regErr)
		}
	}
}

// initIPAM creates the IP address allocator.
func initIPAM() error {
	var dbConn *stateDB
	if stateManager != nil {
		dbConn = stateManager.db
	}
	var allocErr error
	ipam, allocErr = NewIPAM(dbConn)
	if allocErr != nil {
		fmt.Fprintf(os.Stderr, "ghost-ctl: IPAM init warning: %v\n", allocErr)
	}
	return allocErr
}

// newSpawnConfig assembles the ContainerConfig from validated CLI args.
func newSpawnConfig(deptID int, deptName string, tier hierarchy.Tier, parentID int) (namespace.ContainerConfig, string, string, string, error) {
	var subnetCIDR, containerIP, gatewayIP string
	if ipam != nil {
		alloc, allocErr := ipam.Allocate(deptID)
		if allocErr != nil {
			return namespace.ContainerConfig{}, "", "", "", fmt.Errorf("IPAM allocation failed: %w", allocErr)
		}
		subnetCIDR = alloc.SubnetCIDR
		containerIP = alloc.ContainerIP
		gatewayIP = alloc.GatewayIP
		fmt.Printf("  IPAM:       allocated %s (container=%s, gw=%s)\n",
			subnetCIDR, containerIP, gatewayIP)
	} else {
		subnetCIDR = fmt.Sprintf("10.200.%d.0/24", deptID)
		containerIP = fmt.Sprintf("10.200.%d.2", deptID)
		gatewayIP = fmt.Sprintf("10.200.%d.1", deptID)
	}
	limits := namespace.DefaultCgroupLimits(tier)
	cfg := namespace.ContainerConfig{
		DeptID:          deptID,
		DeptName:        deptName,
		Tier:            tier,
		RootFS:          fmt.Sprintf("%s/rootfs/dept-%d", basePath, deptID),
		Hostname:        fmt.Sprintf(deptHostnameFmt, deptID),
		Limits:          limits,
		SubnetCIDR:      subnetCIDR,
		ContainerIP:     containerIP,
		GatewayIP:       gatewayIP,
		AlertSocketPath: alertSocketPath,
		AgentBinaryPath: "/opt/ghost-stack/bin/agent-alpha",
	}
	return cfg, subnetCIDR, containerIP, gatewayIP, nil
}

// persistSpawnState writes a freshly spawned department into SQLite.
func persistSpawnState(deptID int, deptName string, tier hierarchy.Tier, parentID int, rc *namespace.RunningContainer, subnetCIDR, containerIP, gatewayIP string) {
	if stateManager == nil {
		return
	}
	_ = stateManager.SaveDepartment(&DepartmentState{
		DeptID:        deptID,
		DeptName:      deptName,
		Tier:          tier.String(),
		PID:           rc.PID,
		ContainerIP:   containerIP,
		GatewayIP:     gatewayIP,
		SubnetCIDR:    subnetCIDR,
		CgroupPath:    rc.CgroupPath,
		RootFS:        rc.Config.RootFS,
		LUKSMountPath: fmt.Sprintf("%s/vault/mounts/dept-%d", basePath, deptID),
		LUKSVolPath:   fmt.Sprintf("%s/vault/volumes/dept-%d.luks2", basePath, deptID),
		LUKSDMName:    fmt.Sprintf(deptHostnameFmt, deptID),
		ParentDeptID:  parentID,
		Status:        "running",
	})
}

// printSpawnSuccess emits the console confirmation banner after spawn.
func printSpawnSuccess(deptID int, deptName string, rc *namespace.RunningContainer, subnetCIDR, containerIP, gatewayIP string, tier hierarchy.Tier) {
	fmt.Printf("\n[GHOST-CTL] ✓ Department %d (%s) spawned successfully\n", deptID, deptName)
	fmt.Printf("  PID:        %d\n", rc.PID)
	fmt.Printf("  Cgroup:     %s\n", rc.CgroupPath)
	fmt.Printf("  Subnet:     %s\n", subnetCIDR)
	fmt.Printf("  Container:  %s\n", containerIP)
	fmt.Printf("  Gateway:    %s\n", gatewayIP)
	fmt.Printf("  UID Range:  %d-%d (host)\n",
		hierarchy.TierUIDBase(tier)+uint32(deptID)*1000,     // #nosec G115 -- deptID in [0,99], validated at parse
		hierarchy.TierUIDBase(tier)+uint32(deptID)*1000+999) // #nosec G115 -- deptID in [0,99], validated at parse
	fmt.Printf("  DB Type:    %s\n", db.DatabaseTypeForTier(tier))
	fmt.Printf("  Key Mgmt:   HOST-ONLY (HostKeyStore, /dev/shm tmpfs)\n")
}

// checkWritableDir verifies that path is a directory and is writable.
func checkWritableDir(path string) error {
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		return fmt.Errorf("not a directory: %w", err)
	}
	f, err := os.CreateTemp(path, ".ghost-ctl-write-test-*")
	if err != nil {
		return fmt.Errorf("not writable: %w", err)
	}
	f.Close()
	os.Remove(f.Name())
	return nil
}

// checkHostTools verifies that all required host binaries are on $PATH.
func checkHostTools(tools []string) (string, error) {
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return tool, err
		}
	}
	return "", nil
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

var (
	// auditMu serializes audit writes so the hash chain stays ordered.
	auditMu sync.Mutex
	// lastAuditHash is the SHA-256 hex of the most recently appended
	// audit line. Each entry carries PrevHash, forming a tamper-evident
	// chain verifiable with `ghost-ctl audit-trail --verify`.
	lastAuditHash string
	// lastAuditHashLoaded marks whether lastAuditHash was seeded from the
	// tail of the existing log file.
	lastAuditHashLoaded bool
	// auditDev/auditIno/auditSize identify the log file last written to.
	// An inode change or size shrink means logrotate renamed the file
	// (or it was truncated) — the next write starts a new chain segment
	// with an AUDIT_CHAIN_ROTATED genesis entry linking to the old tail.
	auditDev  uint64
	auditIno  uint64
	auditSize int64
)

// appendAudit appends one JSON audit line, chaining it to the previous
// entry via SHA-256 (PrevHash). The file is opened O_APPEND-only with
// 0600; there is no truncation path anywhere in this codebase —
// deploy.sh installs a rename-based (never copytruncate) logrotate config,
// and rotation is detected via inode/size so the new file stays
// self-verifying through a genesis entry.
func appendAudit(entry AuditEntry) {
	if err := os.MkdirAll(basePath+"/audit", 0o700); err != nil {
		return
	}

	auditMu.Lock()
	defer auditMu.Unlock()

	if !lastAuditHashLoaded {
		lastAuditHash = readAuditTailHash()
		lastAuditHashLoaded = true
		auditDev, auditIno, auditSize = statAuditFile()
	}

	// Detect external rotation/truncation since our last write.
	if dev, ino, size := statAuditFile(); dev != auditDev || ino != auditIno || size < auditSize {
		genesis := AuditEntry{
			Timestamp: time.Now().UTC(),
			Action:    "AUDIT_CHAIN_ROTATED",
			Actor:     "orchestrator",
			Details:   map[string]interface{}{"prev_tail_hash": lastAuditHash},
			Result:    "SUCCESS",
			PrevHash:  "",
		}
		if err := writeAuditLine(genesis); err != nil {
			return
		}
		auditDev, auditIno, auditSize = dev, ino, size
	}

	entry.PrevHash = lastAuditHash
	if err := writeAuditLine(entry); err != nil {
		return
	}
	auditDev, auditIno, auditSize = statAuditFile()
}

// writeAuditLine marshals one entry, appends it durably (fsync), and
// advances lastAuditHash. Callers must hold auditMu.
func writeAuditLine(entry AuditEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	f, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	// Best-effort durability: sync each entry so a crash cannot silently
	// lose the tail of the audit trail.
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if serr != nil {
		return serr
	}
	if cerr != nil {
		return cerr
	}

	sum := sha256.Sum256(data)
	lastAuditHash = hex.EncodeToString(sum[:])
	return nil
}

// statAuditFile returns the device, inode, and size of the audit log.
// Missing file → zeros (treated as "rotated" so the first write after
// logrotate starts a fresh, self-verifying chain segment).
func statAuditFile() (dev, ino uint64, size int64) {
	st, err := os.Stat(auditLogPath)
	if err != nil {
		return 0, 0, 0
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		dev, ino = uint64(sys.Dev), uint64(sys.Ino)
	}
	return dev, ino, st.Size()
}

// readAuditTailHash returns the SHA-256 hex of the last non-empty line of
// the audit log, or "" when the log does not exist yet.
func readAuditTailHash() string {
	f, err := os.Open(auditLogPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Read the tail (last 64 KiB is plenty for one JSON line).
	const tailSize = 64 * 1024
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	off := int64(0)
	if st.Size() > tailSize {
		off = st.Size() - tailSize
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return ""
	}
	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if len(bytes.TrimSpace(lines[i])) == 0 {
			continue
		}
		sum := sha256.Sum256(append(lines[i], '\n'))
		return hex.EncodeToString(sum[:])
	}
	return ""
}

// verifyAuditChain replays the audit log and checks every PrevHash link.
// Returns the number of verified entries, or an error naming the first
// broken link.
func verifyAuditChain() (int, error) {
	f, err := os.Open(auditLogPath)
	if err != nil {
		return 0, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	wantPrev := ""
	count := 0
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return count, fmt.Errorf("line %d: invalid JSON: %w", lineNo, err)
		}
		if entry.PrevHash != wantPrev {
			return count, fmt.Errorf("line %d: hash chain broken (action=%s)", lineNo, entry.Action)
		}
		sum := sha256.Sum256(append(append([]byte{}, line...), '\n'))
		wantPrev = hex.EncodeToString(sum[:])
		count++
	}
	if err := sc.Err(); err != nil {
		return count, fmt.Errorf("read audit log: %w", err)
	}
	return count, nil
}
