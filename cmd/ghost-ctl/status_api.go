// GHOST-STACK CORE — ghost-ctl: read-only status API.
//
// Serves JSON on a loopback address for the dashboard and operators:
//
//	GET /api/status     orchestrator version, uptime, XDP state, counts
//	GET /api/allowlist   current Layer 3 allowlist entries
//	GET /api/blocks      IPs auto-blocked by threat response
//	GET /api/audit?limit=N  recent audit trail entries (newest last)
//	GET /api/depts       running department containers
//
// The API is strictly read-only (GET only, no mutation endpoints) and
// defaults to binding 127.0.0.1:9090. The bind address is configurable via
// GHOST_STATUS_ADDR; exposing it beyond loopback is an operator decision
// (put it behind a reverse proxy with auth if you do).
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"
)

// daemonStartTime is set when the daemon command begins serving.
var daemonStartTime = time.Now()

// statusSnapshot is the /api/status payload.
type statusSnapshot struct {
	Version         string `json:"version"`
	UptimeSeconds   int64  `json:"uptime_seconds"`
	XDPAttached     bool   `json:"xdp_attached"`
	ActiveSessions  int    `json:"active_sessions"`
	RegisteredDevs  int    `json:"registered_devices"`
	AllowlistCount  int    `json:"allowlist_entries"`
	BlockedCount    int    `json:"blocked_ips"`
	DeptCount       int    `json:"departments"`
	AlertSocketPath string `json:"alert_socket"`
}

// serveStatusAPI runs the read-only HTTP API until stopCh is closed.
// Errors are non-fatal: the daemon keeps running without the dashboard API.
func serveStatusAPI(addr string, stopCh <-chan struct{}) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", handleAPIStatus)
	mux.HandleFunc("/api/allowlist", handleAPIAllowlist)
	mux.HandleFunc("/api/blocks", handleAPIBlocks)
	mux.HandleFunc("/api/audit", handleAPIAudit)
	mux.HandleFunc("/api/depts", handleAPIDepts)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-stopCh
		_ = srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		_, _ = os.Stderr.WriteString("ghost-ctl: status API: " + err.Error() + "\n")
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return
	}
	snap := statusSnapshot{
		Version:         version,
		UptimeSeconds:   int64(time.Since(daemonStartTime).Seconds()),
		AlertSocketPath: alertSocketPath,
	}
	if l3Manager != nil {
		snap.XDPAttached = l3Manager.IsAttached()
		snap.AllowlistCount = len(l3Manager.ListAllowlist())
	}
	if sessionMgr != nil {
		snap.ActiveSessions = sessionMgr.ActiveSessionCount()
		snap.RegisteredDevs = sessionMgr.RegisteredDeviceCount()
	}
	if threatHandler != nil {
		snap.BlockedCount = len(threatHandler.ListBlockedIPs())
	}
	if deptManager != nil {
		snap.DeptCount = len(deptManager.ListContainers())
	}
	writeJSON(w, snap)
}

func handleAPIAllowlist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return
	}
	entries := []interface{}{}
	if l3Manager != nil {
		for _, e := range l3Manager.ListAllowlist() {
			entries = append(entries, e)
		}
	}
	writeJSON(w, map[string]interface{}{"entries": entries})
}

func handleAPIBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return
	}
	blocks := []interface{}{}
	if threatHandler != nil {
		for _, b := range threatHandler.ListBlockedIPs() {
			blocks = append(blocks, b)
		}
	}
	writeJSON(w, map[string]interface{}{"blocked": blocks})
}

func handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return
	}
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	writeJSON(w, map[string]interface{}{"entries": readAuditTail(limit)})
}

type deptView struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	PID         int       `json:"pid"`
	Subnet      string    `json:"subnet"`
	ContainerIP string    `json:"container_ip"`
	Quarantined bool      `json:"quarantined"`
	Frozen      bool      `json:"frozen"`
	StartedAt   time.Time `json:"started_at"`
}

func handleAPIDepts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return
	}
	depts := []deptView{}
	if deptManager != nil {
		for _, c := range deptManager.ListContainers() {
			depts = append(depts, deptView{
				ID:          c.Config.DeptID,
				Name:        c.Config.DeptName,
				PID:         c.PID,
				Subnet:      c.Config.SubnetCIDR,
				ContainerIP: c.Config.ContainerIP,
				Quarantined: c.Quarantined,
				Frozen:      c.Frozen,
				StartedAt:   c.StartedAt,
			})
		}
	}
	writeJSON(w, map[string]interface{}{"departments": depts})
}

// readAuditTail returns the last n audit entries (oldest first).
func readAuditTail(n int) []AuditEntry {
	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		return []AuditEntry{}
	}
	lines := splitLines(data)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]AuditEntry, 0, len(lines))
	for _, ln := range lines {
		var e AuditEntry
		if err := json.Unmarshal(ln, &e); err == nil {
			out = append(out, e)
		}
	}
	return out
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				out = append(out, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, data[start:])
	}
	return out
}
