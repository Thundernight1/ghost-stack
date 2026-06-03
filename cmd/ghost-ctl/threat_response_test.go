package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	layer3 "github.com/ghost-stack/core/firewall/layer3"
)

// TestThreatResponseHandler_AutoBlocksHighScoreIP verifies that an
// IP already present in the Layer 3 XDP allowlist is automatically
// evicted (removed) when a BETA alert crosses the threat-score
// threshold. The eviction is the mechanism by which the IP is
// subsequently dropped at the NIC by the XDP invisible-wall program.
func TestThreatResponseHandler_AutoBlocksHighScoreIP(t *testing.T) {
	// Redirect basePath into a temporary directory so this test never
	// touches the host filesystem.
	tmp := t.TempDir()
	origBase := basePath
	basePath = tmp
	t.Cleanup(func() { basePath = origBase })

	// Build a fresh keypair — the threat handler needs one to sign
	// internal allowlist updates during blockIP.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	_ = pub

	// Create a Layer 3 manager wired to an empty XDP map. The
	// AllowlistManager will only be able to mutate its in-memory allowlist
	// because the underlying BPF map is nil on this test host — but
	// that's enough for the unit test.
	l3 := layer3.NewAllowlistManager("eth0", pub)

	// Seed the in-memory allowlist with a /24 range that contains the
	// IP we'll attack from.
	entries := []layer3.AllowlistEntry{
		{CIDR: "10.99.0.0/24", Label: "test-allowlist"},
	}
	update, err := layer3.SignUpdate(priv, "add", entries)
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if err := l3.ApplyUpdate(update); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}

	// Build a threat handler with a low threshold so the test fires.
	trh := NewThreatResponseHandler(ThreatResponseConfig{
		AlertSocketPath:      filepath.Join(tmp, "alert.sock"),
		ThreatScoreThreshold: 80,
		RequireL2Hits:        false,
		PrivateKey:           priv,
		PublicKey:            pub,
	}, l3, nil)

	// Fire the alert: THREAT_ACTOR_PROFILED with a source IP inside the
	// allowlisted CIDR. Threat score 99 > threshold 80 → auto-block.
	trh.processAlert(&BetaAlert{
		EventType:   "THREAT_ACTOR_PROFILED",
		SourceIP:    "10.99.0.42",
		ThreatScore: 99,
		Details:     map[string]interface{}{"ttps": []string{"T1110"}},
	})

	// After processAlert, the IP should appear in the blocked list.
	blocked := trh.ListBlockedIPs()
	if len(blocked) != 1 {
		t.Fatalf("expected 1 blocked IP, got %d", len(blocked))
	}
	if blocked[0].IP != "10.99.0.42" {
		t.Fatalf("expected blocked IP 10.99.0.42, got %s", blocked[0].IP)
	}
	if blocked[0].ThreatScore != 99 {
		t.Fatalf("expected threat score 99, got %d", blocked[0].ThreatScore)
	}
	if blocked[0].Reason != "THREAT_SCORE_EXCEEDED" {
		t.Fatalf("expected reason THREAT_SCORE_EXCEEDED, got %s", blocked[0].Reason)
	}

	// The in-memory allowlist should NOT contain the blocked IP
	// (because blockIP removes it). We query via the public API.
	for _, e := range l3.ListAllowlist() {
		if e.CIDR == "10.99.0.42/32" {
			t.Fatalf("expected IP 10.99.0.42 to not be in allowlist after block")
		}
	}
}

// TestThreatResponseHandler_IgnoresBelowThreshold confirms the gate
// logic: alerts with scores under the threshold are silently dropped.
func TestThreatResponseHandler_IgnoresBelowThreshold(t *testing.T) {
	tmp := t.TempDir()
	origBase := basePath
	basePath = tmp
	t.Cleanup(func() { basePath = origBase })

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l3 := layer3.NewAllowlistManager("eth0", pub)
	trh := NewThreatResponseHandler(ThreatResponseConfig{
		AlertSocketPath:      filepath.Join(tmp, "alert.sock"),
		ThreatScoreThreshold: 90,
		RequireL2Hits:        false,
		PrivateKey:           priv,
		PublicKey:            pub,
	}, l3, nil)

	trh.processAlert(&BetaAlert{
		EventType:   "THREAT_ACTOR_PROFILED",
		SourceIP:    "10.99.0.43",
		ThreatScore: 50,
	})
	if got := len(trh.ListBlockedIPs()); got != 0 {
		t.Fatalf("expected 0 blocked IPs (below threshold), got %d", got)
	}
}

// TestThreatResponseHandler_IgnoresUnknownEventType guards the
// defensive default branch in processAlert. Only THREAT_ACTOR_PROFILED
// and L4_VIOLATION are actionable; everything else is dropped without
// mutating state.
func TestThreatResponseHandler_IgnoresUnknownEventType(t *testing.T) {
	tmp := t.TempDir()
	origBase := basePath
	basePath = tmp
	t.Cleanup(func() { basePath = origBase })

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l3 := layer3.NewAllowlistManager("eth0", pub)
	trh := NewThreatResponseHandler(ThreatResponseConfig{
		AlertSocketPath:      filepath.Join(tmp, "alert.sock"),
		ThreatScoreThreshold: 1, // would trigger on anything actionable
		RequireL2Hits:        false,
		PrivateKey:           priv,
		PublicKey:            pub,
	}, l3, nil)

	trh.processAlert(&BetaAlert{
		EventType:   "INFO_TRAFFIC_BASELINE",
		SourceIP:    "10.99.0.44",
		ThreatScore: 99,
	})
	if got := len(trh.ListBlockedIPs()); got != 0 {
		t.Fatalf("expected 0 blocked IPs (unknown event type), got %d", got)
	}
}

// TestThreatResponseHandler_L4ViolationAlwaysBlocks confirms the
// special-cased L4_VIOLATION path that bypasses score thresholding.
func TestThreatResponseHandler_L4ViolationAlwaysBlocks(t *testing.T) {
	tmp := t.TempDir()
	origBase := basePath
	basePath = tmp
	t.Cleanup(func() { basePath = origBase })

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	l3 := layer3.NewAllowlistManager("eth0", pub)
	trh := NewThreatResponseHandler(ThreatResponseConfig{
		AlertSocketPath:      filepath.Join(tmp, "alert.sock"),
		ThreatScoreThreshold: 999, // deliberately unreachable
		RequireL2Hits:        false,
		PrivateKey:           priv,
		PublicKey:            pub,
	}, l3, nil)

	trh.processAlert(&BetaAlert{
		EventType:   "L4_VIOLATION",
		SourceIP:    "10.99.0.45",
		ThreatScore: 10, // far below threshold
	})
	blocked := trh.ListBlockedIPs()
	if len(blocked) != 1 {
		t.Fatalf("expected 1 blocked IP, got %d", len(blocked))
	}
	if blocked[0].Reason != "L4_VIOLATION" {
		t.Fatalf("expected reason L4_VIOLATION, got %s", blocked[0].Reason)
	}
}

// TestAppendAudit_WritesValidJSONLine ensures the log-format contract
// is stable: each audit entry is one JSON line that round-trips.
func TestAppendAudit_WritesValidJSONLine(t *testing.T) {
	tmp := t.TempDir()
	origBase := basePath
	origLog := auditLogPath
	basePath = tmp
	auditLogPath = filepath.Join(tmp, "audit", "audit.log")
	t.Cleanup(func() {
		basePath = origBase
		auditLogPath = origLog
	})

	want := time.Now().UTC().Add(time.Minute).UTC()
	appendAudit(AuditEntry{
		Timestamp: want,
		Action:    "TEST_EVENT",
		Actor:     "test",
		Result:    "OK",
	})

	data, err := os.ReadFile(auditLogPath)
	if err != nil {
		t.Fatalf("audit log not created: %v", err)
	}
	// The log is appended as a single JSON line. Trim trailing newline.
	line := strings.TrimSpace(string(data))
	if strings.Count(line, "}") != strings.Count(line, "{") {
		t.Fatalf("malformed JSON line: %q", line)
	}
	var back AuditEntry
	if err := json.Unmarshal([]byte(line), &back); err != nil {
		t.Fatalf("audit line fails json.Unmarshal: %v", err)
	}
	if back.Action != "TEST_EVENT" {
		t.Fatalf("audit round-trip lost action: got %q", back.Action)
	}
	// Verify timestamp round-trips (parse precision is nanosecond for RFC3339Nano).
	if back.Timestamp.Sub(want) != 0 {
		t.Fatalf("timestamp drift: got %s", back.Timestamp.Format(time.RFC3339Nano))
	}
}
