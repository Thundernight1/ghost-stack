package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withTempAudit redirects the audit globals at a temp dir for the test.
func withTempAudit(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	auditLogPath = filepath.Join(dir, "audit.log")
	basePath = dir
	lastAuditHash = ""
	lastAuditHashLoaded = false
	auditDev, auditIno, auditSize = 0, 0, 0
	t.Cleanup(func() {
		auditLogPath = "/var/lib/ghost-stack/audit/audit.log"
		basePath = "/var/lib/ghost-stack"
		lastAuditHashLoaded = false
	})
}

func TestAuditChain_Verify(t *testing.T) {
	withTempAudit(t)

	for i := 0; i < 5; i++ {
		appendAudit(AuditEntry{
			Timestamp: time.Now().UTC(),
			Action:    "TEST_ACTION",
			Actor:     "test",
			Result:    "SUCCESS",
		})
	}

	n, err := verifyAuditChain()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 5 {
		t.Fatalf("verified %d entries, want 5", n)
	}
}

func TestAuditChain_DetectsTampering(t *testing.T) {
	withTempAudit(t)

	appendAudit(AuditEntry{Timestamp: time.Now().UTC(), Action: "A1", Actor: "test", Result: "SUCCESS"})
	appendAudit(AuditEntry{Timestamp: time.Now().UTC(), Action: "A2", Actor: "test", Result: "SUCCESS"})

	// Tamper: flip a byte in the first line.
	data, _ := os.ReadFile(auditLogPath)
	data[40] ^= 0xff
	if err := os.WriteFile(auditLogPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := verifyAuditChain(); err == nil {
		t.Fatal("expected tamper detection, chain verified clean")
	}
}

func TestAuditChain_RotationStartsNewSegment(t *testing.T) {
	withTempAudit(t)

	appendAudit(AuditEntry{Timestamp: time.Now().UTC(), Action: "BEFORE", Actor: "test", Result: "SUCCESS"})

	// Simulate logrotate: rename the file away, fresh file appears.
	data, _ := os.ReadFile(auditLogPath)
	if err := os.WriteFile(auditLogPath+".1", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(auditLogPath); err != nil {
		t.Fatal(err)
	}

	appendAudit(AuditEntry{Timestamp: time.Now().UTC(), Action: "AFTER", Actor: "test", Result: "SUCCESS"})

	// The new file must be self-verifying: genesis + entry.
	n, err := verifyAuditChain()
	if err != nil {
		t.Fatalf("rotated chain verify: %v", err)
	}
	if n != 2 {
		t.Fatalf("verified %d entries in new segment, want 2 (genesis + entry)", n)
	}

	// The old segment must still verify on its own.
	auditLogPath = auditLogPath + ".1"
	lastAuditHashLoaded = false
	if n, err := verifyAuditChain(); err != nil || n != 1 {
		t.Fatalf("old segment: n=%d err=%v", n, err)
	}
}
