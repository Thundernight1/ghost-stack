package layer3

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestNewAllowlistManager(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	am := NewAllowlistManager("eth0", pub)
	if am == nil {
		t.Fatal("expected non-nil AllowlistManager")
	}

	if am.ifaceName != "eth0" {
		t.Errorf("ifaceName = %q, want %q", am.ifaceName, "eth0")
	}

	if len(am.ListAllowlist()) != 0 {
		t.Errorf("expected empty allowlist, got %d entries", len(am.ListAllowlist()))
	}
}

func TestAllowlistManager_AddEntry_Signed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	am := NewAllowlistManager("eth0", pub)

	entries := []AllowlistEntry{
		{CIDR: "10.0.0.0/24", Label: "trusted-subnet"},
	}

	update, err := SignUpdate(priv, "add", entries)
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}

	err = am.ApplyUpdate(update)
	if err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}

	list := am.ListAllowlist()
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}

	if list[0].CIDR != "10.0.0.0/24" || list[0].Label != "trusted-subnet" {
		t.Errorf("unexpected entry: %+v", list[0])
	}
}

func TestAllowlistManager_AddEntry_Unsigned(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	am := NewAllowlistManager("eth0", pub)

	update := &AllowlistUpdate{
		Action: "add",
		Entries: []AllowlistEntry{
			{CIDR: "192.168.1.0/24", Label: "trusted"},
		},
		Timestamp: time.Now().Unix(),
		Nonce:     "12345678",
		Signature: "", // Unsigned
	}

	err = am.ApplyUpdate(update)
	if err == nil {
		t.Fatal("expected signature verification failure for unsigned update")
	}
}

func TestAllowlistManager_AddEntry_TamperedPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	am := NewAllowlistManager("eth0", pub)

	entries := []AllowlistEntry{
		{CIDR: "10.0.0.0/24", Label: "trusted-subnet"},
	}

	update, err := SignUpdate(priv, "add", entries)
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}

	// Tamper with the CIDR
	update.Entries[0].CIDR = "10.0.0.99/32"

	err = am.ApplyUpdate(update)
	if err == nil {
		t.Fatal("expected signature verification failure for tampered payload")
	}
}

func TestAllowlistManager_AddEntry_ExpiredTimestamp(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	am := NewAllowlistManager("eth0", pub)

	entries := []AllowlistEntry{
		{CIDR: "10.0.0.0/24", Label: "trusted-subnet"},
	}

	// Manually create an update with expired timestamp (100 seconds ago) and sign it correctly.
	timestamp := time.Now().Add(-100 * time.Second).Unix()
	nonce := "expirednonce123"

	msg := struct {
		Action    string           `json:"action"`
		Entries   []AllowlistEntry `json:"entries,omitempty"`
		Timestamp int64            `json:"timestamp"`
		Nonce     string           `json:"nonce"`
	}{
		Action:    "add",
		Entries:   entries,
		Timestamp: timestamp,
		Nonce:     nonce,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256(msgBytes)
	sig := ed25519.Sign(priv, hash[:])

	update := &AllowlistUpdate{
		Action:    "add",
		Entries:   entries,
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: hex.EncodeToString(sig),
	}

	err = am.ApplyUpdate(update)
	if err == nil {
		t.Fatal("expected timestamp freshness check to reject update from 100s ago")
	}
}

func TestAllowlistManager_ReplayAttack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	am := NewAllowlistManager("eth0", pub)

	entries := []AllowlistEntry{
		{CIDR: "10.0.0.0/24", Label: "trusted-subnet"},
	}

	update, err := SignUpdate(priv, "add", entries)
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}

	// First application: must succeed.
	err = am.ApplyUpdate(update)
	if err != nil {
		t.Fatalf("First ApplyUpdate failed: %v", err)
	}

	// Replay (second application with same nonce): must fail!
	err = am.ApplyUpdate(update)
	if err == nil {
		t.Fatal("expected error due to replay protection (reused nonce)")
	}
}

func TestAllowlistManager_ListEntries(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	am := NewAllowlistManager("eth0", pub)

	entries := []AllowlistEntry{
		{CIDR: "10.1.0.0/24", Label: "subnet-a"},
		{CIDR: "10.2.0.0/24", Label: "subnet-b"},
	}

	update, err := SignUpdate(priv, "add", entries)
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}

	if err := am.ApplyUpdate(update); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}

	list := am.ListAllowlist()
	if len(list) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(list))
	}

	// Verify both exist.
	foundA, foundB := false, false
	for _, entry := range list {
		if entry.CIDR == "10.1.0.0/24" && entry.Label == "subnet-a" {
			foundA = true
		}
		if entry.CIDR == "10.2.0.0/24" && entry.Label == "subnet-b" {
			foundB = true
		}
	}

	if !foundA || !foundB {
		t.Errorf("missing entries in allowlist list: %+v", list)
	}
}

func TestAllowlistManager_RemoveEntry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	am := NewAllowlistManager("eth0", pub)

	// 1. Add entry.
	entries := []AllowlistEntry{
		{CIDR: "10.0.0.0/24", Label: "trusted-subnet"},
	}
	updateAdd, _ := SignUpdate(priv, "add", entries)
	_ = am.ApplyUpdate(updateAdd)

	// Verify it's there.
	if len(am.ListAllowlist()) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(am.ListAllowlist()))
	}

	// 2. Remove entry.
	updateRemove, err := SignUpdate(priv, "remove", entries)
	if err != nil {
		t.Fatalf("SignUpdate remove: %v", err)
	}

	err = am.ApplyUpdate(updateRemove)
	if err != nil {
		t.Fatalf("ApplyUpdate remove failed: %v", err)
	}

	// Verify it's gone.
	if len(am.ListAllowlist()) != 0 {
		t.Errorf("expected 0 entries after removal, got %d", len(am.ListAllowlist()))
	}
}
