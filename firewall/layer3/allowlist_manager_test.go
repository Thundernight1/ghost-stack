package layer3

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"
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

func TestAllowlistManager_RemoveIP_Exact32(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	am := NewAllowlistManager("eth0", pub)

	add, _ := SignUpdate(priv, "add", []AllowlistEntry{{CIDR: "10.9.0.7/32", Label: "t"}})
	if err := am.ApplyUpdate(add); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}

	removed, err := am.RemoveIP("10.9.0.7")
	if err != nil || !removed {
		t.Fatalf("RemoveIP = %v, %v; want true, nil", removed, err)
	}
	if am.HasEntry("10.9.0.7/32") {
		t.Fatal("entry still present after RemoveIP")
	}
}

func TestAllowlistManager_RemoveIP_PunchesHoleInCoveringCIDR(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	am := NewAllowlistManager("eth0", pub)

	add, _ := SignUpdate(priv, "add", []AllowlistEntry{{CIDR: "10.99.0.0/24", Label: "dept"}})
	if err := am.ApplyUpdate(add); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}

	removed, err := am.RemoveIP("10.99.0.42")
	if err != nil || !removed {
		t.Fatalf("RemoveIP = %v, %v; want true, nil", removed, err)
	}

	// The covering /24 must be gone...
	if am.HasEntry("10.99.0.0/24") {
		t.Fatal("covering /24 still present after RemoveIP")
	}
	// ...replaced by carve-out prefixes that still cover the neighbours...
	for _, want := range []string{"10.99.0.1", "10.99.0.200"} {
		covered := false
		for _, e := range am.ListAllowlist() {
			if _, ipNet, err := net.ParseCIDR(e.CIDR); err == nil && ipNet.Contains(net.ParseIP(want)) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("neighbour IP %s lost coverage after hole-punch", want)
		}
	}
	// ...but NOT the blocked IP itself.
	for _, e := range am.ListAllowlist() {
		if _, ipNet, err := net.ParseCIDR(e.CIDR); err == nil && ipNet.Contains(net.ParseIP("10.99.0.42")) {
			if e.CIDR == "10.99.0.42/32" {
				t.Fatalf("blocked /32 still present: %s", e.CIDR)
			}
			t.Fatalf("blocked IP 10.99.0.42 still covered by %s", e.CIDR)
		}
	}
}

func TestAllowlistManager_RemoveIP_NotCoveredIsNoop(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	am := NewAllowlistManager("eth0", pub)

	removed, err := am.RemoveIP("192.0.2.99")
	if err != nil {
		t.Fatalf("RemoveIP: %v", err)
	}
	if removed {
		t.Fatal("RemoveIP reported removal for an IP that was never allowlisted")
	}
}

func TestExcludeIPFromCIDR_CoversComplement(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.99.0.0/24")
	out := excludeIPFromCIDR(ipNet, net.ParseIP("10.99.0.42"))
	if len(out) == 0 {
		t.Fatal("expected non-empty exclusion set")
	}
	// Every address in the /24 except 10.99.0.42 must be covered exactly once.
	seen := map[string]int{}
	for _, n := range out {
		// Walk the prefix range.
		mask := n.Mask
		ones, _ := mask.Size()
		base := binary.BigEndian.Uint32(n.IP.To4())
		count := uint32(1) << (32 - ones)
		for i := uint32(0); i < count; i++ {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, base+i)
			seen[ip.String()]++
		}
	}
	for i := 0; i < 256; i++ {
		ip := net.ParseIP("10.99.0." + strconv.Itoa(i))
		c := seen[ip.String()]
		if i == 42 {
			if c != 0 {
				t.Fatalf("blocked IP covered %d times, want 0", c)
			}
		} else if c != 1 {
			t.Fatalf("IP %s covered %d times, want 1", ip, c)
		}
	}
}

func TestAllowlistManager_Carve_Atomic(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	am := NewAllowlistManager("eth0", pub)

	// Seed: wide CIDR allowlisted.
	seed, err := SignUpdate(priv, "add", []AllowlistEntry{{CIDR: "10.0.0.0/24", Label: "trusted"}})
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if err := am.ApplyUpdate(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Carve a hole for 10.0.0.5: remove /24, add the complement CIDRs.
	carve, err := SignCarveUpdate(priv,
		[]string{"10.0.0.0/24"},
		[]AllowlistEntry{{CIDR: "10.0.0.0/29", Label: "carve"}})
	if err != nil {
		t.Fatalf("SignCarveUpdate: %v", err)
	}
	if err := am.ApplyUpdate(carve); err != nil {
		t.Fatalf("carve: %v", err)
	}
	if am.HasEntry("10.0.0.0/24") {
		t.Error("carved-away CIDR still present")
	}
	if !am.HasEntry("10.0.0.0/29") {
		t.Error("carve add entry missing")
	}
}

func TestAllowlistManager_Carve_RollbackOnFailure(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	am := NewAllowlistManager("eth0", pub)

	seed, err := SignUpdate(priv, "add", []AllowlistEntry{{CIDR: "10.0.0.0/24", Label: "trusted"}})
	if err != nil {
		t.Fatalf("SignUpdate: %v", err)
	}
	if err := am.ApplyUpdate(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The add half is invalid (bad CIDR) — the remove must roll back.
	bad, err := SignCarveUpdate(priv,
		[]string{"10.0.0.0/24"},
		[]AllowlistEntry{{CIDR: "not-a-cidr", Label: "bad"}})
	if err != nil {
		t.Fatalf("SignCarveUpdate: %v", err)
	}
	if err := am.ApplyUpdate(bad); err == nil {
		t.Fatal("expected carve failure, got nil")
	}
	if !am.HasEntry("10.0.0.0/24") {
		t.Error("rollback failed: removed CIDR was not restored")
	}
	if am.HasEntry("not-a-cidr") {
		t.Error("invalid entry present after failed carve")
	}
}

func TestAllowlistManager_Carve_BadSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, evil, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	am := NewAllowlistManager("eth0", pub)

	carve, err := SignCarveUpdate(evil,
		[]string{"10.0.0.0/24"},
		[]AllowlistEntry{{CIDR: "10.0.0.0/29", Label: "carve"}})
	if err != nil {
		t.Fatalf("SignCarveUpdate: %v", err)
	}
	_ = priv
	if err := am.ApplyUpdate(carve); err == nil {
		t.Fatal("carve with wrong key must fail signature verification")
	}
}
