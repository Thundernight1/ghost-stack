// Package layer3 implements the XDP allowlist manager for GHOST-STACK CORE
// Layer 3 (Invisible Wall).
//
// Allowlist updates require Ed25519-signed commands from the orchestrator.
// This prevents allowlist poisoning — even if an attacker gains access to
// the management plane, they cannot modify the XDP allowlist without the
// orchestrator's private Ed25519 key.
//
// The manager:
//   - Loads and manages the XDP BPF program
//   - Maintains the LPM trie allowlist
//   - Verifies Ed25519 signatures on all allowlist updates
//   - Polls drop counters every 500ms for AGENT-BETA
//   - Never writes anything to disk (in-memory only)
package layer3

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AllowlistEntry represents a single IP/CIDR in the XDP allowlist.
type AllowlistEntry struct {
	CIDR      string `json:"cidr"`       // e.g., "10.200.0.0/16"
	Label     string `json:"label"`      // e.g., "orchestrator", "dept-1"
	AddedAt   int64  `json:"added_at"`   // Unix timestamp.
	ExpiresAt int64  `json:"expires_at"` // 0 = permanent.
}

// AllowlistUpdate is a signed update command for the XDP allowlist.
type AllowlistUpdate struct {
	// Action: "add", "remove", "flush".
	Action    string           `json:"action"`
	Entries   []AllowlistEntry `json:"entries,omitempty"`
	Timestamp int64            `json:"timestamp"`
	Nonce     string           `json:"nonce"`
	Signature string           `json:"signature"` // Ed25519 signature (hex).
}

// DropStats mirrors the BPF drop_stats structure.
type DropStats struct {
	Count       uint64 `json:"count"`
	FirstSeenNs uint64 `json:"first_seen_ns"`
	LastSeenNs  uint64 `json:"last_seen_ns"`
	LastDstPort uint16 `json:"last_dst_port"`
	LastProto   uint8  `json:"last_proto"`
}

// GlobalStats mirrors the BPF global_stats structure.
type GlobalStats struct {
	TotalPackets  uint64 `json:"total_packets"`
	TotalAllowed  uint64 `json:"total_allowed"`
	TotalDropped  uint64 `json:"total_dropped"`
	TotalARPassed uint64 `json:"total_arp_passed"`
}

// AllowlistManager manages the Layer 3 XDP invisible wall.
type AllowlistManager struct {
	mu sync.RWMutex

	// Ed25519 public key for verifying allowlist updates.
	publicKey ed25519.PublicKey

	// BPF resources.
	collection   *ebpf.Collection
	xdpLink      link.Link
	allowlistMap *ebpf.Map
	dropCounters *ebpf.Map
	statsMap     *ebpf.Map
	configMap    *ebpf.Map

	// In-memory state — never persisted to disk.
	entries map[string]*AllowlistEntry // CIDR → entry
	nonces  map[string]bool           // Replay protection.

	// Interface name.
	ifaceName string

	// Alert callback for AGENT-BETA integration.
	onDropAlert func(ip string, stats DropStats)
}

// NewAllowlistManager creates a new Layer 3 manager.
func NewAllowlistManager(ifaceName string, pubKey ed25519.PublicKey) *AllowlistManager {
	return &AllowlistManager{
		publicKey: pubKey,
		entries:   make(map[string]*AllowlistEntry),
		nonces:    make(map[string]bool),
		ifaceName: ifaceName,
	}
}

// SetDropAlertCallback sets the callback for drop counter alerts.
func (am *AllowlistManager) SetDropAlertCallback(fn func(string, DropStats)) {
	am.onDropAlert = fn
}

// LoadAndAttach loads the XDP program and attaches it to the network interface.
func (am *AllowlistManager) LoadAndAttach(bpfObjectPath string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Load BPF collection.
	spec, err := ebpf.LoadCollectionSpec(bpfObjectPath)
	if err != nil {
		return fmt.Errorf("layer3: load BPF spec: %w", err)
	}

	am.collection, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("layer3: create BPF collection: %w", err)
	}

	// Get map references.
	am.allowlistMap = am.collection.Maps["allowlist"]
	am.dropCounters = am.collection.Maps["drop_counters"]
	am.statsMap = am.collection.Maps["stats"]
	am.configMap = am.collection.Maps["config"]

	if am.allowlistMap == nil || am.dropCounters == nil {
		return fmt.Errorf("layer3: required BPF maps not found")
	}

	// Attach XDP program to interface in native mode.
	prog := am.collection.Programs["xdp_invisible_wall"]
	if prog == nil {
		return fmt.Errorf("layer3: XDP program not found")
	}

	iface, err := net.InterfaceByName(am.ifaceName)
	if err != nil {
		return fmt.Errorf("layer3: interface %s not found: %w", am.ifaceName, err)
	}

	am.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode, // Native mode — NIC driver level.
	})
	if err != nil {
		return fmt.Errorf("layer3: XDP attach: %w", err)
	}

	// Enable the firewall.
	if am.configMap != nil {
		key := uint32(0)
		val := uint32(1) // enabled
		am.configMap.Put(key, val)
	}

	return nil
}

// ApplyUpdate processes a signed allowlist update command.
// The update MUST be signed with the orchestrator's Ed25519 private key.
func (am *AllowlistManager) ApplyUpdate(update *AllowlistUpdate) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Step 1: Verify Ed25519 signature.
	if err := am.verifySignature(update); err != nil {
		return fmt.Errorf("layer3: signature verification FAILED: %w", err)
	}

	// Step 2: Replay protection — check nonce hasn't been used.
	if am.nonces[update.Nonce] {
		return fmt.Errorf("layer3: REPLAY DETECTED — nonce already used")
	}
	am.nonces[update.Nonce] = true

	// Step 3: Timestamp freshness check (max 60 seconds old).
	age := time.Since(time.Unix(update.Timestamp, 0))
	if age > 60*time.Second || age < -10*time.Second {
		return fmt.Errorf("layer3: update timestamp too old or in future: %v", age)
	}

	// Step 4: Apply the update.
	switch update.Action {
	case "add":
		for _, entry := range update.Entries {
			if err := am.addEntry(&entry); err != nil {
				return fmt.Errorf("layer3: add entry %s: %w", entry.CIDR, err)
			}
		}
	case "remove":
		for _, entry := range update.Entries {
			if err := am.removeEntry(entry.CIDR); err != nil {
				return fmt.Errorf("layer3: remove entry %s: %w", entry.CIDR, err)
			}
		}
	case "flush":
		// WARNING: This removes ALL allowlist entries.
		// The system becomes completely invisible to all external traffic.
		am.flushAllEntries()
	default:
		return fmt.Errorf("layer3: unknown action: %s", update.Action)
	}

	return nil
}

// addEntry adds a single CIDR to the XDP LPM trie allowlist.
func (am *AllowlistManager) addEntry(entry *AllowlistEntry) error {
	_, ipNet, err := net.ParseCIDR(entry.CIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	prefixLen, _ := ipNet.Mask.Size()
	ip := ipNet.IP.To4()
	if ip == nil {
		return fmt.Errorf("only IPv4 supported currently")
	}

	// Build LPM key: {prefixlen, addr}.
	key := make([]byte, 8)
	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:8], ip)

	// Value: 1 = allowed.
	val := uint32(1)

	if err := am.allowlistMap.Put(key, val); err != nil {
		return fmt.Errorf("BPF map put: %w", err)
	}

	entry.AddedAt = time.Now().Unix()
	am.entries[entry.CIDR] = entry

	return nil
}

// removeEntry removes a CIDR from the XDP allowlist.
func (am *AllowlistManager) removeEntry(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	prefixLen, _ := ipNet.Mask.Size()
	ip := ipNet.IP.To4()
	if ip == nil {
		return fmt.Errorf("only IPv4 supported currently")
	}

	key := make([]byte, 8)
	binary.LittleEndian.PutUint32(key[0:4], uint32(prefixLen))
	copy(key[4:8], ip)

	if err := am.allowlistMap.Delete(key); err != nil {
		return fmt.Errorf("BPF map delete: %w", err)
	}

	delete(am.entries, cidr)
	return nil
}

// flushAllEntries removes all entries from the allowlist.
func (am *AllowlistManager) flushAllEntries() {
	for cidr := range am.entries {
		_ = am.removeEntry(cidr)
	}
}

// verifySignature verifies the Ed25519 signature on an allowlist update.
func (am *AllowlistManager) verifySignature(update *AllowlistUpdate) error {
	// Build the message that was signed (everything except the signature field).
	msg := struct {
		Action    string           `json:"action"`
		Entries   []AllowlistEntry `json:"entries,omitempty"`
		Timestamp int64            `json:"timestamp"`
		Nonce     string           `json:"nonce"`
	}{
		Action:    update.Action,
		Entries:   update.Entries,
		Timestamp: update.Timestamp,
		Nonce:     update.Nonce,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	// Hash the message.
	hash := sha256.Sum256(msgBytes)

	// Decode the hex signature.
	sig, err := hex.DecodeString(update.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Verify Ed25519 signature.
	if !ed25519.Verify(am.publicKey, hash[:], sig) {
		return fmt.Errorf("Ed25519 signature INVALID — possible allowlist poisoning attempt")
	}

	return nil
}

// PollDropCounters reads the XDP drop counters from the BPF map.
// Called by AGENT-BETA every 500ms. Returns in-memory data only.
func (am *AllowlistManager) PollDropCounters() (map[string]DropStats, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if am.dropCounters == nil {
		return nil, fmt.Errorf("layer3: drop counters map not available")
	}

	results := make(map[string]DropStats)

	var key uint32
	var perCPUStats []DropStats

	iter := am.dropCounters.Iterate()
	for iter.Next(&key, &perCPUStats) {
		// Aggregate per-CPU stats.
		var total DropStats
		for _, cpu := range perCPUStats {
			total.Count += cpu.Count
			if cpu.FirstSeenNs < total.FirstSeenNs || total.FirstSeenNs == 0 {
				total.FirstSeenNs = cpu.FirstSeenNs
			}
			if cpu.LastSeenNs > total.LastSeenNs {
				total.LastSeenNs = cpu.LastSeenNs
				total.LastDstPort = cpu.LastDstPort
				total.LastProto = cpu.LastProto
			}
		}

		// Convert IP uint32 to string.
		ip := fmt.Sprintf("%d.%d.%d.%d",
			key&0xFF, (key>>8)&0xFF, (key>>16)&0xFF, (key>>24)&0xFF)
		results[ip] = total

		// Alert callback for high-count drops.
		if am.onDropAlert != nil && total.Count > 100 {
			am.onDropAlert(ip, total)
		}
	}

	return results, iter.Err()
}

// GetGlobalStats returns aggregated global XDP statistics.
func (am *AllowlistManager) GetGlobalStats() (*GlobalStats, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if am.statsMap == nil {
		return nil, fmt.Errorf("layer3: stats map not available")
	}

	key := uint32(0)
	var perCPUStats []GlobalStats
	if err := am.statsMap.Lookup(key, &perCPUStats); err != nil {
		return nil, err
	}

	var total GlobalStats
	for _, cpu := range perCPUStats {
		total.TotalPackets += cpu.TotalPackets
		total.TotalAllowed += cpu.TotalAllowed
		total.TotalDropped += cpu.TotalDropped
		total.TotalARPassed += cpu.TotalARPassed
	}

	return &total, nil
}

// ListAllowlist returns all currently allowed CIDRs.
func (am *AllowlistManager) ListAllowlist() []AllowlistEntry {
	am.mu.RLock()
	defer am.mu.RUnlock()

	entries := make([]AllowlistEntry, 0, len(am.entries))
	for _, e := range am.entries {
		entries = append(entries, *e)
	}
	return entries
}

// StartDropCounterPoller runs a background goroutine that polls
// drop counters every 500ms for AGENT-BETA consumption.
func (am *AllowlistManager) StartDropCounterPoller(stopCh <-chan struct{}, resultCh chan<- map[string]DropStats) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			stats, err := am.PollDropCounters()
			if err != nil {
				continue
			}
			// Non-blocking send.
			select {
			case resultCh <- stats:
			default:
			}
		}
	}
}

// CleanupExpiredEntries removes allowlist entries past their expiration time.
func (am *AllowlistManager) CleanupExpiredEntries() int {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now().Unix()
	removed := 0

	for cidr, entry := range am.entries {
		if entry.ExpiresAt > 0 && now > entry.ExpiresAt {
			_ = am.removeEntry(cidr)
			removed++
		}
	}

	return removed
}

// Detach removes the XDP program from the interface and cleans up.
func (am *AllowlistManager) Detach() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.xdpLink != nil {
		am.xdpLink.Close()
	}
	if am.collection != nil {
		am.collection.Close()
	}
	return nil
}

// SignUpdate creates a signed allowlist update (for orchestrator use).
func SignUpdate(privateKey ed25519.PrivateKey, action string, entries []AllowlistEntry) (*AllowlistUpdate, error) {
	nonce := make([]byte, 16)
	if _, err := os.ReadFile("/dev/urandom"); err != nil {
		// Fallback: use timestamp-based nonce.
		binary.BigEndian.PutUint64(nonce, uint64(time.Now().UnixNano()))
	}

	update := &AllowlistUpdate{
		Action:    action,
		Entries:   entries,
		Timestamp: time.Now().Unix(),
		Nonce:     hex.EncodeToString(nonce),
	}

	// Build message for signing.
	msg := struct {
		Action    string           `json:"action"`
		Entries   []AllowlistEntry `json:"entries,omitempty"`
		Timestamp int64            `json:"timestamp"`
		Nonce     string           `json:"nonce"`
	}{
		Action:    update.Action,
		Entries:   update.Entries,
		Timestamp: update.Timestamp,
		Nonce:     update.Nonce,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(msgBytes)
	sig := ed25519.Sign(privateKey, hash[:])
	update.Signature = hex.EncodeToString(sig)

	return update, nil
}

// Ensure unsafe import is used (needed for BPF struct size checks).
var _ = unsafe.Sizeof(DropStats{})
