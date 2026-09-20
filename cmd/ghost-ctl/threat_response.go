// Package main — threat_response.go implements the Proactive Threat Response Loop
// for GHOST-STACK CORE.
//
// Gap 5: Bridge AGENT-BETA and Layer 3 XDP.
//
// Architecture:
//
//	AGENT-BETA → Unix Socket → ThreatResponseHandler → Layer 3 XDP BPF Map
//
// Flow:
//  1. AGENT-BETA calculates threat_score > 80 for an IP
//  2. AGENT-BETA sends THREAT_ACTOR_PROFILED alert via Unix socket
//  3. ThreatResponseHandler (this file) receives the alert
//  4. Orchestrator creates an Ed25519-signed allowlist update
//  5. AllowlistManager.removeEntry() deletes the IP from the XDP LPM trie
//  6. Result: IP is silently dropped at NIC level — ABSOLUTE SILENCE
//
// This completes the "Observe → Profile → Silent Block" cycle.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	layer3 "github.com/ghost-stack/core/firewall/layer3"
)

// ThreatResponseConfig configures the proactive response loop.
type ThreatResponseConfig struct {
	// AlertSocketPath is the Unix domain socket where AGENT-BETA sends alerts.
	AlertSocketPath string
	// ThreatScoreThreshold is the minimum score to trigger auto-block (default: 80).
	ThreatScoreThreshold int
	// RequireL2Hits requires at least 1 L2 hit before auto-blocking.
	RequireL2Hits bool
	// Ed25519 key pair for signing allowlist updates.
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// BetaAlert mirrors the agents/beta Alert structure for deserialization.
type BetaAlert struct {
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	EventType   string                 `json:"event_type"`
	SourceIP    string                 `json:"source_ip"`
	ThreatScore int                    `json:"threat_score"`
	Details     map[string]interface{} `json:"details"`
}

// BlockRecord tracks a blocked IP for audit purposes.
type BlockRecord struct {
	IP          string    `json:"ip"`
	ThreatScore int       `json:"threat_score"`
	BlockedAt   time.Time `json:"blocked_at"`
	Reason      string    `json:"reason"`
	TTPs        []string  `json:"ttps,omitempty"`
	Tools       []string  `json:"tools,omitempty"`
}

// ThreatResponseHandler implements the Observe → Profile → Silent Block loop.
type ThreatResponseHandler struct {
	config     ThreatResponseConfig
	l3Manager  *layer3.AllowlistManager
	listener   net.Listener
	blockedIPs map[string]*BlockRecord
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	auditFn    func(AuditEntry)
}

// NewThreatResponseHandler creates a new handler bridging AGENT-BETA to Layer 3 XDP.
func NewThreatResponseHandler(
	cfg ThreatResponseConfig,
	l3Mgr *layer3.AllowlistManager,
	auditFn func(AuditEntry),
) *ThreatResponseHandler {
	ctx, cancel := context.WithCancel(context.Background())

	if cfg.ThreatScoreThreshold == 0 {
		cfg.ThreatScoreThreshold = 80
	}

	return &ThreatResponseHandler{
		config:     cfg,
		l3Manager:  l3Mgr,
		blockedIPs: make(map[string]*BlockRecord),
		ctx:        ctx,
		cancel:     cancel,
		auditFn:    auditFn,
	}
}

// Start begins listening on the alert socket for AGENT-BETA signals.
func (trh *ThreatResponseHandler) Start() error {
	// Remove stale socket.
	os.Remove(trh.config.AlertSocketPath)

	var err error
	trh.listener, err = net.Listen("unix", trh.config.AlertSocketPath)
	if err != nil {
		return fmt.Errorf("threat-response: listen: %w", err)
	}

	// Set socket permissions — only ghost-agent group can write.
	_ = os.Chmod(trh.config.AlertSocketPath, 0o660)

	trh.wg.Add(1)
	go trh.acceptLoop()

	fmt.Printf("[THREAT-RESPONSE] Listening on %s (threshold: score > %d)\n",
		trh.config.AlertSocketPath, trh.config.ThreatScoreThreshold)

	return nil
}

// Stop gracefully shuts down the threat response handler.
func (trh *ThreatResponseHandler) Stop() {
	trh.cancel()
	if trh.listener != nil {
		trh.listener.Close()
	}
	trh.wg.Wait()
}

// acceptLoop accepts connections from AGENT-BETA on the alert socket.
func (trh *ThreatResponseHandler) acceptLoop() {
	defer trh.wg.Done()

	for {
		conn, err := trh.listener.Accept()
		if err != nil {
			select {
			case <-trh.ctx.Done():
				return
			default:
				continue
			}
		}

		trh.wg.Add(1)
		go trh.handleConnection(conn)
	}
}

// betaFrameMagic prefixes every AGENT-BETA alert frame on the socket.
// Wire format: "BETA:<len>:<json>" where <len> is the decimal byte length
// of the JSON payload. The length field is authoritative: the reader waits
// until exactly <len> bytes have arrived, so fragmented TCP/Unix-socket
// reads and coalesced messages are both handled correctly.
const betaFrameMagic = "BETA:"

const (
	// maxFrameSize caps a single alert frame (1 MiB — alerts are small JSON).
	maxFrameSize = 1 << 20
	// maxFrameBuffer caps the per-connection reassembly buffer (4 MiB).
	maxFrameBuffer = 4 << 20
)

// handleConnection processes alerts from a single AGENT-BETA connection.
// It reassembles length-prefixed frames across arbitrary Read boundaries.
func (trh *ThreatResponseHandler) handleConnection(conn net.Conn) {
	defer trh.wg.Done()
	defer conn.Close()

	var buf []byte
	tmp := make([]byte, 65536)

	for {
		// Drain all complete frames currently buffered.
		for {
			frame, rest, ok := extractFrame(buf)
			buf = rest // keep resync progress even when no frame is complete
			if !ok {
				break
			}
			trh.dispatchFrame(frame)
		}

		select {
		case <-trh.ctx.Done():
			return
		default:
		}

		n, err := conn.Read(tmp)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "threat-response: read: %v\n", err)
			}
			return
		}
		if n == 0 {
			continue
		}

		buf = append(buf, tmp[:n]...)
		if len(buf) > maxFrameBuffer {
			fmt.Fprintf(os.Stderr, "threat-response: frame buffer overflow — dropping connection\n")
			return
		}
	}
}

// extractFrame pulls one complete "BETA:<len>:<json>" frame from buf.
// Returns the frame payload, the remaining bytes, and whether a complete
// frame was available.
func extractFrame(buf []byte) (frame []byte, rest []byte, ok bool) {
	magic := []byte(betaFrameMagic)

	if len(buf) < len(magic) {
		return nil, buf, false
	}
	if !bytes.HasPrefix(buf, magic) {
		// Resynchronize on the next magic; keep a tail in case the
		// magic itself was split across two reads.
		if i := bytes.Index(buf, magic); i >= 0 {
			return nil, buf[i:], false
		}
		if len(buf) >= len(magic) {
			return nil, buf[len(buf)-len(magic)+1:], false
		}
		return nil, buf, false
	}

	hdr := buf[len(magic):]
	colon := bytes.IndexByte(hdr, ':')
	if colon < 0 {
		return nil, buf, false // header incomplete — wait for more data
	}
	length, err := strconv.Atoi(string(hdr[:colon]))
	if err != nil || length < 0 || length > maxFrameSize {
		// Corrupt header — skip it and resynchronize.
		return nil, buf[len(magic)+colon+1:], false
	}

	total := len(magic) + colon + 1 + length
	if len(buf) < total {
		return nil, buf, false // payload incomplete — wait for more data
	}
	return buf[len(magic)+colon+1 : total], buf[total:], true
}

// dispatchFrame decodes one complete alert frame and processes it.
func (trh *ThreatResponseHandler) dispatchFrame(frame []byte) {
	var alert BetaAlert
	if err := json.Unmarshal(frame, &alert); err != nil {
		fmt.Fprintf(os.Stderr, "threat-response: bad alert frame: %v\n", err)
		return
	}
	trh.processAlert(&alert)
}

// processAlert evaluates an AGENT-BETA alert and triggers auto-block if warranted.
func (trh *ThreatResponseHandler) processAlert(alert *BetaAlert) {
	// Only process THREAT_ACTOR_PROFILED and L4_VIOLATION events.
	switch alert.EventType {
	case "THREAT_ACTOR_PROFILED":
		trh.handleThreatActorProfiled(alert)
	case "L4_VIOLATION":
		// L4 violations are always critical — immediate block.
		trh.blockIP(alert.SourceIP, alert.ThreatScore, "L4_VIOLATION", alert.Details)
	default:
		// Other alert types are informational — no action.
		return
	}
}

// handleThreatActorProfiled processes a profiled threat actor alert.
// Triggers auto-block if threat_score > threshold AND l2_hits > 0.
func (trh *ThreatResponseHandler) handleThreatActorProfiled(alert *BetaAlert) {
	if alert.SourceIP == "" {
		return
	}

	// Check threshold.
	if alert.ThreatScore <= trh.config.ThreatScoreThreshold {
		return
	}

	// Check L2 hits requirement.
	if trh.config.RequireL2Hits {
		l2Hits, ok := alert.Details["l2_hits"]
		if !ok {
			return
		}
		// Type assertion — JSON numbers decode as float64.
		switch v := l2Hits.(type) {
		case float64:
			if v == 0 {
				return
			}
		case int:
			if v == 0 {
				return
			}
		case uint64:
			if v == 0 {
				return
			}
		}
	}

	// Check if already blocked.
	trh.mu.Lock()
	if _, blocked := trh.blockedIPs[alert.SourceIP]; blocked {
		trh.mu.Unlock()
		return // Already blocked.
	}
	trh.mu.Unlock()

	// Extract TTP tags and tools from details.
	var ttps, tools []string
	if ttpRaw, ok := alert.Details["ttp_tags"]; ok {
		if ttpSlice, ok := ttpRaw.([]interface{}); ok {
			for _, t := range ttpSlice {
				if s, ok := t.(string); ok {
					ttps = append(ttps, s)
					_ = ttps
				}
			}
		}
	}
	if toolsRaw, ok := alert.Details["tools"]; ok {
		if toolSlice, ok := toolsRaw.([]interface{}); ok {
			for _, t := range toolSlice {
				if s, ok := t.(string); ok {
					tools = append(tools, s)
					_ = tools
				}
			}
		}
	}

	// Trigger the block.
	trh.blockIP(alert.SourceIP, alert.ThreatScore, "THREAT_SCORE_EXCEEDED", alert.Details)
}

// blockIP denies an IP at the Layer 3 XDP allowlist via a signed update.
// It removes the exact /32 entry, or — if the IP is only covered by a
// broader CIDR — punches a precise hole so the rest of the subnet stays
// allowed. If the IP was never allowlisted the block is a no-op and the
// audit record says so honestly instead of claiming success.
func (trh *ThreatResponseHandler) blockIP(ip string, score int, reason string, details map[string]interface{}) {
	fmt.Printf("[THREAT-RESPONSE] ⚡ AUTO-BLOCK: %s (score=%d, reason=%s)\n", ip, score, reason)

	// Compute the allowlist mutation that denies this IP (exact /32
	// removal, or a precise hole punched in a covering CIDR).
	remove, add, changed, err := trh.l3Manager.PlanIPRemoval(ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "threat-response: plan removal of %s: %v\n", ip, err)
		return
	}

	denied := false
	if changed {
		// One Ed25519-signed "carve" update applies the removal and the
		// hole-punch adds atomically: either both land or the allowlist
		// rolls back to its pre-block state — no half-blocked window.
		update, err := layer3.SignCarveUpdate(trh.config.PrivateKey, remove, add)
		if err != nil {
			fmt.Fprintf(os.Stderr, "threat-response: sign carve update: %v\n", err)
			return
		}
		if err := trh.l3Manager.ApplyUpdate(update); err != nil {
			fmt.Fprintf(os.Stderr, "threat-response: apply carve update: %v\n", err)
			return
		}
		denied = true
	}

	// Record the block intent (also serves as dedup for repeated alerts).
	record := &BlockRecord{
		IP:          ip,
		ThreatScore: score,
		BlockedAt:   time.Now(),
		Reason:      reason,
	}

	trh.mu.Lock()
	trh.blockedIPs[ip] = record
	trh.mu.Unlock()

	// Honest audit: only claim kernel-level denial when the allowlist
	// actually changed. An IP that was never allowlisted was already
	// denied by the allowlist model — record that as a no-op.
	result := "SUCCESS"
	effect := "ABSOLUTE_SILENCE"
	if !denied {
		result = "NOOP_ALREADY_DENIED"
		effect = "NONE_IP_WAS_NEVER_ALLOWLISTED"
		fmt.Printf("[THREAT-RESPONSE] • %s was not in the allowlist — already denied, no kernel change\n", ip)
	} else {
		fmt.Printf("[THREAT-RESPONSE] ✓ %s now in ABSOLUTE SILENCE (XDP_DROP at NIC level)\n", ip)
	}

	// Append to audit log.
	if trh.auditFn != nil {
		trh.auditFn(AuditEntry{
			Timestamp: time.Now(),
			Action:    "AUTO_BLOCK",
			Actor:     "THREAT-RESPONSE",
			Details: map[string]interface{}{
				"ip":           ip,
				"threat_score": score,
				"reason":       reason,
				"method":       "XDP_ALLOWLIST_REMOVE",
				"effect":       effect,
			},
			Result: result,
		})
	}
}

// ListBlockedIPs returns all currently blocked IPs.
func (trh *ThreatResponseHandler) ListBlockedIPs() []*BlockRecord {
	trh.mu.Lock()
	defer trh.mu.Unlock()

	var result []*BlockRecord
	for _, record := range trh.blockedIPs {
		result = append(result, record)
	}
	return result
}

// UnblockIP manually removes an IP from the block list and re-adds it
// to the allowlist. Requires operator intervention.
func (trh *ThreatResponseHandler) UnblockIP(ip string) error {
	trh.mu.Lock()
	delete(trh.blockedIPs, ip)
	trh.mu.Unlock()

	cidr := ip + "/32"
	update, err := layer3.SignUpdate(trh.config.PrivateKey, "add", []layer3.AllowlistEntry{
		{CIDR: cidr, Label: "manual-unblock"},
	})
	if err != nil {
		return fmt.Errorf("threat-response: sign unblock: %w", err)
	}

	return trh.l3Manager.ApplyUpdate(update)
}

// Stats returns threat response statistics.
func (trh *ThreatResponseHandler) Stats() map[string]interface{} {
	trh.mu.Lock()
	defer trh.mu.Unlock()

	return map[string]interface{}{
		"total_blocked":   len(trh.blockedIPs),
		"score_threshold": trh.config.ThreatScoreThreshold,
		"require_l2_hits": trh.config.RequireL2Hits,
	}
}
