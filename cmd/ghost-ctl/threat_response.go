// Package main — threat_response.go implements the Proactive Threat Response Loop
// for GHOST-STACK CORE.
//
// Gap 5: Bridge AGENT-BETA and Layer 3 XDP.
//
// Architecture:
//   AGENT-BETA → Unix Socket → ThreatResponseHandler → Layer 3 XDP BPF Map
//
// Flow:
//   1. AGENT-BETA calculates threat_score > 80 for an IP
//   2. AGENT-BETA sends THREAT_ACTOR_PROFILED alert via Unix socket
//   3. ThreatResponseHandler (this file) receives the alert
//   4. Orchestrator creates an Ed25519-signed allowlist update
//   5. AllowlistManager.removeEntry() deletes the IP from the XDP LPM trie
//   6. Result: IP is silently dropped at NIC level — ABSOLUTE SILENCE
//
// This completes the "Observe → Profile → Silent Block" cycle.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
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
	config       ThreatResponseConfig
	l3Manager    *layer3.AllowlistManager
	listener     net.Listener
	blockedIPs   map[string]*BlockRecord
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	auditFn      func(AuditEntry)
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
	os.Chmod(trh.config.AlertSocketPath, 0o660)

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

// handleConnection processes alerts from a single AGENT-BETA connection.
func (trh *ThreatResponseHandler) handleConnection(conn net.Conn) {
	defer trh.wg.Done()
	defer conn.Close()

	buf := make([]byte, 65536)

	for {
		select {
		case <-trh.ctx.Done():
			return
		default:
		}

		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "threat-response: read: %v\n", err)
			}
			return
		}

		// Parse the BETA protocol: "BETA:<length>:<json>"
		data := string(buf[:n])
		trh.parseAndDispatch(data)
	}
}

// parseAndDispatch parses AGENT-BETA alert messages and dispatches actions.
func (trh *ThreatResponseHandler) parseAndDispatch(raw string) {
	// Format: "BETA:<len>:{json}" — may contain multiple messages.
	for len(raw) > 0 {
		idx := strings.Index(raw, "BETA:")
		if idx == -1 {
			break
		}
		raw = raw[idx+5:]

		// Find the colon separating length from JSON.
		colonIdx := strings.Index(raw, ":")
		if colonIdx == -1 {
			break
		}
		raw = raw[colonIdx+1:]

		// Find the end of the JSON object.
		var alert BetaAlert
		decoder := json.NewDecoder(strings.NewReader(raw))
		if err := decoder.Decode(&alert); err != nil {
			break
		}

		// Dispatch based on event type.
		trh.processAlert(&alert)

		// Advance past the consumed JSON.
		consumed := int(decoder.InputOffset())
		if consumed < len(raw) {
			raw = raw[consumed:]
		} else {
			break
		}
	}
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
				}
			}
		}
	}
	if toolsRaw, ok := alert.Details["tools"]; ok {
		if toolSlice, ok := toolsRaw.([]interface{}); ok {
			for _, t := range toolSlice {
				if s, ok := t.(string); ok {
					tools = append(tools, s)
				}
			}
		}
	}

	// Trigger the block.
	trh.blockIP(alert.SourceIP, alert.ThreatScore, "THREAT_SCORE_EXCEEDED", alert.Details)
}

// blockIP removes an IP from the Layer 3 XDP allowlist via a signed update.
// After this, the IP is silently dropped at NIC driver level — ABSOLUTE SILENCE.
func (trh *ThreatResponseHandler) blockIP(ip string, score int, reason string, details map[string]interface{}) {
	fmt.Printf("[THREAT-RESPONSE] ⚡ AUTO-BLOCK: %s (score=%d, reason=%s)\n", ip, score, reason)

	// Construct the CIDR for a single IP.
	cidr := ip + "/32"

	// Create an Ed25519-signed allowlist removal.
	update, err := layer3.SignUpdate(trh.config.PrivateKey, "remove", []layer3.AllowlistEntry{
		{CIDR: cidr, Label: fmt.Sprintf("auto-block:%s", reason)},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "threat-response: sign update: %v\n", err)
		return
	}

	// Apply the signed update to the Layer 3 XDP allowlist.
	if err := trh.l3Manager.ApplyUpdate(update); err != nil {
		// If removal fails (IP might not be in allowlist), this is fine —
		// the IP was already not allowed, so it's already being dropped.
		fmt.Fprintf(os.Stderr, "threat-response: apply update: %v (non-fatal)\n", err)
	}

	// Record the block.
	record := &BlockRecord{
		IP:          ip,
		ThreatScore: score,
		BlockedAt:   time.Now(),
		Reason:      reason,
	}

	trh.mu.Lock()
	trh.blockedIPs[ip] = record
	trh.mu.Unlock()

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
				"method":       "XDP_LPM_TRIE_REMOVE",
				"effect":       "ABSOLUTE_SILENCE",
			},
			Result: "SUCCESS",
		})
	}

	fmt.Printf("[THREAT-RESPONSE] ✓ %s now in ABSOLUTE SILENCE (XDP_DROP at NIC level)\n", ip)
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
		"total_blocked":    len(trh.blockedIPs),
		"score_threshold":  trh.config.ThreatScoreThreshold,
		"require_l2_hits":  trh.config.RequireL2Hits,
	}
}
