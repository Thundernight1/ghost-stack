// Package beta implements AGENT-BETA — the passive firewall observer
// for GHOST-STACK CORE's 4-layer deception firewall.
//
// Architecture: 4 goroutines, one per layer feed:
//   - L1 goroutine: reads nflog ring buffer (netlink socket)
//   - L2 goroutine: reads eBPF perf_event_array
//   - L3 goroutine: polls XDP drop counter BPF map every 500ms
//   - L4 goroutine: reads LSM audit netlink socket
//
// STRICTLY PASSIVE — zero blocking capability, zero write capability.
// All data is in-memory only — NEVER written to disk unless
// orchestrator explicitly requests forensic export (signed command).
package beta

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// AgentBetaConfig holds configuration for AGENT-BETA.
type AgentBetaConfig struct {
	// NflogGroup is the nflog group ID for Layer 1 events (default: 1).
	NflogGroup uint16
	// L2PerfMapPath is the pinned BPF perf_event_array path for L2.
	L2PerfMapPath string
	// L3DropMapPath is the pinned BPF map path for L3 drop counters.
	L3DropMapPath string
	// AlertSocketPath is the Unix domain socket for sending alerts.
	AlertSocketPath string
	// OrchestratorAddr is the address for the orchestrator control plane.
	OrchestratorAddr string
}

// LayerEvent represents an event from any firewall layer.
type LayerEvent struct {
	Layer     int                    `json:"layer"`
	Timestamp time.Time              `json:"timestamp"`
	SourceIP  string                 `json:"source_ip"`
	EventType string                 `json:"event_type"`
	Details   map[string]interface{} `json:"details"`
	RawData   []byte                 `json:"-"`
}

// Alert represents an alert sent to the orchestrator.
type Alert struct {
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity"` // INFO, WARNING, CRITICAL, ALERT
	Source      string                 `json:"source"`   // AGENT-BETA
	EventType   string                 `json:"event_type"`
	SourceIP    string                 `json:"source_ip,omitempty"`
	ThreatScore int                    `json:"threat_score,omitempty"`
	Profile     *AttackerProfile       `json:"profile,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// AgentBeta is the main AGENT-BETA passive firewall observer.
type AgentBeta struct {
	config   AgentBetaConfig
	profiler *Profiler
	mapper   *TTPMapper

	// Event channels — one per layer.
	l1Events chan LayerEvent
	l2Events chan LayerEvent
	l3Events chan LayerEvent
	l4Events chan LayerEvent

	// Alert output.
	alertConn net.Conn
	alertMu   sync.Mutex

	// Lifecycle.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewAgentBeta creates a new AGENT-BETA instance.
func NewAgentBeta(cfg AgentBetaConfig) *AgentBeta {
	ctx, cancel := context.WithCancel(context.Background())

	if cfg.NflogGroup == 0 {
		cfg.NflogGroup = 1 // documented default
	}

	return &AgentBeta{
		config:   cfg,
		profiler: NewProfiler(50000),
		mapper:   NewTTPMapper(),
		l1Events: make(chan LayerEvent, 1024),
		l2Events: make(chan LayerEvent, 1024),
		l3Events: make(chan LayerEvent, 1024),
		l4Events: make(chan LayerEvent, 512),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start launches all 4 goroutines and the event correlator.
func (ab *AgentBeta) Start() error {
	// Connect to alert socket.
	if ab.config.AlertSocketPath != "" {
		conn, err := net.Dial("unix", ab.config.AlertSocketPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent-beta: alert socket: %v\n", err)
		} else {
			ab.alertConn = conn
		}
	}

	// Launch 4 layer goroutines.
	ab.wg.Add(5)

	// L1: nflog reader.
	go ab.l1NflogReader()

	// L2: eBPF perf_event reader.
	go ab.l2PerfReader()

	// L3: XDP drop counter poller.
	go ab.l3DropPoller()

	// L4: LSM audit reader.
	go ab.l4AuditReader()

	// Correlator: processes events from all 4 layers.
	go ab.eventCorrelator()

	return nil
}

// Stop gracefully shuts down AGENT-BETA.
func (ab *AgentBeta) Stop() {
	ab.cancel()
	ab.wg.Wait()
	if ab.alertConn != nil {
		ab.alertConn.Close()
	}
}

// --- Layer 1 Goroutine: nflog ring buffer reader ---

func (ab *AgentBeta) l1NflogReader() {
	defer ab.wg.Done()

	r, err := openNFLOG(ab.config.NflogGroup)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent-beta/L1: %v — L1 feed disabled\n", err)
		return
	}
	defer r.close()

	// Unblock the pending Recvfrom when the agent stops.
	go func() {
		<-ab.ctx.Done()
		r.close()
	}()

	buf := make([]byte, 65536)
	for {
		packets, err := r.readPacket(buf)
		if err != nil {
			if ab.ctx.Err() != nil {
				return
			}
			continue
		}
		for _, p := range packets {
			ev := nflogEvent(p)
			select {
			case ab.l1Events <- ev:
			default:
				// Drop if channel full — never block the kernel feed.
			}
		}
	}
}

// --- Layer 2 Goroutine: eBPF perf_event_array reader ---

func (ab *AgentBeta) l2PerfReader() {
	defer ab.wg.Done()

	if ab.config.L2PerfMapPath == "" {
		fmt.Fprintf(os.Stderr, "agent-beta/L2: no perf map path configured — L2 feed disabled\n")
		return
	}
	r, err := openL2Perf(ab.config.L2PerfMapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent-beta/L2: %v — L2 feed disabled\n", err)
		return
	}
	defer r.close()

	// Unblock the pending perf read when the agent stops.
	go func() {
		<-ab.ctx.Done()
		r.close()
	}()

	for {
		ev, err := r.nextEvent()
		if err != nil {
			if ab.ctx.Err() != nil {
				return
			}
			// Transient perf error — back off briefly, then continue.
			time.Sleep(time.Second)
			continue
		}

		select {
		case ab.l2Events <- ev:
		default:
		}
	}
}

// --- Layer 3 Goroutine: XDP drop counter map poller ---

func (ab *AgentBeta) l3DropPoller() {
	defer ab.wg.Done()

	if ab.config.L3DropMapPath == "" {
		fmt.Fprintf(os.Stderr, "agent-beta/L3: no drop map path configured — L3 feed disabled\n")
		return
	}

	// prev holds the last-seen per-IP totals so only new drops are emitted.
	prev := make(map[string]uint64)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ab.ctx.Done():
			return
		case <-ticker.C:
			drops, err := pollL3Drops(ab.config.L3DropMapPath, prev)
			if err != nil {
				continue
			}

			for ip, stats := range drops {
				event := LayerEvent{
					Layer:     3,
					Timestamp: time.Now(),
					SourceIP:  ip,
					EventType: "XDP_DROP",
					Details: map[string]interface{}{
						"count":         stats.Count,
						"last_dst_port": stats.LastDstPort,
						"last_proto":    stats.LastProto,
					},
				}

				select {
				case ab.l3Events <- event:
				default:
				}
			}
		}
	}
}

// --- Layer 4 Goroutine: LSM audit netlink reader ---

func (ab *AgentBeta) l4AuditReader() {
	defer ab.wg.Done()

	r, err := openAuditNetlink()
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent-beta/L4: %v — L4 feed disabled\n", err)
		return
	}
	defer r.close()

	// Unblock the pending Recvfrom when the agent stops.
	go func() {
		<-ab.ctx.Done()
		r.close()
	}()

	buf := make([]byte, 8192)
	for {
		events, err := r.readMessage(buf)
		if err != nil {
			if ab.ctx.Err() != nil {
				return
			}
			continue
		}

		for _, e := range events {
			le := auditLayerEvent(e)
			select {
			case ab.l4Events <- *le:
			default:
			}
		}
	}
}

// --- Event Correlator ---

func (ab *AgentBeta) eventCorrelator() {
	defer ab.wg.Done()

	for {
		select {
		case <-ab.ctx.Done():
			return

		case event := <-ab.l1Events:
			ab.processL1Event(event)

		case event := <-ab.l2Events:
			ab.processL2Event(event)

		case event := <-ab.l3Events:
			ab.processL3Event(event)

		case event := <-ab.l4Events:
			ab.processL4Event(event)
		}
	}
}

// --- L1 Event Processing ---

func (ab *AgentBeta) processL1Event(event LayerEvent) {
	if event.SourceIP == "" {
		return
	}

	profile := ab.profiler.GetOrCreate(event.SourceIP)

	profile.mu.Lock()
	profile.L1Hits++
	profile.LastSeen = time.Now()

	// Port scan detection: >20 ports in 5 seconds.
	if portCount, ok := event.Details["ports_in_window"].(int); ok && portCount > 20 {
		profile.ThreatScore += 10
		ab.mapper.TagTTP(profile, "T1046", "Network Service Discovery")
	}

	// Known scanner User-Agent detection.
	if ua, ok := event.Details["user_agent"].(string); ok {
		if tool := ab.mapper.DetectTool(ua); tool != "" {
			profile.ThreatScore += 20
			profile.ToolsDetected = appendUnique(profile.ToolsDetected, tool)
		}
	}

	// SYN flood detection: >500/s.
	if rate, ok := event.Details["syn_rate"].(int); ok && rate > 500 {
		profile.ThreatScore += 30
		ab.mapper.TagTTP(profile, "T1498", "Network Denial of Service")
	}

	profile.mu.Unlock()

	// Still NO action — only profile update.
}

// --- L2 Event Processing ---

func (ab *AgentBeta) processL2Event(event LayerEvent) {
	if event.SourceIP == "" {
		return
	}

	profile := ab.profiler.GetOrCreate(event.SourceIP)

	profile.mu.Lock()
	profile.L2Hits++
	profile.LastSeen = time.Now()

	switch event.EventType {
	case "CREDENTIAL":
		// Credential attempt: capture + threat_score += 15.
		profile.ThreatScore += 15
		cred := CredAttempt{
			Timestamp: event.Timestamp,
		}
		if user, ok := event.Details["username"].(string); ok {
			cred.User = user
		}
		if pass, ok := event.Details["password"].(string); ok {
			cred.Pass = pass
		}
		profile.CredsAttempted = append(profile.CredsAttempted, cred)
		ab.mapper.TagTTP(profile, "T1110", "Brute Force")

	case "EXPLOIT":
		// Exploit payload: threat_score += 40.
		profile.ThreatScore += 40
		exploit := ExploitAttempt{
			Timestamp: event.Timestamp,
		}
		if t, ok := event.Details["exploit_type"].(string); ok {
			exploit.Type = t
		}
		if h, ok := event.Details["payload_hash"].(string); ok {
			exploit.PayloadHash = h
		}
		profile.ExploitAttempts = append(profile.ExploitAttempts, exploit)

		// MITRE ATT&CK mapping based on exploit type.
		if exploit.Type == "sqli" {
			ab.mapper.TagTTP(profile, "T1190", "Exploit Public-Facing Application")
		} else if exploit.Type == "log4shell" {
			ab.mapper.TagTTP(profile, "T1190", "Exploit Public-Facing Application")
			ab.mapper.TagTTP(profile, "T1059", "Command and Scripting Interpreter")
		} else if exploit.Type == "ssrf" {
			ab.mapper.TagTTP(profile, "T1190", "Exploit Public-Facing Application")
			ab.mapper.TagTTP(profile, "T1552", "Unsecured Credentials")
		}

	case "API_ABUSE":
		profile.ThreatScore += 25
		ab.mapper.TagTTP(profile, "T1106", "Native API")

	case "TOOL_SIGNATURE":
		if tool, ok := event.Details["tool"].(string); ok {
			profile.ToolsDetected = appendUnique(profile.ToolsDetected, tool)
			profile.ThreatScore += 20
		}
	}

	profile.mu.Unlock()

	// Still NO action — profile + score only.
}

// --- L3 Event Processing ---

func (ab *AgentBeta) processL3Event(event LayerEvent) {
	if event.SourceIP == "" {
		return
	}

	profile := ab.profiler.GetOrCreate(event.SourceIP)

	profile.mu.Lock()
	if count, ok := event.Details["count"].(uint64); ok {
		profile.L3Drops += count
	}
	profile.LastSeen = time.Now()

	// Correlate with L1/L2: calculate TTP timeline.
	if profile.L1Hits > 0 || profile.L2Hits > 0 {
		ab.mapper.TagTTP(profile, "TA0043", "Reconnaissance")
		if profile.L2Hits > 0 {
			ab.mapper.TagTTP(profile, "TA0001", "Initial Access Attempt")
		}
	}

	profile.mu.Unlock()
}

// --- L4 Event Processing ---

func (ab *AgentBeta) processL4Event(event LayerEvent) {
	// L4 events are from INSIDE the department namespaces.
	// Legitimate-appearing traffic violating policy = CRITICAL.
	// This means either insider threat or compromised department.

	profile := ab.profiler.GetOrCreate(event.SourceIP)

	profile.mu.Lock()
	profile.L4Violations++
	profile.LastSeen = time.Now()
	profile.ThreatScore += 50 // L4 violations are always high severity.
	ab.mapper.TagTTP(profile, "T1548", "Abuse Elevation Control Mechanism")
	profile.mu.Unlock()

	// IMMEDIATE alert — L4 violations are always critical.
	ab.sendAlert(Alert{
		Timestamp:   time.Now(),
		Severity:    "CRITICAL",
		Source:      "AGENT-BETA",
		EventType:   "L4_VIOLATION",
		SourceIP:    event.SourceIP,
		ThreatScore: profile.ThreatScore,
		Details:     event.Details,
	})
}

// --- Proactive Response Trigger ---
// Called periodically by the correlator.

// --- Alert Sending ---

func (ab *AgentBeta) sendAlert(alert Alert) {
	ab.alertMu.Lock()
	defer ab.alertMu.Unlock()

	if ab.alertConn == nil {
		// Try reconnecting.
		conn, err := net.Dial("unix", ab.config.AlertSocketPath)
		if err != nil {
			return
		}
		ab.alertConn = conn
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return
	}

	// Single write: "BETA:<len>:<json>". Two Writes risk the header and
	// the payload being split across reads on a datagram socket, which
	// breaks the length-framed protocol the orchestrator parses.
	frame := append([]byte(fmt.Sprintf("BETA:%d:", len(data))), data...)
	if _, err := ab.alertConn.Write(frame); err != nil {
		// Drop the dead connection so the next alert reconnects.
		ab.alertConn.Close()
		ab.alertConn = nil
	}
}

// l3DropStats is the per-IP drop aggregate used by the L3 poller.
type l3DropStats struct {
	Count       uint64
	LastDstPort uint16
	LastProto   uint8
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
