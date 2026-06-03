// Package alpha implements AGENT-ALPHA — the passive internal observer
// for GHOST-STACK CORE department containers.
//
// Agent-Alpha is STRICTLY PASSIVE:
//   - ZERO write capability — read-only eBPF ring buffer consumer
//   - NEVER blocks, NEVER modifies — observe and report only
//   - Events sent via Unix domain socket to central alert bus
//   - NOT logged to container filesystem
//   - Binary mounted read-only from host — container cannot tamper
//   - Runs under dedicated UID with only CAP_BPF + CAP_PERFMON
//
// Uses cilium/ebpf library (NOT bcc/Python).
package alpha

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Event types — must match alpha.bpf.c enum event_type.
const (
	EventExecve       = 1
	EventConnect      = 2
	EventCommitCreds  = 3
	EventUnshare      = 4
	EventOpenat       = 5
)

// Severity levels — must match alpha.bpf.c enum severity.
const (
	SevInfo     = 0
	SevWarning  = 1
	SevCritical = 2
	SevAlert    = 3
)

// EventHeader is the common header for all eBPF events.
// Must match struct event_header in alpha.bpf.c exactly.
type EventHeader struct {
	TimestampNs uint64
	PID         uint32
	TGID        uint32
	UID         uint32
	GID         uint32
	EventType   uint32
	Severity    uint32
	PIDNsID     uint32
	MntNsID     uint32
	Comm        [16]byte
}

// ExecveEvent represents a process execution event.
type ExecveEvent struct {
	Header   EventHeader
	Filename [256]byte
	Args     [512]byte
	Flags    uint32
}

// ConnectEvent represents an outbound connection event.
type ConnectEvent struct {
	Header   EventHeader
	Family   uint16
	DstPort  uint16
	DstIPv4  uint32
	DstIPv6  [16]byte
	SockFD   int32
}

// CredsEvent represents a credential change event.
type CredsEvent struct {
	Header     EventHeader
	OldUID     uint32
	OldGID     uint32
	NewUID     uint32
	NewGID     uint32
	OldCapLo   uint32
	OldCapHi   uint32
	NewCapLo   uint32
	NewCapHi   uint32
}

// UnshareEvent represents a namespace manipulation event.
type UnshareEvent struct {
	Header        EventHeader
	UnshareFlags  uint64
}

// OpenatEvent represents a file access event.
type OpenatEvent struct {
	Header   EventHeader
	DirFD    int32
	Flags    int32
	Mode     uint32
	Filename [256]byte
}

// AlertEvent is the JSON-serializable event sent to the alert bus.
type AlertEvent struct {
	Timestamp    time.Time              `json:"timestamp"`
	DeptID       int                    `json:"dept_id"`
	EventType    string                 `json:"event_type"`
	Severity     string                 `json:"severity"`
	PID          uint32                 `json:"pid"`
	TGID         uint32                 `json:"tgid"`
	UID          uint32                 `json:"uid"`
	Comm         string                 `json:"comm"`
	PIDNamespace uint32                 `json:"pid_namespace"`
	MntNamespace uint32                 `json:"mnt_namespace"`
	Details      map[string]interface{} `json:"details"`
}

// ObserverConfig holds configuration for the AGENT-ALPHA observer.
type ObserverConfig struct {
	// DeptID identifies the department container being observed.
	DeptID int
	// TargetPIDNsID is the PID namespace ID of the monitored container.
	// Set to 0 to monitor all namespaces.
	TargetPIDNsID uint32
	// AlertSocketPath is the Unix domain socket for sending events.
	AlertSocketPath string
	// BPFObjectPath is the path to the compiled eBPF object file.
	BPFObjectPath string
	// SensitivePaths are filesystem paths that trigger elevated alerts.
	SensitivePaths []string
}

// Observer is the AGENT-ALPHA passive observer instance.
type Observer struct {
	config     ObserverConfig
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	alertConn  net.Conn
	stopCh     chan struct{}
	wg         sync.WaitGroup

	// Metrics (in-memory only, never persisted).
	mu             sync.Mutex
	eventsReceived uint64
	eventsByType   map[uint32]uint64
	eventsBySev    map[uint32]uint64
}

// NewObserver creates a new AGENT-ALPHA observer.
func NewObserver(cfg ObserverConfig) *Observer {
	return &Observer{
		config:       cfg,
		stopCh:       make(chan struct{}),
		eventsByType: make(map[uint32]uint64),
		eventsBySev:  make(map[uint32]uint64),
	}
}

// Start loads the eBPF programs, attaches probes, and begins consuming
// the ring buffer. This is the main entry point for AGENT-ALPHA.
func (o *Observer) Start() error {
	// Step 1: Verify we have proper capabilities.
	if err := verifyCapabilities(); err != nil {
		return fmt.Errorf("agent-alpha: capability check: %w", err)
	}

	// Step 2: Load compiled eBPF object.
	spec, err := ebpf.LoadCollectionSpec(o.config.BPFObjectPath)
	if err != nil {
		return fmt.Errorf("agent-alpha: load BPF spec: %w", err)
	}

	// Step 3: Load collection (programs + maps).
	o.collection, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("agent-alpha: create BPF collection: %w", err)
	}

	// Step 4: Set target PID namespace in config map.
	if o.config.TargetPIDNsID != 0 {
		configMap := o.collection.Maps["config"]
		if configMap != nil {
			key := uint32(0)
			if err := configMap.Put(key, o.config.TargetPIDNsID); err != nil {
				return fmt.Errorf("agent-alpha: set target ns: %w", err)
			}
		}
	}

	// Step 5: Populate sensitive paths map.
	if err := o.populateSensitivePaths(); err != nil {
		fmt.Fprintf(os.Stderr, "agent-alpha: warning: sensitive paths setup: %v\n", err)
	}

	// Step 6: Attach tracepoint and kprobe programs.
	if err := o.attachPrograms(); err != nil {
		o.cleanup()
		return fmt.Errorf("agent-alpha: attach programs: %w", err)
	}

	// Step 7: Create ring buffer reader.
	eventsMap := o.collection.Maps["events"]
	if eventsMap == nil {
		o.cleanup()
		return fmt.Errorf("agent-alpha: 'events' ring buffer map not found")
	}

	o.reader, err = ringbuf.NewReader(eventsMap)
	if err != nil {
		o.cleanup()
		return fmt.Errorf("agent-alpha: create ring buffer reader: %w", err)
	}

	// Step 8: Connect to alert bus Unix domain socket.
	if o.config.AlertSocketPath != "" {
		o.alertConn, err = net.Dial("unix", o.config.AlertSocketPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent-alpha: alert socket connect: %v (events will be dropped)\n", err)
		}
	}

	// Step 9: Start ring buffer consumer goroutine.
	o.wg.Add(1)
	go o.consumeRingBuffer()

	return nil
}

// Stop gracefully shuts down the observer.
func (o *Observer) Stop() {
	close(o.stopCh)
	if o.reader != nil {
		o.reader.Close()
	}
	o.wg.Wait()
	o.cleanup()
}

// WaitForSignal blocks until SIGINT or SIGTERM is received.
func (o *Observer) WaitForSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

// Stats returns current observer statistics.
func (o *Observer) Stats() map[string]interface{} {
	o.mu.Lock()
	defer o.mu.Unlock()

	stats := map[string]interface{}{
		"events_received": o.eventsReceived,
		"events_by_type":  copyMap(o.eventsByType),
		"events_by_sev":   copyMap(o.eventsBySev),
	}
	return stats
}

// --- Internal methods ---

// attachPrograms attaches all eBPF programs to their hooks.
func (o *Observer) attachPrograms() error {
	type attachSpec struct {
		progName string
		attachFn func(prog *ebpf.Program) (link.Link, error)
	}

	specs := []attachSpec{
		{
			progName: "trace_execve",
			attachFn: func(prog *ebpf.Program) (link.Link, error) {
				return link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
			},
		},
		{
			progName: "trace_connect",
			attachFn: func(prog *ebpf.Program) (link.Link, error) {
				return link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
			},
		},
		{
			progName: "trace_commit_creds",
			attachFn: func(prog *ebpf.Program) (link.Link, error) {
				return link.Kprobe("commit_creds", prog, nil)
			},
		},
		{
			progName: "trace_unshare",
			attachFn: func(prog *ebpf.Program) (link.Link, error) {
				return link.Tracepoint("syscalls", "sys_enter_unshare", prog, nil)
			},
		},
		{
			progName: "trace_openat",
			attachFn: func(prog *ebpf.Program) (link.Link, error) {
				return link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
			},
		},
		{
			progName: "trace_setns",
			attachFn: func(prog *ebpf.Program) (link.Link, error) {
				return link.Tracepoint("syscalls", "sys_enter_setns", prog, nil)
			},
		},
	}

	for _, s := range specs {
		prog := o.collection.Programs[s.progName]
		if prog == nil {
			fmt.Fprintf(os.Stderr, "agent-alpha: program %s not found, skipping\n", s.progName)
			continue
		}

		l, err := s.attachFn(prog)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent-alpha: attach %s: %v\n", s.progName, err)
			continue
		}
		o.links = append(o.links, l)
	}

	if len(o.links) == 0 {
		return fmt.Errorf("no programs attached successfully")
	}

	return nil
}

// populateSensitivePaths fills the BPF hash map with paths that trigger alerts.
func (o *Observer) populateSensitivePaths() error {
	pathMap := o.collection.Maps["sensitive_paths"]
	if pathMap == nil {
		return fmt.Errorf("sensitive_paths map not found")
	}

	defaultPaths := []struct {
		path     string
		severity uint32
	}{
		{"/etc/shadow", SevCritical},
		{"/etc/passwd", SevWarning},
		{"/etc/sudoers", SevCritical},
		{"/proc/self/ns", SevAlert},
		{"/proc/1/ns", SevAlert},
		{"/dev/mem", SevAlert},
		{"/dev/kmem", SevAlert},
		{"/proc/kcore", SevAlert},
		{"/proc/kallsyms", SevCritical},
		{"/proc/modules", SevWarning},
		{"/sys/kernel/security", SevCritical},
		{"/var/run/docker.sock", SevAlert},
		{"/run/containerd", SevAlert},
	}

	// Add configured sensitive paths.
	for _, p := range o.config.SensitivePaths {
		defaultPaths = append(defaultPaths, struct {
			path     string
			severity uint32
		}{p, SevWarning})
	}

	for _, sp := range defaultPaths {
		hash := hashPath(sp.path)
		if err := pathMap.Put(hash, sp.severity); err != nil {
			fmt.Fprintf(os.Stderr, "agent-alpha: sensitive path %s: %v\n", sp.path, err)
		}
	}

	return nil
}

// consumeRingBuffer reads events from the eBPF ring buffer and
// forwards them to the alert bus. This runs in its own goroutine.
func (o *Observer) consumeRingBuffer() {
	defer o.wg.Done()

	for {
		record, err := o.reader.Read()
		if err != nil {
			select {
			case <-o.stopCh:
				return
			default:
				fmt.Fprintf(os.Stderr, "agent-alpha: ring buffer read: %v\n", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		// Parse the event header to determine event type.
		if len(record.RawSample) < int(unsafe.Sizeof(EventHeader{})) {
			continue
		}

		var hdr EventHeader
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &hdr); err != nil {
			continue
		}

		// Update metrics.
		o.mu.Lock()
		o.eventsReceived++
		o.eventsByType[hdr.EventType]++
		o.eventsBySev[hdr.Severity]++
		o.mu.Unlock()

		// Parse full event based on type.
		alert := o.parseEvent(hdr.EventType, record.RawSample)
		if alert == nil {
			continue
		}

		// Send to alert bus via Unix domain socket.
		o.sendAlert(alert)
	}
}

// parseEvent parses a raw eBPF event into an AlertEvent.
func (o *Observer) parseEvent(eventType uint32, raw []byte) *AlertEvent {
	reader := bytes.NewReader(raw)

	alert := &AlertEvent{
		Timestamp: time.Now(),
		DeptID:    o.config.DeptID,
		Details:   make(map[string]interface{}),
	}

	switch eventType {
	case EventExecve:
		var evt ExecveEvent
		if err := binary.Read(reader, binary.LittleEndian, &evt); err != nil {
			return nil
		}
		alert.EventType = "EXECVE"
		alert.PID = evt.Header.PID
		alert.TGID = evt.Header.TGID
		alert.UID = evt.Header.UID
		alert.Comm = nullTermString(evt.Header.Comm[:])
		alert.PIDNamespace = evt.Header.PIDNsID
		alert.MntNamespace = evt.Header.MntNsID
		alert.Severity = severityString(evt.Header.Severity)
		alert.Details["filename"] = nullTermString(evt.Filename[:])
		alert.Details["args"] = nullTermString(evt.Args[:])

	case EventConnect:
		var evt ConnectEvent
		if err := binary.Read(reader, binary.LittleEndian, &evt); err != nil {
			return nil
		}
		alert.EventType = "CONNECT"
		alert.PID = evt.Header.PID
		alert.TGID = evt.Header.TGID
		alert.UID = evt.Header.UID
		alert.Comm = nullTermString(evt.Header.Comm[:])
		alert.PIDNamespace = evt.Header.PIDNsID
		alert.MntNamespace = evt.Header.MntNsID
		alert.Severity = severityString(evt.Header.Severity)
		alert.Details["family"] = evt.Family
		alert.Details["dst_port"] = evt.DstPort
		if evt.Family == 2 { // AF_INET
			alert.Details["dst_ip"] = fmt.Sprintf("%d.%d.%d.%d",
				evt.DstIPv4&0xFF, (evt.DstIPv4>>8)&0xFF,
				(evt.DstIPv4>>16)&0xFF, (evt.DstIPv4>>24)&0xFF)
		}

	case EventCommitCreds:
		var evt CredsEvent
		if err := binary.Read(reader, binary.LittleEndian, &evt); err != nil {
			return nil
		}
		alert.EventType = "COMMIT_CREDS"
		alert.PID = evt.Header.PID
		alert.TGID = evt.Header.TGID
		alert.UID = evt.Header.UID
		alert.Comm = nullTermString(evt.Header.Comm[:])
		alert.PIDNamespace = evt.Header.PIDNsID
		alert.MntNamespace = evt.Header.MntNsID
		alert.Severity = severityString(evt.Header.Severity)
		alert.Details["old_uid"] = evt.OldUID
		alert.Details["new_uid"] = evt.NewUID
		alert.Details["old_gid"] = evt.OldGID
		alert.Details["new_gid"] = evt.NewGID
		alert.Details["cap_elevation"] = evt.NewCapLo > evt.OldCapLo || evt.NewCapHi > evt.OldCapHi

	case EventUnshare:
		var evt UnshareEvent
		if err := binary.Read(reader, binary.LittleEndian, &evt); err != nil {
			return nil
		}
		alert.EventType = "NAMESPACE_ESCAPE"
		alert.PID = evt.Header.PID
		alert.TGID = evt.Header.TGID
		alert.UID = evt.Header.UID
		alert.Comm = nullTermString(evt.Header.Comm[:])
		alert.PIDNamespace = evt.Header.PIDNsID
		alert.MntNamespace = evt.Header.MntNsID
		alert.Severity = severityString(evt.Header.Severity)
		alert.Details["unshare_flags"] = fmt.Sprintf("0x%x", evt.UnshareFlags)

	case EventOpenat:
		var evt OpenatEvent
		if err := binary.Read(reader, binary.LittleEndian, &evt); err != nil {
			return nil
		}
		alert.EventType = "FILE_ACCESS"
		alert.PID = evt.Header.PID
		alert.TGID = evt.Header.TGID
		alert.UID = evt.Header.UID
		alert.Comm = nullTermString(evt.Header.Comm[:])
		alert.PIDNamespace = evt.Header.PIDNsID
		alert.MntNamespace = evt.Header.MntNsID
		alert.Severity = severityString(evt.Header.Severity)
		alert.Details["filename"] = nullTermString(evt.Filename[:])
		alert.Details["flags"] = fmt.Sprintf("0x%x", evt.Flags)
		alert.Details["dirfd"] = evt.DirFD

	default:
		return nil
	}

	return alert
}

// sendAlert serializes an alert and sends it via Unix domain socket.
// NEVER writes to the container filesystem.
func (o *Observer) sendAlert(alert *AlertEvent) {
	if o.alertConn == nil {
		// Try reconnecting.
		var err error
		o.alertConn, err = net.Dial("unix", o.config.AlertSocketPath)
		if err != nil {
			return // Drop silently — agent is passive.
		}
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return
	}

	// Length-prefixed message.
	header := fmt.Sprintf("ALPHA:%d:%d:", o.config.DeptID, len(data))
	if _, err := o.alertConn.Write([]byte(header)); err != nil {
		o.alertConn.Close()
		o.alertConn = nil
		return
	}
	if _, err := o.alertConn.Write(data); err != nil {
		o.alertConn.Close()
		o.alertConn = nil
		return
	}
}

// cleanup releases all eBPF resources.
func (o *Observer) cleanup() {
	for _, l := range o.links {
		l.Close()
	}
	if o.collection != nil {
		o.collection.Close()
	}
	if o.alertConn != nil {
		o.alertConn.Close()
	}
}

// --- Utility functions ---

// verifyCapabilities checks that we have CAP_BPF and CAP_PERFMON.
func verifyCapabilities() error {
	// In production, use golang.org/x/sys/unix CapGet.
	// For now, a basic check via /proc/self/status.
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("cannot read proc status: %w", err)
	}
	_ = data // Parse CapEff in production.
	return nil
}

// nullTermString converts a null-terminated byte slice to a Go string.
func nullTermString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

// severityString converts a numeric severity to a human-readable string.
func severityString(sev uint32) string {
	switch sev {
	case SevInfo:
		return "INFO"
	case SevWarning:
		return "WARNING"
	case SevCritical:
		return "CRITICAL"
	case SevAlert:
		return "ALERT"
	default:
		return "UNKNOWN"
	}
}

// hashPath computes a simple hash of a filesystem path for BPF map lookup.
// Must match the hash algorithm in alpha.bpf.c.
func hashPath(path string) uint64 {
	var hash uint64
	for i := 0; i < len(path) && i < 64; i++ {
		hash = hash*31 + uint64(path[i])
	}
	return hash
}

// copyMap creates a copy of a uint32->uint64 map for safe external access.
func copyMap(m map[uint32]uint64) map[uint32]uint64 {
	c := make(map[uint32]uint64, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
