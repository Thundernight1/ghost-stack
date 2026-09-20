// Command agent-beta is the host-side launcher for AGENT-BETA, the
// 4-layer threat correlator for GHOST-STACK CORE.
//
// AGENT-BETA consumes events from:
//   - Layer 1: nflog (nftables drop logs)
//   - Layer 2: eBPF perf_event_array (TC classifier events)
//   - Layer 3: XDP drop counters (allowlist misses)
//   - Layer 4: Linux audit / LSM
//
// The correlator profiles observed source IPs, accumulates a threat
// score, and when the score exceeds the configured threshold
// (default 80) emits a signed alert over the orchestrator's
// Unix domain socket. The orchestrator's threat response handler
// then removes the IP from the Layer 3 XDP allowlist, which causes
// the NIC-level XDP_DROP rule to take effect — "absolute silence."
//
// This binary is the entry point invoked by the
// `ghost-agent-beta.service` systemd unit. It does not implement
// any CLI surface — configuration comes from environment variables.
//
// Configuration (env vars):
//
//	GHOST_ALERT_SOCKET   Path to the orchestrator's alert socket.
//	                     Default: /var/run/ghost-stack/alert.sock
//	GHOST_L2_PERF_MAP    Pinned BPF perf_event_array path for L2.
//	                     Default: /sys/fs/bpf/ghost-stack/l2_events
//	GHOST_L3_DROP_MAP    Pinned BPF map path for L3 drop counters.
//	                     Default: /sys/fs/bpf/ghost-stack/l3_drops
//	GHOST_NFLOG_GROUP    NFLOG group ID for L1 events.
//	                     Default: 1
package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/ghost-stack/core/agents/beta"
)

func main() {
	cfg := beta.AgentBetaConfig{
		AlertSocketPath:  getenv("GHOST_ALERT_SOCKET", "/var/run/ghost-stack/alert.sock"),
		L2PerfMapPath:    getenv("GHOST_L2_PERF_MAP", "/sys/fs/bpf/ghost-stack/l2_events"),
		L3DropMapPath:    getenv("GHOST_L3_DROP_MAP", "/sys/fs/bpf/ghost-stack/l3_drops"),
		OrchestratorAddr: getenv("GHOST_ORCHESTRATOR", ""),
	}
	if g, err := strconv.Atoi(getenv("GHOST_NFLOG_GROUP", "1")); err == nil && g >= 0 && g <= 65535 {
		cfg.NflogGroup = uint16(g) // #nosec G115 -- range validated above
	}

	ab := beta.NewAgentBeta(cfg)

	// SIGTERM/SIGINT triggers an orderly stop: cancel the context,
	// wait for the layer goroutines to drain, close the alert conn.
	// The done channel is closed by the signal goroutine after Stop()
	// returns; main blocks on it so the program exits cleanly.
	doneCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		fmt.Fprintf(os.Stderr, "[AGENT-BETA] received %s — stopping\n", sig)
		ab.Stop()
		close(doneCh)
	}()

	fmt.Printf("[AGENT-BETA] starting (socket=%s l2=%s l3=%s nflog=%d)\n",
		cfg.AlertSocketPath, cfg.L2PerfMapPath, cfg.L3DropMapPath, cfg.NflogGroup)
	if err := ab.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[AGENT-BETA] start failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "[AGENT-BETA] correlator running, waiting for layer events")
	<-doneCh
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
