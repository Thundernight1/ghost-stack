// Command agent-alpha is the host-side launcher for AGENT-ALPHA, the
// strictly-passive eBPF observer for GHOST-STACK CORE.
//
// AGENT-ALPHA's design contract (see agents/alpha/observer.go package
// doc): zero write capability, read-only eBPF ring buffer consumer,
// events sent via Unix domain socket to the orchestrator's alert
// bus (/var/run/ghost-stack/alert.sock). It is mounted read-only
// inside department containers, but the host-side launcher runs as
// a systemd service against the *host* BPF context — it observes
// kernel events that escape any single container's view (process
// transitions, namespace boundaries, sensitive-path opens).
//
// This binary is the entry point invoked by the
// `ghost-agent-alpha@.service` systemd template unit (one instance
// per configured department, indexed by the @ argument). It does
// not implement any CLI surface — config comes from environment
// variables and a single optional positional arg (the DeptID).
//
// Configuration (env vars):
//   GHOST_ALERT_SOCKET  Path to the orchestrator's alert socket.
//                       Default: /var/run/ghost-stack/alert.sock
//   GHOST_BPF_OBJECT    Path to the compiled eBPF object.
//                       Default: /opt/ghost-stack/bpf/alpha.bpf.o
//   GHOST_DEPT_ID       Department ID to observe (matches the @ arg
//                       from the systemd unit). Default: 0
//   GHOST_PID_NS        Target PID namespace ID (0 = all). Default: 0
package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/ghost-stack/core/agents/alpha"
)

func main() {
	cfg := alpha.ObserverConfig{
		AlertSocketPath: getenv("GHOST_ALERT_SOCKET", "/var/run/ghost-stack/alert.sock"),
		BPFObjectPath:   getenv("GHOST_BPF_OBJECT", "/opt/ghost-stack/bpf/alpha.bpf.o"),
		DeptID:          getenvInt("GHOST_DEPT_ID", 0),
		TargetPIDNsID:   uint32(getenvInt("GHOST_PID_NS", 0)),
		// SensitivePaths defaults are populated by Observer.attachPrograms
		// if left nil (see populateSensitivePaths).
	}

	// Optional positional arg: dept ID, matching the systemd
	// template-unit's @ instance. Lets operators override the env.
	if len(os.Args) > 1 {
		if v, err := strconv.Atoi(os.Args[1]); err == nil {
			cfg.DeptID = v
		}
	}

	obs := alpha.NewObserver(cfg)

	// Install signal handlers so systemd's SIGTERM (or Ctrl-C in
	// development) triggers an orderly stop: detach BPF programs,
	// close ring buffer reader, close the alert socket connection.
	// The done channel is closed by the signal goroutine after Stop()
	// returns; main blocks on it so the program exits cleanly.
	doneCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		fmt.Fprintf(os.Stderr, "[AGENT-ALPHA] received %s — stopping\n", sig)
		obs.Stop()
		close(doneCh)
	}()

	fmt.Printf("[AGENT-ALPHA] starting (dept=%d pidns=%d socket=%s bpf=%s)\n",
		cfg.DeptID, cfg.TargetPIDNsID, cfg.AlertSocketPath, cfg.BPFObjectPath)
	if err := obs.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[AGENT-ALPHA] start failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "[AGENT-ALPHA] observer running, waiting for events")
	<-doneCh
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
