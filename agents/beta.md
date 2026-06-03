# Agent-Beta

Agent-Beta is GHOST-STACK CORE's 4-layer threat correlator. It reads events from all four firewall layers concurrently, profiles each observed source IP, accumulates a threat score, and — when the score crosses the configured threshold — emits a signed alert to the orchestrator. The orchestrator then removes the offending IP from the Layer 3 XDP allowlist, producing the "absolute silence" drop at the NIC.

The host-side launcher is the `agent-beta` binary, installed at `/opt/ghost-stack/bin/agent-beta`. It is invoked by the `ghost-agent-beta.service` systemd unit. One instance runs per host.

---

## When to run it

Run Agent-Beta on every host where you want the **Observe → Profile → Silent Block** loop closed. Without Agent-Beta, the Layer 3 XDP allowlist still drops traffic, but new attacker IPs are never added to the drop list automatically — operators have to issue signed `allowlist remove` commands by hand.

Start it after the orchestrator, after the firewall is deployed, and after the L2/L3 BPF maps are pinned at the expected paths:

```bash
sudo bash deploy/firewall_deploy.sh
sudo systemctl enable --now ghost-orchestrator.service
sudo systemctl enable --now ghost-agent-beta.service
```

The shipped unit declares `BindsTo=ghost-orchestrator.service`, so stopping the orchestrator stops Agent-Beta automatically.

---

## What it reads

Agent-Beta runs four goroutines, each consuming one feed:

| Layer | Source | Default path / ID |
|---|---|---|
| L1 | NFLOG netlink socket | group `1` |
| L2 | Pinned BPF `perf_event_array` | `/sys/fs/bpf/ghost-stack/l2_events` |
| L3 | Pinned BPF drop-counter map (polled every 500 ms) | `/sys/fs/bpf/ghost-stack/l3_drops` |
| L4 | Linux audit / LSM netlink | system default |

If any feed is unavailable at start, Agent-Beta exits with a non-zero status — confirm the firewall deploy step ran first.

---

## Configuration

Agent-Beta has no CLI flags. All configuration is environment-driven.

| Variable | Default | Description |
|---|---|---|
| `GHOST_ALERT_SOCKET` | `/var/run/ghost-stack/alert.sock` | Unix socket where signed alerts are sent. Must match the orchestrator's bind path. |
| `GHOST_L2_PERF_MAP` | `/sys/fs/bpf/ghost-stack/l2_events` | Pinned BPF perf-event array for L2 events. |
| `GHOST_L3_DROP_MAP` | `/sys/fs/bpf/ghost-stack/l3_drops` | Pinned BPF map for L3 drop counters. |
| `GHOST_NFLOG_GROUP` | `1` | NFLOG group ID the L1 nftables rules log to. |
| `GHOST_ORCHESTRATOR` | _(unset)_ | Optional explicit orchestrator address. Leave blank to use `GHOST_ALERT_SOCKET`. |

The default threat-score threshold (`80`) and the auto-block policy live on the orchestrator side — see [Threat response](/operations/threat-response).

---

## Run it manually

```bash
sudo GHOST_ALERT_SOCKET=/var/run/ghost-stack/alert.sock \
     GHOST_NFLOG_GROUP=1 \
     /opt/ghost-stack/bin/agent-beta
```

On start, the agent prints its configuration:

```
[AGENT-BETA] starting (socket=/var/run/ghost-stack/alert.sock l2=/sys/fs/bpf/ghost-stack/l2_events l3=/sys/fs/bpf/ghost-stack/l3_drops nflog=1)
[AGENT-BETA] correlator running, waiting for layer events
```

Send `SIGTERM` (or `Ctrl-C`) to stop. The agent cancels the layer-reader context, waits for the four goroutines to drain, and closes the alert connection before exiting.

---

## Verify the correlator is alive

After Agent-Beta is running, watch its journal:

```bash
sudo journalctl -u ghost-agent-beta -f
```

Then, from a non-allowlisted IP, run a port scan against the host. Within a few seconds you should see L3 drop counters increase and — once the threat score crosses the threshold — a `THREAT_ACTOR_PROFILED` alert event in the orchestrator's journal. The [`audit-trail`](/operations/daemon) command on the orchestrator should then show an `ALLOWLIST_REMOVE` entry for the scanner IP.

If you see `start failed: cannot open pinned map ...`, the firewall layers were not deployed. Run `sudo bash deploy/firewall_deploy.sh` first and confirm the paths exist with `ls /sys/fs/bpf/ghost-stack/`.
