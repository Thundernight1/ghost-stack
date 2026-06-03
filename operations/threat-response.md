# Threat response

The threat-response handler is the bridge between Agent-Beta's behavioral correlator and the Layer 3 XDP allowlist. It closes the **Observe → Profile → Silent Block** loop: when a source IP accumulates enough suspicious behavior, the orchestrator removes it from the allowlist and the kernel begins dropping its packets silently at the NIC.

The handler runs in-process inside `ghost-ctl daemon` — there is no separate binary or unit. It starts automatically with the orchestrator and stops cleanly on `SIGTERM`.

---

## When this applies to you

You get auto-blocking for free as soon as both of these are running on the same host:

1. The orchestrator (`ghost-orchestrator.service`) — which hosts the threat-response handler.
2. Agent-Beta (`ghost-agent-beta.service`) — which emits the alerts.

If you only run the orchestrator, the alert socket is up but nothing writes to it: the L3 allowlist is managed only by operator-issued signed commands. If you only run Agent-Beta, alerts pile up against a closed socket and the agent exits.

You may want to adjust the default policy when:

- You are running a noisy benchmark or pen-test from a known-good IP and want to suppress auto-blocks.
- You want stricter (lower-threshold) blocking on internet-facing edge hosts.
- You want to disable the L2-hit requirement on hosts where Layer 2 deception is not deployed.

---

## How it works

```
AGENT-BETA  ──►  /var/run/ghost-stack/alert.sock  ──►  ThreatResponseHandler
                                                                │
                                                                ▼
                                              Ed25519-signed allowlist_remove
                                                                │
                                                                ▼
                                            Layer 3 XDP LPM trie (BPF map)
                                                                │
                                                                ▼
                                                       XDP_DROP at the NIC
```

1. Agent-Beta computes a `threat_score` per source IP from L1–L4 events.
2. When the score exceeds the threshold (default `80`), Agent-Beta sends a `THREAT_ACTOR_PROFILED` alert in the `BETA:<len>:{json}` framing over the Unix domain socket.
3. The handler validates the alert, optionally requires at least one Layer 2 hit, and dispatches to `blockIP`.
4. `blockIP` creates an Ed25519-signed `allowlist_remove` op and submits it to `AllowlistManager`.
5. The XDP LPM-trie entry is deleted in kernel space. Subsequent packets from the IP hit the default `XDP_DROP` and disappear with no RST and no ICMP.
6. An `ALLOWLIST_REMOVE` audit entry is appended to `/var/lib/ghost-stack/audit/audit.log`.

`L4_VIOLATION` alerts skip the threshold check and block immediately — AppArmor or namespace-iptables denials are treated as ground truth.

---

## Default policy

The orchestrator wires the handler with these defaults when it initializes:

| Field | Default | Effect |
|---|---|---|
| `AlertSocketPath` | `/var/run/ghost-stack/alert.sock` | Unix socket bound at `0660`, group `ghost-agent`. |
| `ThreatScoreThreshold` | `80` | `THREAT_ACTOR_PROFILED` alerts below this score are ignored. |
| `RequireL2Hits` | `true` | At least one Layer 2 deception hit must be present in `details.l2_hits`. |

Only alerts of type `THREAT_ACTOR_PROFILED` and `L4_VIOLATION` produce blocks. Everything else is informational and is logged but not acted on.

---

## Verify the loop end-to-end

After the daemon and Agent-Beta are both running:

```bash
# 1. Confirm the alert socket is bound.
sudo ls -l /var/run/ghost-stack/alert.sock

# 2. Tail the audit trail.
sudo ghost-ctl audit-trail | tail -n 0 -f &

# 3. From a non-allowlisted IP, run a probe that triggers L1 + L2.
nmap -sS -p1-1000 <host>

# 4. Within a few seconds, expect an ALLOWLIST_REMOVE entry.
```

Subsequent traffic from the probing IP will hit `XDP_DROP` before reaching the kernel network stack. From the attacker's perspective, the host appears offline. From the operator's perspective, the audit trail records the exact alert that caused the block, including the threat score, TTPs, and detected tools.

---

## Tune or disable auto-blocking

The defaults are hard-wired in `cmdDaemon`'s initializer. To change them today you need to override the values in code and rebuild. Two common changes:

- **Raise the threshold** to reduce false positives — set `ThreatScoreThreshold` to `100` or higher for hosts in noisy networks.
- **Drop the L2 requirement** for hosts that don't deploy Layer 2 — set `RequireL2Hits: false` so alerts based on L1 nflog or L4 LSM hits alone still block.

A future release will expose these via environment variables on `ghost-orchestrator.service`. Until then, restart the orchestrator after any rebuild:

```bash
sudo systemctl restart ghost-orchestrator.service
sudo journalctl -u ghost-orchestrator -n 20 | grep THREAT-RESPONSE
```

On a successful restart you should see:

```
[THREAT-RESPONSE] Listening on /var/run/ghost-stack/alert.sock (threshold: score > 80)
```

To disable auto-blocking entirely, stop Agent-Beta:

```bash
sudo systemctl stop ghost-agent-beta.service
```

The orchestrator stays up and the L3 allowlist still drops non-allowlisted traffic — only the auto-block edges are removed.
