# Running the orchestrator daemon

The `ghost-ctl daemon` subcommand runs the long-lived GHOST-STACK CORE control plane. It is the process that systemd supervises as `ghost-orchestrator.service`. Use it whenever you want department spawn, quarantine, snapshot, hierarchy, or threat-response capabilities available on a host.

Before the daemon starts, `ghost-ctl self-check` runs as the unit's `ExecStartPre=` and verifies that the host is in a state where the daemon can safely come up.

---

## When to use this

- **`ghost-ctl self-check`** — Run after a fresh install, after upgrading the kernel, after rolling out new agent binaries, or any time the orchestrator fails to start and you need a precise reason. It exits with a deterministic code per failure mode so you can wire it into deployment automation.
- **`ghost-ctl daemon`** — Run only via systemd in production. Invoke it directly only when you are debugging on a developer host and want to attach to stderr.

The orchestrator must be running before `ghost-agent-alpha@.service` or `ghost-agent-beta.service` start — both units declare `BindsTo=ghost-orchestrator.service`.

---

## `ghost-ctl self-check`

`self-check` is a preflight that does not require the orchestrator to be running. It validates seven preconditions in order and exits on the first failure:

| Check | What it verifies | Exit code |
|---|---|---|
| Base path | `/var/lib/ghost-stack` exists and is a directory | `1` |
| Base path is writable | A temp file can be created in the base path | `2` |
| Alert socket dir | `/var/run/ghost-stack` can be created (mode `0700`) | `3` |
| BPF object dir | `/opt/ghost-stack/bpf` is a directory if present | `4` |
| Agent binaries | `/opt/ghost-stack/bin/agent-alpha` and `agent-beta` exist (warning only) | — |
| BPF kernel support | `/proc/sys/kernel/bpf_stats_enabled` exists (kernel ≥ 5.8) | `5` |
| Host tools | `ip`, `mount`, `umount` are on `$PATH` | `7` |
| Orchestrator key | `/etc/ghost-stack/orchestrator.ed25519` exists (warning only) | — |

Exit code `0` means all preconditions are satisfied. The daemon can be started.

### Run it manually

```bash
sudo ghost-ctl self-check
echo "exit=$?"
```

Typical successful output:

```
ghost-ctl: self-check: verifying preconditions...
ghost-ctl: self-check: all preconditions satisfied
exit=0
```

Typical failure output:

```
ghost-ctl: self-check: verifying preconditions...
self-check: required host tool "ip" not found in $PATH: ... — install with: apt-get install iproute2 mount
exit=7
```

Each failure message includes the remediation command, so a non-zero exit is enough information to fix the host.

### Use exit codes in automation

Because each precondition maps to a unique code, you can branch in deploy scripts without parsing stderr:

```bash
sudo ghost-ctl self-check
case $? in
  0) systemctl start ghost-orchestrator ;;
  1|2) echo "base path issue — fix /var/lib/ghost-stack" >&2; exit 1 ;;
  5)   echo "kernel too old — needs Linux ≥ 5.8" >&2; exit 1 ;;
  7)   apt-get install -y iproute2 mount ;;
  *)   echo "self-check failed — see journal" >&2; exit 1 ;;
esac
```

---

## `ghost-ctl daemon`

`daemon` initializes every subsystem the control plane needs, signals readiness to systemd, and then blocks until `SIGTERM` or `SIGINT`.

On start, the daemon:

1. Opens the SQLite state store at `/var/lib/ghost-stack/orchestrator.db`.
2. Rebuilds the in-memory department hierarchy from persisted state.
3. Loads (or generates) the orchestrator's Ed25519 key pair at `/etc/ghost-stack/orchestrator.ed25519`.
4. Starts the threat-response handler and binds the alert socket at `/var/run/ghost-stack/alert.sock`.
5. Sends `READY=1` over `NOTIFY_SOCKET` so systemd's `Type=notify` unit transitions to `active`.

On shutdown, the daemon stops the threat handler, writes a final `ORCHESTRATOR_STOP` audit entry, and flushes the state store. It does **not** tear down running department containers — those persist across orchestrator restarts.

### Start under systemd

The shipped unit handles everything:

```bash
sudo systemctl enable --now ghost-orchestrator.service
sudo systemctl status ghost-orchestrator.service
```

You should see `Active: active (running)` and a journal entry of `daemon: running (waiting for SIGTERM/SIGINT)`.

### Start manually for development

Run the daemon in the foreground when you want to see its stderr stream live:

```bash
sudo /usr/bin/ghost-ctl daemon
```

Send `Ctrl-C` to trigger a clean shutdown. The next start will recover department state from the SQLite store.

### Configuration

The daemon reads the same environment variables the systemd unit sets:

| Variable | Default | Description |
|---|---|---|
| `GHOST_LOG_LEVEL` | `info` | Daemon log verbosity. |
| `GHOST_AUDIT_PATH` | `/var/lib/ghost-stack/audit/audit.log` | Append-only audit log path. |
| `GHOST_ALERT_SOCKET` | `/var/run/ghost-stack/alert.sock` | Unix socket where Agent-Beta sends alerts. |

Override these with `systemctl edit ghost-orchestrator.service` rather than editing the shipped unit file directly.

---

## Verify the daemon is healthy

After start, confirm the control plane responds:

```bash
sudo ghost-ctl hierarchy show
sudo ghost-ctl audit-trail | tail -n 5
```

If `hierarchy show` returns the root tier and `audit-trail` shows an `ORCHESTRATOR_START` entry, the daemon is fully initialized and ready to accept signed commands.
