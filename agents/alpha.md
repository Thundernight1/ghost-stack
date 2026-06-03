# Agent-Alpha

Agent-Alpha is GHOST-STACK CORE's strictly-passive eBPF observer. It attaches read-only kernel probes — process execution, outbound connections, credential changes, namespace unshares, and sensitive file opens — and streams events to the orchestrator's alert socket. By verifier-enforced design it has zero write capability and cannot block kernel execution.

The host-side launcher is the `agent-alpha` binary, installed at `/opt/ghost-stack/bin/agent-alpha`. It is invoked by the `ghost-agent-alpha@.service` systemd template unit — one instance per department container.

---

## When to run it

Run one Agent-Alpha instance for every department whose kernel events you want correlated by the orchestrator. The template unit indexes instances by the department ID (`%i`):

```bash
sudo systemctl enable --now "ghost-agent-alpha@0.service"
sudo systemctl enable --now "ghost-agent-alpha@1.service"
sudo systemctl enable --now "ghost-agent-alpha@10.service"
```

Each instance attaches to the host BPF context but filters events to the configured department's PID namespace, so two departments running simultaneously will not see each other's process or connection events.

The agent must come up **after** `ghost-orchestrator.service` — the shipped unit declares `BindsTo=ghost-orchestrator.service` and `PartOf=ghost-orchestrator.service`, so stopping the orchestrator stops all Agent-Alpha instances automatically.

---

## Configuration

Agent-Alpha has no CLI flags. All configuration is environment-driven, with an optional positional argument for the department ID (used by the systemd template).

| Variable | Default | Description |
|---|---|---|
| `GHOST_ALERT_SOCKET` | `/var/run/ghost-stack/alert.sock` | Unix domain socket where the orchestrator accepts alerts. |
| `GHOST_BPF_OBJECT` | `/opt/ghost-stack/bpf/alpha.bpf.o` | Compiled eBPF object to load. |
| `GHOST_DEPT_ID` | `0` | Department ID this instance observes. Override with the first positional arg or the systemd `@` instance. |
| `GHOST_PID_NS` | `0` | Target PID namespace ID. `0` observes all namespaces. |

The shipped systemd template passes the department ID as the first positional argument, so `ghost-agent-alpha@5.service` runs `agent-alpha 5` and pins `GHOST_DEPT_ID=5`.

---

## Run it manually

For development or smoke testing, invoke the binary directly. Agent-Alpha requires `CAP_BPF` and `CAP_PERFMON` — the shipped unit grants exactly those and nothing else, but on a developer host you typically run it as root:

```bash
sudo GHOST_ALERT_SOCKET=/tmp/ghost-alert.sock \
     GHOST_BPF_OBJECT=./build/bpf/alpha.bpf.o \
     GHOST_DEPT_ID=0 \
     /opt/ghost-stack/bin/agent-alpha
```

On start, the agent prints its configuration on stdout:

```
[AGENT-ALPHA] starting (dept=0 pidns=0 socket=/tmp/ghost-alert.sock bpf=./build/bpf/alpha.bpf.o)
[AGENT-ALPHA] observer running, waiting for events
```

Send `SIGTERM` (or `Ctrl-C`) to stop. The agent detaches all BPF programs, closes the ring buffer reader, and closes the alert-socket connection before exiting.

---

## Verify it is observing

After Agent-Alpha is running, generate a kernel event inside the department and check the journal:

```bash
sudo nsenter -t "$(systemctl show -p MainPID --value ghost-dept-0)" -p -m -- /bin/true
sudo journalctl -u "ghost-agent-alpha@0" -n 20
```

You should see an event line for the `execve` of `/bin/true`. If the journal shows `start failed: ...` instead, the most common causes are a missing BPF object at `GHOST_BPF_OBJECT`, the orchestrator's alert socket not yet bound, or the kernel running below the required version. Run [`ghost-ctl self-check`](/operations/daemon) to narrow it down.
