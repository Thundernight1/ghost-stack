# Unquarantining a department

`ghost-ctl dept unquarantine` reverses a prior `dept quarantine` action: it thaws the department's cgroup and restores network connectivity for the container.

Use it when the cause of a quarantine has been investigated and the department is safe to bring back online — for example, after capturing a forensic snapshot, applying a configuration fix, or confirming that an alert was a false positive.

---

## When to use

Run `unquarantine` only after you have:

1. Captured a memory snapshot of the frozen department (`ghost-ctl dept snapshot <ID>`) if forensic evidence is required.
2. Reviewed the audit trail (`ghost-ctl audit-trail`) to confirm the trigger.
3. Verified the underlying threat has been mitigated.

The reverse operation does not roll back any state changes the orchestrator made during the freeze — it only restores process execution and network reachability.

---

## Usage

```bash
ghost-ctl dept unquarantine <DEPT_ID>
```

| Argument | Description |
|---|---|
| `DEPT_ID` | Numeric ID of the department to unquarantine. Must match an existing quarantined department. |

The command runs as two ordered steps:

1. **Thaw cgroup** — writes `0` to `/sys/fs/cgroup/ghost-stack/dept-<ID>/cgroup.freeze`, resuming every process in the department.
2. **Restore network** — flushes the `inet quarantine` nftables table inside the department's network namespace, allowing traffic to flow through the normal Layer 1–4 firewall path again.

---

## Example

```bash
$ sudo ./build/ghost-ctl dept unquarantine 100
[GHOST-CTL] ⚠ UNQUARANTINING department 100...
  Step 1: Thawing cgroup (cgroup.freeze = 0)
  Step 2: Removing drop-all nftables rules

[GHOST-CTL] ✓ Department 100 unquarantined — processes resumed, network restored
```

Every invocation appends a `DEPT_UNQUARANTINE` entry to the immutable audit trail:

```bash
$ sudo ./build/ghost-ctl audit-trail
  [2026-05-25 00:20:46] DEPT_QUARANTINE   dept=100 result=SUCCESS
  [2026-05-25 00:31:12] DEPT_UNQUARANTINE dept=100 result=SUCCESS
```

---

## Verifying the result

Confirm the cgroup is no longer frozen:

```bash
$ cat /sys/fs/cgroup/ghost-stack/dept-100/cgroup.freeze
0

$ cat /sys/fs/cgroup/ghost-stack/dept-100/cgroup.events
populated 1
frozen 0
```

Confirm the drop-all nftables table is gone from the department's network namespace:

```bash
$ sudo nsenter -t <DEPT_PID> -n nft list ruleset
# (no `table inet quarantine` block — restored to normal policy)
```

---

## Errors

| Message | Cause |
|---|---|
| `unquarantine failed: department <ID> not running` | The department was never spawned, or its in-memory state has not been recovered yet. Run `ghost-ctl dept status <ID>` first. |
| `unquarantine failed: department <ID> is not quarantined` | The cgroup is already in the thawed state — nothing to do. |
| `invalid dept ID: <value>` | The argument is not a positive integer. |
