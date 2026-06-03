# CLI help

`ghost-ctl` ships with built-in help menus at two levels: a top-level command summary and per-subcommand usage. Use them to discover available actions without leaving the shell or grep'ing source.

---

## Top-level help

Run `ghost-ctl` with no arguments, `help`, or `--help` to see every command, accepted RBAC tiers, and worked examples:

```bash
$ sudo ./build/ghost-ctl help

Usage: ghost-ctl <command> [args]

Commands:
  dept spawn <ID> <NAME> <TIER> [PARENT_ID]   Spawn a department container
  dept quarantine <ID>                          Quarantine a running dept (freeze+drop)
  dept unquarantine <ID>                        Reverse a prior quarantine (thaw+restore net)
  dept snapshot <ID>                            Capture department state snapshot
  dept status <ID>                              Show department status
  hierarchy show                                Display hierarchy tree
  audit-trail                                   View append-only audit log
  version                                       Show version
  help                                          Show this help

Tiers: ROOT | DIRECTOR | MANAGER | STAFF

Examples:
  ghost-ctl dept spawn 0 "Headquarters" ROOT
  ghost-ctl dept spawn 1 "Engineering" DIRECTOR 0
  ghost-ctl dept spawn 10 "Backend Team" MANAGER 1
  ghost-ctl dept spawn 100 "dev-alice" STAFF 10
  ghost-ctl dept quarantine 100
  ghost-ctl dept unquarantine 100
  ghost-ctl hierarchy show
```

The same banner prints automatically when you invoke an unknown command or omit required arguments, so any mistake during operations doubles as a discovery tool.

---

## Subcommand help

`dept spawn` accepts `-h` or `--help` for argument-level details:

```bash
$ sudo ./build/ghost-ctl dept spawn --help
Usage: ghost-ctl dept spawn <DEPT_ID> <NAME> <TIER> [PARENT_ID]

Spawn a new department container with its own cgroup, network,
mount, PID, UTS, IPC, user, cgroup, and time namespaces.

Arguments:
  DEPT_ID    Unique numeric ID for the department (0-99).
             0 is typically the ROOT department.
  NAME       Human-readable name; must match ^[a-zA-Z0-9_-]+$
             (letters, digits, underscore, hyphen; no spaces).
  TIER       Hierarchy tier — one of:
               ROOT     | DIRECTOR | MANAGER | STAFF
  PARENT_ID  Optional parent department ID (omit for ROOT).
```

Use this view to remind yourself of the department name validation rule (`^[a-zA-Z0-9_-]+$`) — spawn calls with whitespace or shell metacharacters fail before the orchestrator ever creates a namespace, so checking the regex up front saves a round trip.

---

## Discoverability tips

- Pipe `ghost-ctl help` into `grep` to find a command quickly: `ghost-ctl help | grep quarantine`.
- The top-level help is printed to stdout, so it's safe to capture in scripts or wrap with `less`.
- Help output never reads from or writes to `/var/lib/ghost-stack`, so it works on a fresh host before any state directory has been provisioned.
