# Audit log rotation

The orchestrator writes every state change to an append-only audit trail at `/var/lib/ghost-stack/audit/audit.log`. Left unmanaged, this file grows indefinitely. `deploy/deploy.sh` installs a `logrotate` configuration that bounds its disk footprint while preserving forensic continuity.

You don't need to call rotation manually — `logrotate.timer` (or the daily `cron.daily` job, depending on distribution) runs it automatically once the configuration is in place.

---

## What gets installed

Running `sudo bash deploy/deploy.sh` writes `/etc/logrotate.d/ghost-stack` with the following policy:

```conf
/var/lib/ghost-stack/audit/*.log {
    weekly
    size 100M
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 0640 root root
    dateext
    dateformat -%Y%m%d-%s
    sharedscripts
}
```

| Directive | Effect |
|---|---|
| `weekly` + `size 100M` | Rotates whichever comes first: a full week of activity or 100 MB of growth. |
| `rotate 12` | Keeps 12 historical archives (≈3 months of weekly rotations). |
| `compress` / `delaycompress` | gzip-compresses archives one rotation after they're produced, so the previous log remains readable in plain text. |
| `copytruncate` | Copies and truncates the live file in place — never renames it. This is required because the orchestrator's threat-response goroutine holds a long-lived append handle; a rename would leave it writing to a deleted inode. |
| `create 0640 root root` | Recreates the empty file with mode `0640` so reading is limited to root and the `ghost-stack` group. |
| `dateext` + `dateformat -%Y%m%d-%s` | Names archives like `audit.log-20260520-1716163200.gz` for deterministic, sortable forensic ordering. |

---

## Verifying rotation

After deployment, confirm the policy is registered:

```bash
$ sudo logrotate --debug /etc/logrotate.d/ghost-stack
reading config file /etc/logrotate.d/ghost-stack
Handling 1 logs
...
considering log /var/lib/ghost-stack/audit/audit.log
```

Force a rotation immediately (useful for testing, do not run routinely):

```bash
sudo logrotate --force /etc/logrotate.d/ghost-stack
ls -lh /var/lib/ghost-stack/audit/
```

Expected result: the live `audit.log` is truncated to size 0 and a timestamped archive sits alongside it.

---

## Adjusting retention

If you need longer-term retention for compliance, edit `deploy/deploy.sh` before running it (search for `Step 7b`) and increase `rotate 12` to your required archive count. Re-running the deploy script overwrites `/etc/logrotate.d/ghost-stack`, so manual edits to that file are lost on the next deploy — always change the source.

To ship archives off-host for long-term storage, add a `postrotate` hook in the same block. Example:

```conf
postrotate
    /usr/local/bin/ship-audit-archive.sh /var/lib/ghost-stack/audit/
endscript
```

---

## Why `copytruncate` matters

Standard `logrotate` policies use `create` mode: the old file is renamed to `audit.log.1` and a fresh `audit.log` is created. Any process holding an open file descriptor on the original keeps writing to the now-renamed file.

`ghost-ctl`'s `appendAudit` is invoked from the threat-response handler goroutine, which retains an `O_APPEND` handle for the lifetime of the orchestrator. Renaming would silently divert audit entries into the rotated archive while the new `audit.log` stays empty — a forensic gap that defeats the point of the append-only trail. `copytruncate` avoids this by truncating the existing inode in place.
