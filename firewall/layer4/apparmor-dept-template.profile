# GHOST-STACK CORE — Layer 4: AppArmor Department Profile Template
#
# Applied INSIDE each department namespace via nsenter.
# This is a TEMPLATE — variables are substituted per-department:
#   {{DEPT_ID}}   — Department ID (0-99)
#   {{DEPT_NAME}} — Department name
#   {{SUBNET}}    — Department subnet CIDR
#   {{DNS_IP}}    — Internal DNS resolver IP
#   {{ORCH_IP}}   — Orchestrator control socket IP
#
# Enforces:
#   - Filesystem whitelist
#   - Capability deny list
#   - Network peer restriction (dept-specific subnet only)
#
# Load with: apparmor_parser -r /etc/apparmor.d/ghost-dept-{{DEPT_ID}}

#include <tunables/global>

profile ghost-dept-{{DEPT_ID}} flags=(attach_disconnected,mediate_deleted) {

    #include <abstractions/base>

    # === FILESYSTEM WHITELIST ===

    # Department root filesystem — read/write within department only.
    /ghost/dept-{{DEPT_ID}}/** rw,
    /ghost/dept-{{DEPT_ID}}/   r,

    # Read-only access to system libraries and binaries.
    /bin/**                    rix,
    /sbin/**                   rix,
    /usr/bin/**                rix,
    /usr/sbin/**               rix,
    /usr/lib/**                rm,
    /usr/lib64/**              rm,
    /lib/**                    rm,
    /lib64/**                  rm,

    # Read-only access to necessary system files.
    /etc/passwd                r,
    /etc/group                 r,
    /etc/hosts                 r,
    /etc/resolv.conf           r,
    /etc/nsswitch.conf         r,
    /etc/ld.so.cache           r,
    /etc/ld.so.conf            r,
    /etc/ld.so.conf.d/         r,
    /etc/ld.so.conf.d/**       r,
    /etc/localtime             r,
    /etc/ssl/certs/**          r,

    # /proc — restricted.
    /proc/                     r,
    /proc/self/**              r,
    /proc/sys/kernel/hostname  r,
    /proc/sys/net/**           r,
    /proc/meminfo              r,
    /proc/cpuinfo              r,
    /proc/stat                 r,
    /proc/uptime               r,
    /proc/loadavg              r,

    # DENY sensitive /proc paths.
    deny /proc/*/mem           rw,
    deny /proc/kcore           rw,
    deny /proc/kallsyms        r,
    deny /proc/modules         r,
    deny /proc/1/ns/**         r,       # Prevent namespace inspection.
    deny /proc/sys/kernel/core_pattern w,

    # /sys — minimal read-only.
    /sys/fs/cgroup/**          r,
    deny /sys/kernel/**        rw,
    deny /sys/firmware/**      rw,
    deny /sys/module/**        rw,

    # /dev — only necessary devices.
    /dev/null                  rw,
    /dev/zero                  r,
    /dev/urandom               r,
    /dev/random                r,
    /dev/pts/*                 rw,
    /dev/tty                   rw,
    /dev/console               rw,
    deny /dev/mem               rw,
    deny /dev/kmem              rw,
    deny /dev/port              rw,

    # Temporary directories.
    /tmp/**                    rw,
    /var/tmp/**                rw,
    /var/run/**                rw,
    /var/log/dept-{{DEPT_ID}}/** rw,

    # AGENT-ALPHA binary — mounted read-only from host.
    /opt/ghost-agent/alpha     rix,
    # Alert socket — write only (for sending events).
    /var/run/ghost-alert.sock  w,

    # Database files — department-specific directory only.
    /var/lib/ghost-db/dept-{{DEPT_ID}}/** rw,

    # DENY cross-department access — cryptographically impossible
    # but also policy-enforced as defense in depth.
    deny /ghost/dept-[!{{DEPT_ID}}]**   rw,
    deny /var/lib/ghost-db/dept-[!{{DEPT_ID}}]** rw,

    # === CAPABILITY DENY LIST ===
    # Deny dangerous capabilities that could enable container escape.

    deny capability sys_admin,
    deny capability sys_ptrace,
    deny capability sys_module,
    deny capability sys_rawio,
    deny capability sys_boot,
    deny capability sys_time,
    deny capability sys_resource,
    deny capability mknod,
    deny capability net_admin,
    deny capability net_raw,
    deny capability mac_admin,
    deny capability mac_override,
    deny capability syslog,
    deny capability audit_control,
    deny capability audit_write,

    # Allow only minimal capabilities.
    capability dac_override,
    capability fowner,
    capability setuid,
    capability setgid,
    capability chown,
    capability kill,

    # === NETWORK PEER RESTRICTION ===
    # Only allow communication within department subnet and to
    # internal DNS + orchestrator.

    network inet stream,
    network inet dgram,
    network inet6 stream,
    network inet6 dgram,
    network unix stream,
    network unix dgram,

    # DENY raw sockets — prevents packet sniffing/injection.
    deny network raw,
    deny network packet,

    # === MOUNT RESTRICTION ===
    # Prevent any mount operations inside the container.
    deny mount,
    deny umount,
    deny pivot_root,

    # === SIGNAL RESTRICTION ===
    signal (receive) set=(kill, term, int, hup) peer=ghost-orchestrator,
    signal (send) set=(kill, term) peer=ghost-dept-{{DEPT_ID}},

    # === PTRACE RESTRICTION ===
    # Prevent debugging/tracing — blocks exploitation tools.
    deny ptrace,

    # === DBUS RESTRICTION ===
    deny dbus,
}
