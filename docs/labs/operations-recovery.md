# Lab — operations, backup and recovery

<badge color="warning">Stage 13 — operational readiness; validate on the running lab</badge>

This runbook covers the maintenance and recovery work after the core lab is operational. It does not make a single-node home lab highly available. Follow the [Enterprise Dual-SIEM VM Lab Runbook](enterprise-dual-siem-vm-lab.md) and [Master Build Sequence](build-sequence.md).

## 1. Configuration inventory

Keep a private, current inventory of:
- Hypervisor, host OS/build and versions.
- VM name, guest OS/build/architecture, vCPU, RAM, disk, NICs and snapshot reference.
- Virtual switch/network name, adapter MAC, IP, subnet, gateway and DNS.
- Firewall interface mapping, rules and rule purpose.
- Product/agent versions, service ports, certificate expiry and data paths.
- Log sources, datasets/indexes, retention and storage budgets.
- Backup location, encryption, last successful backup and last restore test.

Never put passwords, API tokens, enrollment tokens, private keys, customer data or employer logs in the public PSV repository.

## 2. Backup and restore matrix

| System | Protect | Restore validation |
|---|---|---|
| OPNsense | Encrypted configuration export | Restore to an isolated test firewall; verify interfaces, gateways and rules |
| Active Directory | Supported System State backup and recovery documentation | Test the documented recovery procedure in an isolated environment |
| Elasticsearch | Snapshot repository, relevant configuration and certificates | Restore a test snapshot/index and verify documents |
| Splunk | Configuration and index data using the selected deployment's supported backup method | Restore a sample configuration/data set into a test instance |
| Vector | Config, transforms, service settings and required certificates | Run the installed Vector CLI validation against restored config |
| Zeek/Suricata | Config, custom rules, ruleset version and selected PCAP evidence | Validate/reload rules and replay a known PCAP |
| Endpoints | VM configuration and clean baseline snapshots | Restore a clone and confirm expected identity/agent re-enrollment behavior |

A VM snapshot is useful for rollback but is not an independent backup. Keep at least one protected copy outside the VM's virtual disk. Encrypt backups containing secrets or sensitive telemetry.

## 3. Retention and storage limits

For Elasticsearch, Splunk, Vector buffers, Zeek logs, Suricata EVE JSON and PCAP:
1. Assign a maximum storage budget to each data path.
2. Set retention to match the learning objective and available capacity.
3. Configure the product's supported lifecycle/retention policy for the pinned version.
4. Configure log rotation and verify the service reopens rotated files.
5. Monitor guest filesystem usage and host free space.
6. Test behavior when a destination is unavailable and when disk capacity is low.

Do not use unbounded queues or unlimited packet capture. Preserve free space for OS updates, recovery and filesystem operations.

## 4. Routine health checks

- **Hypervisor:** unexpected VM stops/restarts, host memory pressure and datastore/free-space status.
- **OPNsense:** interface/link state, DHCP/DNS, rule counters and firewall logs.
- **AD DS/DNS:** DNS resolution, authentication, time synchronization and relevant directory service health.
- **Elastic:** cluster health, disk watermarks, ingest errors, Fleet agent status and snapshot status.
- **Splunk:** service health, receiving/HEC availability, indexing queues, disk usage and license status.
- **Vector:** service state, component errors, retry/buffer metrics and buffer disk use.
- **Zeek/Suricata:** capture counters, service state, log freshness and rule update status.
- **Endpoints:** agent/forwarder service health and last-seen timestamps.
- **End-to-end:** generate a known synthetic event and verify it is searchable in both SIEMs.

Example Linux checks (adapt service names to the installed guest):

    systemctl --failed
    systemctl status vector
    df -h
    timedatectl
    journalctl -u vector --since "1 hour ago"

## 5. Recovery exercises

Perform tests on isolated clones or after verifying backups:
1. Restore OPNsense configuration and confirm segmentation still blocks prohibited paths.
2. Restore Vector configuration; validate it before restarting the service.
3. Stop one SIEM, observe bounded retry/buffering, restart it and verify delivery/recovery.
4. Restore a small Elasticsearch snapshot and confirm expected documents and timestamps.
5. Restore Splunk configuration/sample data and verify searches.
6. Restore a cloned endpoint and confirm it does not create an unintended duplicate agent identity.
7. Reboot the host and confirm required VM startup order, DNS and time dependencies.

Record recovery time, the last recoverable data point, data loss (if any), errors and corrective actions. Do not label a recovery successful until the service and restored data are checked.

## 6. Change and evidence management

For each update record the date, reason, affected VM/service, previous and new versions, backup/snapshot reference, rollback steps, test performed, expected/actual result and impact on ingestion/detections.

Use synthetic lab data only. Sanitize screenshots and exports. Never publish secrets, private keys, enrollment tokens, customer information or employer telemetry.

## 7. Stage 13 acceptance gate

Stage 13 is complete only when:
- The VM/service inventory is current.
- Independent backups exist for critical systems.
- Restore procedures have been tested for critical configurations/data.
- Retention and disk limits are configured and monitored.
- Health checks cover firewall, AD, broker, both SIEMs, endpoints and sensor.
- A SIEM outage/recovery exercise is recorded.
- Evidence is sanitized and rollback steps are usable.

A running service is not proof of healthy ingestion, a snapshot is not a backup, and a green dashboard is not proof of recoverability.
