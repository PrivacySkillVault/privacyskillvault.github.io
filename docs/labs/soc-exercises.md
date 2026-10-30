# Lab 11 — SOC validation exercises and operational monitoring

<badge color="warning">Build guide — not yet lab-tested</badge>

This programme validates the full collection-to-investigation chain. Run each exercise in the SIEM currently powered on. Do not attempt to deploy every platform at once.

## 1. Define monitoring coverage

Create an asset inventory for the lab:

| Asset | Role | Telemetry source | Owner | Expected heartbeat |
|---|---|---|---|---|
| PSV-DC01 | AD DS/DNS | Windows Security, DNS | Lab admin | Agent/forwarder health |
| PSV-W11-01 | Windows endpoint | Sysmon, Security, PowerShell | Lab admin | Agent/forwarder health |
| Ubuntu endpoint | Linux endpoint | auditd, system logs, system metrics | Lab admin | Agent health |
| Kali | Assessment source | System/auth logs; test record | Lab admin | Optional |
| SIEM host | Log platform | Platform/service health | Lab admin | Service health |
| Sensor | Network monitoring | Zeek/Suricata/PCAP metadata | Lab admin | Sensor health |

For every source document event generation, collection, parsing, storage, searchability, alerting and retention. A green agent status does not prove all required event channels are collected.

## 2. Exercise A — Windows process creation

1. Confirm Sysmon Event ID 1 is generated locally.
2. Confirm the same event reaches Elastic or Splunk.
3. Compare host, image, command line, parent and process GUID fields.
4. Run the Phase 5 encoded PowerShell analytic's positive and negative tests on the disposable endpoint.
5. Confirm positive matches and negative no-match.
6. Record the raw event, query, rule version, alert, timestamps and collection delay.

Use only a harmless test command in your own VM. Do not execute downloaded payloads or real malware.

## 3. Exercise B — local Administrators group change

On a disposable Windows endpoint, create a synthetic local test user and add it to the local Administrators group only for the controlled exercise. Record the exact before/after membership and use an approved local admin session.

Verify the Windows Security log contains Event ID 4732 and the target group SID is S-1-5-32-544. Forward the event to the SIEM. Run the Phase 5 detection and confirm:
- Positive: target SID is the built-in Administrators SID.
- Negative: an event for another group (for example Users) does not match.
- Actor, member, target SID, host and time are parsed correctly.

Remove the test user from the group and delete the synthetic account. Confirm the cleanup event is also recorded. Do not run this on a production or personal daily-use machine.

## 4. Exercise C — Linux authentication and audit

1. Confirm auditd is installed and active on Ubuntu.
2. Generate a successful login to the test account and a failed login using a deliberately incorrect password.
3. Confirm source records exist in the journal/auth log and audit log where configured.
4. Forward the records to the selected SIEM.
5. Verify username, source, event time and result are parsed correctly.
6. Record whether the SIEM distinguishes failed authentication from successful login.

Do not brute-force accounts. A single controlled failed login is sufficient to validate collection.

## 5. Exercise D — network monitoring

1. Generate a DNS query from a lab endpoint to the lab DNS server.
2. Generate HTTP traffic to the Juice Shop target.
3. Confirm the sensor sees the traffic on the intended capture interface.
4. Confirm Zeek logs the expected connection/DNS metadata.
5. Confirm Suricata processes the packet and writes EVE output.
6. Correlate endpoint, DNS and sensor records using IP, time and other available identifiers.

If sensor packets are missing, check SPAN/mirroring, VLAN, NIC mapping, asymmetric routing, capture drops and time synchronisation before changing rules.

## 6. Exercise E — health and availability monitoring

Monitor:
- Agent/forwarder last-seen and policy state.
- SIEM node health, cluster status and disk watermarks.
- Indexing/ingest errors and queue/backpressure.
- CPU, RAM, swap, disk I/O latency and free storage.
- Sensor interface status, packet drops and capture throughput.
- Clock synchronisation and event ingestion delay.
- Backup/restore and snapshot status.

Set thresholds based on measured baseline and vendor guidance. Avoid arbitrary universal thresholds. Alert on loss of telemetry as well as security events.

## 7. Exercise F — investigation and case management

For one synthetic alert:
1. Create a case with unique lab case ID.
2. Preserve the raw source event and SIEM alert.
3. Build a UTC timeline retaining original timezone.
4. Correlate host, user, process GUID, session, IP and transaction-like test reference where relevant.
5. Record confirmed facts separately from hypotheses.
6. Document false-positive assessment, evidence gaps and decision.
7. Add remediation and retest evidence.
8. Close the case with reviewer and date.

Use the Phase 5 fraud/incident templates as structures, not as proof of regulatory compliance.

## 8. Evidence package

For each exercise save:
- Hardware and hypervisor details.
- VM settings and IP/network diagram.
- Exact OS and product versions.
- Relevant configuration (sanitised).
- Original local event and SIEM copy.
- Search/query and rule versions.
- Expected vs actual result.
- Timestamps and ingest latency.
- Troubleshooting and cleanup.
- Limitations and reviewer sign-off.

Use synthetic accounts and addresses. Do not upload production telemetry, customer records, internal hostnames or credentials to PSV.

## 9. Exit criteria

A lab is complete only when:
- Network isolation is proven.
- Source event generation is verified locally.
- SIEM ingestion and parsing are verified.
- Positive and negative tests pass.
- Alert context supports analyst triage.
- Telemetry-health gaps are documented.
- Cleanup is verified.
- The evidence package is reproducible by another person.

## References

- [Microsoft Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Elastic detection rule concepts](https://www.elastic.co/docs/solutions/security/detect-and-alert/detection-rule-concepts)
- [Splunk monitoring console](https://docs.splunk.com/Documentation/Splunk/latest/DMC/AbouttheMonitoringConsole)
- [Wazuh documentation](https://documentation.wazuh.com/current/)
- [Security Onion documentation](https://docs.securityonion.net/en/3/)
