# Lab — Telemetry collection and forwarding pipeline

<badge color="warning">Mandatory pre-SIEM stage — reference guide, not yet hardware-tested</badge>

This stage creates and proves the data path before installing Elastic, Splunk or Wazuh. The SIEM is the destination, not the source of firewall, endpoint or network telemetry.

## 1. Required source-to-destination map

| Source | Prove locally first | Collection/forwarding path |
|---|---|---|
| OPNsense firewall rules | Live log/filter log | Remote syslog → Linux relay → source-specific file → SIEM collector |
| OPNsense Suricata IDS | IDS alerts/EVE output | EVE/syslog → relay |
| Mac nftables router | journald firewall message | rsyslog file → SIEM collector |
| Windows Security/Sysmon | Event Viewer channels | Elastic Agent, Splunk UF or Wazuh agent |
| Linux auditd/journald | Local audit/journal | Elastic Agent, Splunk UF or Wazuh agent |
| Zeek | conn.log/dns.log | JSON files → collector/agent on sensor |
| Sensor Suricata | eve.json | JSON file → collector/agent on sensor |

Do not install competing agents to collect the same source unless duplicate ingestion is intentional.

## 2. Create a Linux syslog relay

On Windows track create PSV-LOG01 on SERVER, for example 10.10.30.30/24. On Mac track use an ARM64 Ubuntu Server VM on SERVER. Configure static/reserved addressing, correct DNS/NTP and restricted management.

Install the distribution-supported rsyslog package. Configure it to receive syslog only on the lab-facing interface and only from known firewall/router source addresses. Prefer TCP for an isolated lab; use TLS when logs cross a network you do not fully trust. Do not expose the listener to home LAN or Internet.

Write separate source files for firewall system events, firewall filter events and IDS alerts. Configure rotation, disk limits and read permissions for the later collector account. Preserve source identity and timestamps. Use the exact rsyslog input/template syntax for the installed distribution version and test before enabling the listener.

Verify listener:

    sudo ss -lntup

Do not proceed until a test syslog message arrives from an allowed source and is written to the expected file.

## 3. Configure OPNsense remote logging

In OPNsense open System → Settings → Logging → Remote:

1. Add and enable a destination.
2. Select the same transport configured on the relay (TCP or TLS preferred where supported).
3. Set the relay address, such as 10.10.30.30, and the configured port.
4. Select firewall/system applications and Suricata events needed for the exercise.
5. Save and Apply.
6. For TLS, configure and validate certificates and hostname trust on both ends.

Enable the Log option on the individual firewall rules whose pass/block decisions must be investigated. Rule logging is not automatically enabled for every rule. For IDS, enable EVE syslog output and configure a remote target for Suricata.

Generate one allowed and one blocked test flow. Confirm the relay receives both with source, timestamp, interface/rule context and action preserved.

## 4. Mac router logging

For the nftables router, first prove firewall messages appear locally in journald. Configure rsyslog to write only the unique nftables log prefix/facility to a dedicated file. Then configure rsyslog to forward those records to the SERVER relay over the restricted TCP/TLS transport configured for the lab; retain a local copy for troubleshooting. Alternatively, collect the local file with a supported agent after the SIEM is installed. nftables does not automatically forward logs remotely. Do not assume an Elastic, Splunk or Wazuh agent supports the exact ARM64 OS/release until its support matrix confirms it.

## 5. Prepare Zeek and Suricata files

On the sensor, prove the files exist before adding a collector:
- Zeek JSON logs such as conn.log and dns.log.
- Suricata eve.json.
- Correct owner/group and read permissions.
- Log rotation and retention.
- Sensor hostname, interface and capture scope recorded.

Zeek supports JSON log output; Suricata EVE writes JSON events. Do not send full PCAP as routine SIEM events; PCAP needs separate access, storage and retention controls.

## 6. Pre-SIEM acceptance gate — source and relay only

Verify:
1. Firewall test event appears in the relay file.
2. Suricata IDS alert appears in local EVE/syslog and, where configured, the relay output.
3. Zeek DNS/connection event appears in its local JSON file if Zeek is enabled.
4. Windows Sysmon/Security event exists locally.
5. Linux audit/journal event exists locally.
6. macOS Unified Logging or Mac-router nftables event exists locally when that track is used.
7. Hostname, source timestamp and event identity are preserved.
8. Relay and sensor files have rotation, bounded disk use and correct collector read permissions.

This gate proves source generation and pre-SIEM relay only. It does not claim SIEM ingestion. SIEM-specific agents/forwarders and end-to-end searches are configured after the selected SIEM server is ready.

## 7. SIEM-specific collector pattern

**Elastic:** install Elastic Agent on relay and sensor. Use Custom Logs (Filestream) for written rsyslog, Zeek and Suricata files. Use Windows and System integrations for endpoint sources. A TCP/UDP integration is a separate listener design; do not assume Fleet being online means syslog is ingested.

**Splunk:** use Universal Forwarder on relay and sensor to monitor written files, and a Windows Universal Forwarder for Event Log channels. Splunk's validated architecture guidance recommends a syslog receiver such as rsyslog/syslog-ng plus a forwarder, or Splunk Connect for Syslog, rather than direct UDP/TCP input on Splunk Enterprise as the default production pattern. Verify every forwarder host architecture.

**Wazuh:** install Wazuh agents on endpoints, relay and sensor. Configure Logcollector to monitor firewall and sensor files. Current Wazuh documentation notes that Wazuh 5.0 removes the manager's direct syslog listener; relay-file-plus-agent avoids depending on direct listener support across versions. Check the exact release documentation.

## 8. Network policy

Permit only:
- Firewall/router source addresses → relay listener port.
- Relay/sensor/endpoint agents → selected SIEM documented ports.
- Admin workstation → management UIs/SSH/RDP as required.

Do not open every common SIEM port on every segment. Use the installed release's port reference, source allowlists, TLS and host firewall policy. Keep management ports off WAN.

## 9. Troubleshoot from source to destination

1. Did the source generate the event locally?
2. Is it configured to export/forward?
3. Does the packet reach the relay? Check listener, route, firewall and packet capture.
4. Does the relay write the expected file? Check rsyslog, permissions and disk.
5. Can the collector read the file? Check agent logs and offsets.
6. Does the SIEM accept it? Check receiver, parsing, index/data stream and time range.
7. Are fields parsed correctly? Inspect raw event before changing queries.

## References

- [OPNsense remote logging](https://docs.opnsense.org/manual/settingsmenu.html)
- [OPNsense IDS/IPS and EVE syslog](https://docs.opnsense.org/manual/ips.html)
- [Elastic Custom Logs Filestream](https://www.elastic.co/docs/reference/integrations/filestream/)
- [Elastic Custom TCP Logs](https://www.elastic.co/docs/reference/integrations/tcp/)
- [Elastic Custom UDP Logs](https://www.elastic.co/docs/reference/integrations/udp/)
- [Splunk syslog collection architectures](https://help.splunk.com/en/data-management/splunk-validated-architectures/getting-data-in-forwarding-and-preprocessing/syslog-data-collection)
- [Wazuh log collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html)
- [Wazuh monitoring log files](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html)
- [Zeek JSON logs](https://docs.zeek.org/en/current/tutorial/logs.html)
- [Suricata EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
