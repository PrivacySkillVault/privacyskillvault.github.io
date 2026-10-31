# SIEM collector implementation — Elastic, Splunk and Wazuh

<badge color="warning">Stage 8 — configure only after all pre-SIEM source gates pass</badge>

This guide connects the already-proven local event sources and relay files to one selected SIEM. Do not install all three SIEMs at once. Pick one, configure one source at a time, prove raw event ingestion, then add the next source.

**Prerequisites:** [Master Build Sequence](build-sequence.md) Stages 0–7 pass; the [syslog relay](syslog-relay-implementation.md), [network sensor](network-sensor-implementation.md) and [endpoint telemetry](endpoint-telemetry-implementation.md) acceptance gates are complete.

## 1. Inventory before installing an agent

Create a source inventory:

| Host | Source | Local path/channel | Format | Expected identity |
|---|---|---|---|---|
| PSV-LOG01 | Firewall syslog | /var/log/remote/psv-opnsense.log | syslog text | source IP + hostname |
| PSV-LOG01 | Mac router syslog | /var/log/remote/psv-mac-router.log | syslog text | source IP + hostname |
| PSV-SENSOR01 | Zeek | active Zeek conn/dns logs | JSON if enabled | sensor hostname |
| PSV-SENSOR01 | Suricata | /var/log/suricata/eve.json | JSON lines | sensor hostname |
| PSV-W11-01 | Windows Security | Security event channel | Windows Event Log | endpoint hostname |
| PSV-W11-01 | Sysmon | Microsoft-Windows-Sysmon/Operational | Windows Event Log | endpoint hostname |
| Linux endpoint | audit/journal | auditd/journald | native source | endpoint hostname |
| Mac endpoint | Unified Logging | macOS ULS | native source | Mac hostname |

Actual file paths depend on the installed service configuration. Confirm paths with the source host before configuring a collector. Do not monitor an empty example directory.

## 2. Elastic — Fleet and Filestream

Use supported Elastic Stack/Agent versions and an OS/architecture listed in the current Elastic Support Matrix. Keep Elasticsearch, Kibana, Fleet Server and Elastic Agent on compatible release versions. Do not assume an Elastic Agent package for ARM64 implies every integration is supported on that OS.

### 2.1 Create policies

In Kibana:
1. Open Management → Fleet.
2. Confirm Fleet Server is healthy and its URL/certificate is reachable from the agent host.
3. Create separate policies for Windows endpoints, Linux relay/sensor and macOS endpoints where their integrations differ.
4. Use the generated enrollment command on each host; protect enrollment tokens.
5. Confirm the agent is enrolled and the policy is applied before adding integrations.

### 2.2 Linux relay and sensor files

For the Linux policy, add the **Custom Logs (Filestream)** integration. Configure paths for files that actually exist, for example:

~~~text
/var/log/remote/psv-*.log
/opt/zeek/logs/current/*.log
/var/log/suricata/eve.json
~~~

Use separate inputs/datasets where possible so source types remain distinguishable. Enable JSON decoding for Zeek and Suricata JSON lines using the integration's current JSON parser settings. Keep plain rsyslog text as plain text; do not force JSON decoding on it.

Ensure the Elastic Agent service account can read active and rotated files. Grant only group read access to the specific log directories. Do not make all logs world-readable. If logs rotate, test that the agent continues reading new files and does not re-ingest the entire file unexpectedly.

### 2.3 Windows endpoint

Add the Windows integration to the Windows endpoint policy. Enable Security event collection and the Sysmon Operational channel. Verify local events first. Do not assume Sysmon data is included just because the Windows integration is installed; inspect the integration's channel configuration and agent policy.

### 2.4 macOS endpoint

Check the exact macOS version and ARM64 support. Add the macOS Security Events integration only where supported. Grant only the documented permissions and validate the actual categories collected. Do not promise full Unified Logging visibility; macOS privacy and permissions affect what can be read.

### 2.5 Verify

In Discover:
1. Select the time range covering the test event.
2. Search the actual data stream and dataset created by the integration.
3. Open the raw document.
4. Verify @timestamp, host.name, event.dataset, source/destination fields and original message.
5. Compare event time with source and relay timestamps.
6. Record ingest delay and any duplicate event count.

Agent online or Fleet healthy is not proof of file ingestion. Check agent diagnostics and integration errors if no data arrives.

## 3. Splunk — Universal Forwarder

Use Splunk Enterprise on a supported x86-64 Windows/Linux server. Verify the Universal Forwarder OS/architecture matrix for each endpoint; do not assume Windows ARM or all macOS ARM versions are supported.

### 3.1 Configure the receiver

On Splunk Enterprise, enable receiving on TCP/9997 (or the chosen port) and create indexes such as:
- psv_windows
- psv_network
- psv_firewall

Create only indexes needed for the current exercise. Set retention and storage limits deliberately. Restrict TCP/9997 to approved forwarder hosts.

### 3.2 Linux Universal Forwarder — outputs.conf

On each Linux relay/sensor forwarder, configure the system-local outputs file (package path commonly /opt/splunkforwarder/etc/system/local/outputs.conf):

~~~ini
[tcpout]
defaultGroup = psv-indexers

[tcpout:psv-indexers]
server = 10.10.30.21:9997
~~~

Replace the address with the actual Splunk receiver. Protect the configuration directory and use Splunk's documented TLS options if the path is not fully isolated. Do not store cleartext passwords in config files.

### 3.3 Linux Universal Forwarder — inputs.conf

Create inputs in /opt/splunkforwarder/etc/system/local/inputs.conf after confirming the real paths:

~~~ini
[monitor:///var/log/remote/psv-opnsense.log]
disabled = 0
index = psv_firewall
sourcetype = psv:firewall:syslog

[monitor:///opt/zeek/logs/current/conn.log]
disabled = 0
index = psv_network
sourcetype = zeek:conn:json

[monitor:///opt/zeek/logs/current/dns.log]
disabled = 0
index = psv_network
sourcetype = zeek:dns:json

[monitor:///var/log/suricata/eve.json]
disabled = 0
index = psv_network
sourcetype = suricata:eve:json
~~~

Paths for Zeek change with package/deployment method; use the exact active directory. Configure one stanza per file/source if they need different sourcetypes. Check permissions and monitor checkpoints. Avoid monitoring both an original and a duplicate copy of the same file.

Restart using the installed forwarder's supported command:

~~~bash
sudo /opt/splunkforwarder/bin/splunk restart
sudo /opt/splunkforwarder/bin/splunk list forward-server
sudo /opt/splunkforwarder/bin/splunk list monitor
~~~

### 3.4 Windows Universal Forwarder — inputs.conf

Install the supported Windows x64 Universal Forwarder. Configure the receiving host through the installer wizard or outputs.conf. A starting Sysmon channel stanza is:

~~~ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = psv_windows
renderXml = 1

[WinEventLog://Security]
disabled = 0
index = psv_windows
renderXml = 1
~~~

Use the exact stanza syntax supported by the installed UF version. Security log access requires the correct service account privileges. Do not collect every Windows channel by default; select the channels needed for the exercise.

### 3.5 Verify Splunk

Start with:

~~~spl
index=psv_firewall earliest=-15m
| stats count by host source sourcetype

index=psv_network earliest=-15m
| stats count by host source sourcetype

index=psv_windows earliest=-15m
| stats count by host source sourcetype
~~~

Inspect raw events before writing field-dependent searches. JSON sourcetype names do not automatically guarantee correct JSON field extraction; configure and verify the appropriate search-time parsing. Confirm _time, host, source, sourcetype and event-specific fields.

## 4. Wazuh — agent Logcollector and custom files

Use a supported Wazuh server and agent version. Wazuh agent secure communications use the documented secure channel (TCP/1514 by default); enrollment normally uses TCP/1515. Verify the installed version and firewall port reference.

### 4.1 Linux relay and sensor agents

On the relay/sensor, back up /var/ossec/etc/ossec.conf. Add only the actual files that exist:

~~~xml
<localfile>
  <location>/var/log/remote/psv-opnsense.log</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/opt/zeek/logs/current/conn.log</location>
  <log_format>json</log_format>
</localfile>

<localfile>
  <location>/opt/zeek/logs/current/dns.log</location>
  <log_format>json</log_format>
</localfile>

<localfile>
  <location>/var/log/suricata/eve.json</location>
  <log_format>json</log_format>
</localfile>
~~~

Use syslog format for one-line syslog text and json for single-line JSON records. If the actual Zeek logs are not JSON, change the Zeek configuration or use a supported parser; do not label ASCII as JSON. Configure file permissions so the Wazuh agent can read the logs without granting world access.

Validate XML and restart the agent:

~~~bash
sudo apt install -y libxml2-utils
sudo xmllint --noout /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent --no-pager
sudo tail -n 100 /var/ossec/logs/ossec.log
~~~

If the installed version does not provide the same validation flag, consult that version's CLI help and validate using its documented method.

### 4.2 Windows agent

The Wazuh Windows agent collects standard Windows channels; configure Sysmon Operational explicitly if it is not already included by the selected policy. Back up the Windows agent configuration, add the correct EventChannel localfile block, restart the Wazuh service and verify agent logs.

~~~xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
~~~

### 4.3 macOS agent

Wazuh macOS uses Unified Logging. Configure the macOS localfile block as described in [Endpoint Telemetry Implementation](endpoint-telemetry-implementation.md). Verify that the exact query returns local events and that the manager receives them. macOS privacy controls may limit fields/categories.

### 4.4 Verify Wazuh ingestion

- Agent status is active and last keepalive is current.
- The raw test record is visible in the manager/dashboard.
- Decoder and rule behaviour are understood; an event may be ingested without triggering an alert.
- Hostname, timestamp, source file/channel and raw message are preserved.
- No source is collected twice unintentionally.

## 5. Source-by-source rollout order

Connect in this order and do not add the next source until the current one passes:
1. One relay firewall test event.
2. One OPNsense IDS/EVE event.
3. One Zeek DNS or connection event.
4. One Suricata EVE flow/alert event.
5. One Windows Security event.
6. One Sysmon process event.
7. One Linux audit/journal event.
8. One macOS Unified Logging event, if the Mac track is used.

For each, capture source event, collector log/offset, SIEM raw event, timestamp delta, host identity and parsing. Then run a positive and negative detection test.

## 6. Common troubleshooting

| Symptom | Check in order |
|---|---|
| Agent online, no data | Local source exists → path/channel configured → permissions → agent diagnostics → receiver/index/data stream |
| Only newest events | File input start position/offset, file rotation and retention |
| Duplicate events | Multiple agents, duplicate monitor stanzas, overlapping file paths, relay forwarding loops |
| Wrong hostname | Source host metadata vs relay hostname; preserve original sender in syslog template |
| Wrong timestamp | Source timestamp vs receive timestamp vs SIEM ingest time; check NTP and timezone |
| JSON not parsed | Confirm source is one JSON object per line; verify parser/sourcetype and raw message |
| Missing fields | Inspect raw event and installed integration/version; do not assume a field mapping |
| Disk/queue growth | Agent queue, receiver health, disk capacity, retention and backpressure |

## 7. Security and acceptance gate

- [ ] Only one SIEM stack selected.
- [ ] Agent/forwarder OS and architecture support verified.
- [ ] TLS and certificate trust configured for non-isolated paths.
- [ ] Credentials/enrollment tokens stored securely and not committed.
- [ ] Firewall permits only required agent-to-server ports.
- [ ] Collector reads only intended files/channels.
- [ ] Every source has a raw searchable event.
- [ ] Host, event time, source identity and original payload preserved.
- [ ] Ingest delay measured; duplicates and gaps checked.
- [ ] Retention, queueing, disk thresholds and agent health monitored.
- [ ] Positive/negative test evidence captured and sanitized.

## References

- [Elastic Custom Logs Filestream](https://www.elastic.co/docs/reference/integrations/filestream)
- [Elastic Windows integration](https://www.elastic.co/docs/reference/integrations/windows)
- [Elastic macOS Security Events](https://www.elastic.co/docs/reference/integrations/macos)
- [Splunk Universal Forwarder configuration files](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Configurationfiles)
- [Splunk monitor inputs](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Monitorfilesanddirectories)
- [Splunk Windows Event Log inputs](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/MonitorWindowseventlogdata)
- [Wazuh localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
- [Wazuh remote input configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html)
- [Wazuh required ports](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Elastic Support Matrix](https://www.elastic.co/support/matrix)
- [Splunk platform support](https://www.splunk.com/en_us/download/universal-forwarder.html)
