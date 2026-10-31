# Lab 6 — Splunk Enterprise and Universal Forwarder

<badge color="warning">Build guide — not yet lab-tested</badge>

This is a separate Splunk deployment. Use a supported x86-64 Windows or Linux server on the Windows PC. The Mac is an endpoint/admin client; do not assume Splunk Enterprise server is supported natively on Apple-silicon macOS.

## Mandatory prerequisites — complete before installing Splunk

Do not start this SIEM until Stages 0–7 in [Master Build Sequence](build-sequence.md) pass. Firewall syslog must be written by the Linux relay; Zeek/Suricata files must exist and be readable on the sensor; Windows Security/Sysmon and Linux source events must be proven locally. Follow [Telemetry Collection & Forwarding](telemetry-pipeline.md).

Use Splunk Universal Forwarder to monitor endpoint Event Log channels and relay/sensor files. Splunk's validated architecture guidance recommends a syslog receiver such as rsyslog/syslog-ng plus a forwarder, or Splunk Connect for Syslog; direct TCP/UDP syslog input to Splunk Enterprise is discouraged for production designs. Verify OS and architecture support for each forwarder host.

## 1. Architecture

Windows endpoint (Sysmon + Universal Forwarder) → TCP receiving port → Splunk Enterprise → Search & Reporting.

Use a dedicated VM. Do not run Splunk, Elastic, Wazuh and Security Onion together on a resource-constrained host.

## 2. Install Splunk Enterprise

1. Download the current Splunk Enterprise installer from Splunk's official download portal.
2. Check current supported OS, architecture, RAM, disk and licence terms.
3. Select a supported x86-64 platform from the current support matrix.
4. For Linux, follow Splunk's release-specific package installation instructions. A Debian package workflow is shown below; replace placeholders with the exact downloaded filename:

```bash
sudo dpkg -i splunk-<version>-<build>-linux-amd64.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
```

5. For Windows, run the signed MSI as Administrator and follow the installer. Record the actual install path.
6. Set a strong unique admin password and store it securely.
7. Confirm the service is running and open Splunk Web from MGMT only.

## 3. Enable receiving

In Splunk Web, go to Settings → Forwarding and receiving → Configure receiving → New Receiving Port. Configure TCP 9997 (or another explicitly selected port). Restrict inbound access to the endpoint subnet.

Verify on Linux:

```bash
sudo ss -lntp | grep 9997
```

On Windows:

```powershell
Get-NetTCPConnection -LocalPort 9997 -State Listen
```

Do not expose management port 8089 or Web port 8000 to untrusted networks.

## 4. Create a test index

Create an index named `windows_lab` under Settings → Indexes. Record its retention and storage policy. Use a disposable lab index, not production.

## 5. Install Universal Forwarder on Windows endpoint

1. Download the current Windows x64 Universal Forwarder MSI from Splunk.
2. Confirm compatibility with the Enterprise version.
3. Install on PSV-W11-01.
4. Configure the receiving Splunk host and port using the installer wizard or current Splunk CLI.
5. Configure the Sysmon Operational channel input. A starting stanza is:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows_lab
renderXml = 1
```

Confirm the channel name and stanza syntax against the current Universal Forwarder documentation. Do not assume the Splunk Add-on for Microsoft Windows or CIM field extractions are present.

6. Configure outputs.conf with the actual server address and port:

```ini
[tcpout]
defaultGroup = lab-indexer

[tcpout:lab-indexer]
server = 10.10.30.21:9997
```

7. Restart the forwarder using the supported service/CLI method and inspect its internal logs.

## 6. Verify ingestion

Search:

```spl
index=windows_lab earliest=-15m
| stats count by host sourcetype source
```

Then inspect Sysmon process events:

```spl
index=windows_lab EventCode=1
| table _time host Image CommandLine ParentImage ProcessGuid
| sort -_time
```

Field names vary with raw XML, add-ons and parsing. If EventCode or Image is absent, inspect raw events and adapt the query. A running forwarder service is not proof of ingestion.

## 7. Test the Phase 5 detection

Use the PowerShell encoded-command detection only after confirming the real field names. Run positive and negative test cases on the disposable endpoint. Record raw event, search result, field extraction and any benign positives. Do not use production indexes.

## 8. Troubleshooting

- Confirm the local Sysmon event exists.
- Check forwarder service status and internal logs.
- Confirm outputs.conf destination, port, DNS and firewall.
- Confirm Splunk receiving is enabled and the test index exists.
- Check index permissions and time range.
- Inspect raw XML before changing field names.
- Avoid duplicate collection of the same channel by multiple agents.

## 9. Licence note

Splunk licence and trial/free capabilities change. Check current terms from Splunk before downloading; do not assume an evaluation remains fully functional after expiry.

## References

- [Splunk Enterprise installation](https://docs.splunk.com/Documentation/Splunk/latest/Installation/InstallonLinux)
- [Universal Forwarder installation](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Installtheuniversalforwarder)
- [Windows Event Log inputs](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/MonitorWindowseventlogdata)
- [Enable a receiver](https://docs.splunk.com/Documentation/Splunk/latest/Forwarding/Enableareceiver)
- [Splunk syslog data collection architectures](https://help.splunk.com/en/data-management/splunk-validated-architectures/getting-data-in-forwarding-and-preprocessing/syslog-data-collection)
