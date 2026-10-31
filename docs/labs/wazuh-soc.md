# Lab 7 — Wazuh all-in-one SOC stack

<badge color="warning">Build guide — not yet lab-tested</badge>

The all-in-one Wazuh deployment places manager, indexer and dashboard on one Linux host for learning. It is not a highly available production architecture.

## Mandatory prerequisites — complete before installing Wazuh

Do not start this SIEM until Stages 0–7 in [Master Build Sequence](build-sequence.md) pass. Firewall logs must be received and written by the Linux syslog relay; Zeek/Suricata files must exist locally; endpoint source events must be verified. Follow [Telemetry Collection & Forwarding](telemetry-pipeline.md).

Install Wazuh agents on endpoints, relay and sensor. Configure Logcollector to monitor the relay and sensor files explicitly. Wazuh manager releases document a direct syslog input mode as well as the normal secure agent channel. For this lab, prefer the relay-file-plus-agent pattern because it gives durable source-specific files and consistent collection across versions. If you choose direct manager syslog, verify the exact release's remote-input configuration, restrict allowed source IPs, and use TLS or a trusted isolated network. Do not assume direct syslog is removed or enabled by default.

## 1. Prepare the server

Use a fresh supported Ubuntu Server VM on the Windows PC or Mac. Wazuh central components support 64-bit Intel, AMD and ARM Linux on the operating systems listed in the current support matrix. For a 1–25 agent quickstart, Wazuh currently recommends 4 vCPU, 8 GiB RAM and 50 GB storage for 90 days of indexed alert data; use more disk for raw logs and longer retention. Run Wazuh separately from Elastic and Splunk initially.

Set hostname and static address, update the OS, and confirm DNS/time are correct. Do not expose the dashboard to the public Internet.

## 2. Install using the official assistant

1. Open the current Wazuh Quickstart documentation and confirm the current version, OS support and sizing. At the time this guide was checked, the official page documents Wazuh 4.14 and the following assistant command. If the current docs show a newer version, use that documented version instead:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

2. Run the assistant on the fresh server.
3. Save the generated dashboard credentials and certificates securely.
4. Confirm services:

```bash
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
```

5. Access the dashboard over the management network using HTTPS and the generated trust material. Do not permanently disable certificate validation.

## 3. Optional direct syslog input (only if deliberately selected)

Wazuh manager supports a syslog remote input in documented releases. This is separate from the secure agent channel (normally TCP/1514). Configure only after checking the installed release's documentation. Example manager configuration fragment for a dedicated lab manager, with source allowlisting:

~~~xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.10.30.1</allowed-ips>
  <local_ip>10.10.30.21</local_ip>
</remote>
~~~

Replace the source and listener addresses with actual values. Restrict TCP/514 at host and network firewalls. Validate XML/configuration and restart the manager using the release-specific procedure. Direct syslog input does not replace endpoint agents for Windows Event Channels or macOS Unified Logging. Do not enable this listener on an untrusted interface.

## 4. Enrol Windows endpoint

1. In the dashboard, open Agents → Deploy new agent.
2. Select Windows and the current agent package.
3. Enter the Wazuh manager address reachable on SERVER.
4. Copy the generated installation/enrolment command.
5. Run it in elevated PowerShell on PSV-W11-01.
6. Start the Wazuh service and confirm the agent appears active.

Generated commands may contain registration secrets and internal addresses. Never publish them.

## 5. Enrol Linux endpoint

1. Open Deploy new agent and select the correct Linux distribution and architecture.
2. Follow the current repository and package instructions.
3. Configure the manager address and enrol the agent.
4. Enable/start the agent and verify it appears active.

## 6. Validate telemetry

- Check agent status and last keepalive.
- Inspect manager and agent logs for connection or decoder errors.
- Generate a harmless test event, such as creating/modifying a file in a dedicated FIM test directory.
- Confirm the event is visible in the dashboard.
- Record agent ID, rule ID, decoder, source log, event time and raw event.

Installing an agent does not automatically enable every capability. File Integrity Monitoring, vulnerability detection, Security Configuration Assessment, command auditing and log collection have separate configuration and coverage requirements.

## 7. First exercises

1. Configure FIM for a dedicated lab directory using the current Wazuh FIM documentation.
2. Create, modify and delete a harmless test file.
3. Verify the expected alert and identify the rule that generated it.
4. Configure collection of the Sysmon Operational channel on Windows.
5. Generate a benign Notepad process event.
6. Compare the Wazuh event with the original Event Viewer record.

Use a version-controlled copy of custom rules. Validate configuration before restarting services. Do not paste unreviewed example rules into a production manager.

## 8. Troubleshooting and cleanup

Check manager/indexer/dashboard service logs, agent connectivity, DNS, firewall, certificates, disk and memory. Unenrol agents through the supported workflow. Do not delete indexer data directories manually while services are running.

## References

- [Wazuh Quickstart](https://documentation.wazuh.com/current/quickstart.html)
- [Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html)
- [Agent deployment and enrolment](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html)
- [File Integrity Monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Wazuh remote configuration and syslog input](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/remote.html)
