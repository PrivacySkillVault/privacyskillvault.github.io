# Lab 7 — Wazuh all-in-one SOC stack

<badge color="warning">Build guide — not yet lab-tested</badge>

The all-in-one Wazuh deployment places manager, indexer and dashboard on one Linux host for learning. It is not a highly available production architecture.

## 1. Prepare the server

Use a fresh supported Ubuntu Server x86-64 VM on the Windows PC. Start with 4 vCPU, 8–12 GB RAM and 100 GB SSD-backed disk for a small lab. Check Wazuh's current quickstart sizing table for the number of agents and expected events. Run Wazuh separately from Elastic and Splunk initially.

Set hostname and static address, update the OS, and confirm DNS/time are correct. Do not expose the dashboard to the public Internet.

## 2. Install using the official assistant

1. Open the current Wazuh Quickstart documentation.
2. Follow the all-in-one installation assistant command shown for the current release. The download URL and version may change; do not copy a stale assistant command from a blog.
3. Run the assistant as instructed on the fresh server.
4. Save the generated dashboard credentials and certificates securely.
5. Confirm services:

\`\`\`bash
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
\`\`\`

6. Access the dashboard over the management network using HTTPS and the generated trust material. Do not permanently disable certificate validation.

## 3. Enrol Windows endpoint

1. In the dashboard, open Agents → Deploy new agent.
2. Select Windows and the current agent package.
3. Enter the Wazuh manager address reachable on SERVER.
4. Copy the generated installation/enrolment command.
5. Run it in elevated PowerShell on PSV-W11-01.
6. Start the Wazuh service and confirm the agent appears active.

Generated commands may contain registration secrets and internal addresses. Never publish them.

## 4. Enrol Linux endpoint

1. Open Deploy new agent and select the correct Linux distribution and architecture.
2. Follow the current repository and package instructions.
3. Configure the manager address and enrol the agent.
4. Enable/start the agent and verify it appears active.

## 5. Validate telemetry

- Check agent status and last keepalive.
- Inspect manager and agent logs for connection or decoder errors.
- Generate a harmless test event, such as creating/modifying a file in a dedicated FIM test directory.
- Confirm the event is visible in the dashboard.
- Record agent ID, rule ID, decoder, source log, event time and raw event.

Installing an agent does not automatically enable every capability. File Integrity Monitoring, vulnerability detection, Security Configuration Assessment, command auditing and log collection have separate configuration and coverage requirements.

## 6. First exercises

1. Configure FIM for a dedicated lab directory using the current Wazuh FIM documentation.
2. Create, modify and delete a harmless test file.
3. Verify the expected alert and identify the rule that generated it.
4. Configure collection of the Sysmon Operational channel on Windows.
5. Generate a benign Notepad process event.
6. Compare the Wazuh event with the original Event Viewer record.

Use a version-controlled copy of custom rules. Validate configuration before restarting services. Do not paste unreviewed example rules into a production manager.

## 7. Troubleshooting and cleanup

Check manager/indexer/dashboard service logs, agent connectivity, DNS, firewall, certificates, disk and memory. Unenrol agents through the supported workflow. Do not delete indexer data directories manually while services are running.

## References

- [Wazuh Quickstart](https://documentation.wazuh.com/current/quickstart.html)
- [Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html)
- [Agent deployment and enrolment](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/index.html)
- [File Integrity Monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
