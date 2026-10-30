# End-to-end lab build sequence and acceptance gates

<badge color="warning">Execution runbook — not yet lab-tested</badge>

Use this runbook as the master sequence for building the PSV home lab from an empty host. The linked lab pages contain the product-specific installation commands and settings. Complete the gates in order; do not install every platform and SIEM at once.

## 0. Select the host path

Choose one primary host for x86-64 infrastructure:

- **Windows x64 PC:** Hyper-V, VMware Workstation or [VirtualBox](platform-virtualbox.md). OPNsense, Windows Server, Windows 11 x64, Splunk Enterprise and Security Onion belong on this host where the exact release support matrix allows.
- **Apple-silicon Mac:** VMware Fusion or VirtualBox for ARM64 guests only. Use ARM64 Ubuntu/Kali/Windows images. Do not plan x86-64 OPNsense, Security Onion or Splunk Enterprise on this host.

Read [Hardware & Compatibility](requirements.md) and the selected [Windows host](platform-windows.md), [VirtualBox host](platform-virtualbox.md) or [Mac host](platform-macos.md) guide first.

**Gate 0 — host ready**

- Host architecture, OS build, RAM, CPU virtualisation and free SSD space recorded.
- Firmware virtualisation enabled.
- Host data backed up and BitLocker recovery key available where applicable.
- Exact hypervisor version and guest architecture selected.
- Enough RAM remains for the host OS; do not allocate all physical memory to VMs.

## 1. Install and baseline the hypervisor

1. Install only the chosen hypervisor on the primary Windows host.
2. Create the VM storage folders and set the hypervisor's default VM path.
3. Download guest images from official vendor pages only.
4. Verify published SHA-256 checksums where provided; record image filename, version, architecture and checksum.
5. Create one small Ubuntu test VM and boot it.
6. Install guest OS updates and verify guest tools/integration components from the hypervisor vendor.
7. Take a clean baseline snapshot and test restore.

Use the exact platform guide for network creation and host-specific caveats.

**Gate 1 — hypervisor works**

- Test VM boots after a host reboot.
- Guest architecture matches the intended host/guest pairing.
- Snapshot restore works.
- No guest is connected to a physical bridged network unless the topology explicitly requires it.

## 2. Build the isolated virtual networks

Use the [Network Design](network-design.md) address plan. Before using the suggested ranges, check for overlap with the home LAN, VPN routes and other networks.

| Segment | Subnet | Function |
|---|---|---|
| MGMT | 10.10.10.0/24 | Host/admin access to lab management |
| ENDPOINT | 10.10.20.0/24 | Windows/Linux endpoints |
| SERVER | 10.10.30.0/24 | AD DS/DNS and SIEM servers |
| REDTEAM | 10.10.40.0/24 | Kali and authorised test source |
| SENSOR | 10.10.50.0/24 | Passive monitoring path, if explicitly implemented |
| DMZ | 10.10.60.0/24 | Intentionally vulnerable targets |

Do not assume a virtual switch enforces security policy. Layer-2 networks require a router/firewall for controlled inter-subnet traffic.

### 2.1 Deploy OPNsense

Follow [OPNsense Firewall & Routing](firewall-routing.md) and its hypervisor-specific adapter mapping. Use a dedicated firewall VM with separate virtual NICs for WAN, MGMT, ENDPOINT, SERVER, REDTEAM and DMZ. Do not add a sensor NIC to the routing path merely to make it reachable.

Configure:

- WAN on the hypervisor's NAT/update network only.
- MGMT at 10.10.10.1/24.
- ENDPOINT at 10.10.20.1/24.
- SERVER at 10.10.30.1/24.
- REDTEAM at 10.10.40.1/24.
- DMZ at 10.10.60.1/24.

Map interfaces by MAC address. Do not assume adapter order equals OPNsense interface order.

### 2.2 Apply minimum firewall policy

1. Change default credentials immediately.
2. Restrict firewall GUI/SSH to the admin workstation on MGMT.
3. Enable DNS resolver only on required lab interfaces.
4. Create DHCP scopes only on segments that need them. Keep domain controller and SIEM server addresses static or reserved.
5. Start with default-deny between segments.
6. Add narrow rules for DNS, NTP, Active Directory, management and telemetry only after confirming the selected product's current port documentation.
7. Permit Kali to reach only the explicitly scoped target IP/ports.
8. Deny DMZ-to-MGMT/SERVER/ENDPOINT and deny all lab-to-home-LAN access.
9. Permit temporary outbound updates only when required; disable update egress for vulnerable targets before exercises.
10. Export an encrypted firewall configuration backup.

**Gate 2 — isolation proven**

- Every VM has only the intended NICs.
- DHCP, gateway and DNS are correct.
- Allowed flows work on the required ports.
- Denied flows are blocked and visible in firewall logs.
- Kali cannot reach the host's physical LAN, home router or management network.
- Juice Shop and other vulnerable targets have no direct bridged or unrestricted Internet path.
- Evidence includes route tables, firewall rules/logs and specific TCP tests. Ping failure alone is not proof.

## 3. Install operating systems and identity services

Follow [Operating Systems & Identity](operating-systems.md).

Recommended first set:

| VM name | OS / role | Network | Suggested address |
|---|---|---|---|
| PSV-DC01 | Windows Server, AD DS + DNS | SERVER | 10.10.30.10 |
| PSV-W11-01 | Windows 11 x64 endpoint | ENDPOINT | DHCP reservation |
| PSV-UBU-01 | Ubuntu Server endpoint | ENDPOINT | DHCP reservation |
| PSV-KALI-01 | Kali Linux assessment source | REDTEAM | 10.10.40.10 |
| PSV-SIEM01 | One selected SIEM host | SERVER | 10.10.30.20–22 |
| PSV-JUICE01 | OWASP Juice Shop target | DMZ | 10.10.60.20 |

These are example names and addresses for a synthetic lab. Confirm no subnet conflicts before using them.

### 3.1 Windows Server and Active Directory

1. Install a supported Windows Server evaluation or licensed image on a Generation 2/UEFI VM.
2. Set hostname `PSV-DC01`, static IP `10.10.30.10/24`, gateway `10.10.30.1`, and DNS initially to itself only after DNS service is installed; during initial setup follow Microsoft's domain-controller DNS guidance.
3. Apply updates and set time synchronisation.
4. Install the AD DS and DNS roles using Server Manager or the supported PowerShell workflow.
5. Promote the server as a new forest using a reserved lab-only DNS domain such as `psv.lab`. Never use a real public domain you do not own.
6. Set a strong Directory Services Restore Mode password and store it securely.
7. Verify DNS forward and reverse lookups and domain-controller health using Microsoft's supported diagnostic tools.
8. Create a dedicated lab OU and synthetic test users/groups. Do not reuse personal or employer accounts.

### 3.2 Windows 11 endpoint

1. Install supported Windows 11 x64 media on an x64 host VM.
2. Configure UEFI, virtual TPM and Secure Boot as required by the hypervisor and Windows release.
3. Set hostname `PSV-W11-01`; point DNS to `10.10.30.10` when joining the lab domain.
4. Install updates and verify domain name resolution.
5. Join `psv.lab` using a delegated lab join account.
6. Reboot and verify domain sign-in and Group Policy application.
7. Take a clean endpoint snapshot before adding Sysmon or agents.

### 3.3 Ubuntu endpoint/server

1. Install the correct x86-64 or ARM64 Ubuntu Server ISO for the host.
2. Set hostname, static/reserved IP, gateway, DNS and time synchronisation.
3. Create a named sudo user; disable direct root SSH login.
4. Install only required packages and enable SSH only from MGMT.
5. Install/configure auditd if the monitoring exercise requires Linux audit events.
6. Verify journald/authentication logs and audit records locally before installing a SIEM agent.

### 3.4 Kali and vulnerable target

1. Install official Kali image on REDTEAM only.
2. Install Kali updates while temporary update egress is enabled, then remove that egress.
3. Install assessment tools from official repositories and record versions.
4. Deploy OWASP Juice Shop on a dedicated DMZ VM/container host. Bind its service to the lab interface, not the host's public or home-LAN interface.
5. Verify Kali can reach only the Juice Shop target service required for the exercise.
6. Do not scan public systems, employer networks or home devices as part of this lab.

**Gate 3 — OS baseline complete**

- All hostnames, OS versions, architectures, addresses and NICs recorded.
- Domain controller and domain client resolve DNS correctly.
- Endpoint logs exist locally before forwarding.
- Kali and vulnerable target remain isolated.
- Baseline snapshots and recovery method documented.

## 4. Add endpoint telemetry before installing a SIEM

1. On Windows, enable/install Sysmon using Microsoft's current instructions. Windows 11 may provide Sysmon as an optional feature; check before installing the standalone package to avoid duplicate installations.
2. Confirm Sysmon Event ID 1 appears in the Sysmon Operational channel after launching Notepad.
3. Configure Windows Security auditing using the lab Group Policy and record the exact audit subcategories enabled.
4. On Ubuntu, enable auditd only for the selected test rules and confirm records locally.
5. Record source event channel, event ID, time, host, user and relevant process fields.
6. Take a snapshot after the endpoint telemetry baseline is stable.

Use [Windows Endpoint Telemetry](windows-endpoint-telemetry.md) for the Sysmon-to-Elastic reference walkthrough.

**Gate 4 — source events proven**

- Raw local Windows Sysmon event exists.
- Required Windows Security events are generated by controlled actions.
- Linux auth/audit records exist.
- Source timestamps and host identity are recorded.
- No SIEM troubleshooting begins until local event generation is proven.

## 5. Install one SIEM stack at a time

Choose the product lab that matches the learning objective. Do not run Elastic, Splunk, Wazuh and Security Onion concurrently on a constrained PC.

### Option A — Elastic Stack + Fleet

Follow [Elastic SIEM](elastic-siem.md). Use a supported Linux release/architecture and a single-node learning deployment. Keep Elasticsearch and Kibana on the same compatible version family. Enrol one Windows and one Linux endpoint, add only the integrations required, and inspect raw events before assuming field mappings.

### Option B — Splunk Enterprise + Universal Forwarder

Follow [Splunk SIEM](splunk-siem.md). Install Enterprise on a supported x86-64 Windows/Linux platform. Enable a receiving port only on the lab interface. Install a compatible Universal Forwarder on the Windows endpoint and validate the raw Sysmon event before relying on field extractions or CIM fields. Check the current Splunk licence and support matrix.

### Option C — Wazuh all-in-one

Follow [Wazuh SOC](wazuh-soc.md). Use a supported x86-64 or ARM64 Linux build only when all Wazuh components in the selected release support it. The all-in-one quickstart is a learning deployment, not a production HA design. Enrol Windows/Linux agents and explicitly configure the log sources/capabilities being tested.

For each SIEM:

1. Record OS and product versions, package source, licence and VM resource allocation.
2. Install from the official vendor repository/package.
3. Configure authentication and TLS; do not disable security controls to make setup easier.
4. Bind management UI to the lab management path and restrict it to MGMT.
5. Configure the receiver/agent path using the product's current documentation.
6. Forward one known benign event.
7. Search for the raw event, inspect actual field names and measure ingestion delay.
8. Run positive and negative tests from the Phase 5 detection content.
9. Export sanitised configuration/evidence and take a snapshot.

**Gate 5 — SIEM ingestion proven**

- SIEM service health is good.
- Endpoint agent/forwarder is enrolled and policy applied.
- Local source event and SIEM document are correlated.
- Host, timestamp, event code and process/user context are usable.
- Positive and negative detection tests are recorded.
- Ingestion delay and missing telemetry are documented.

## 6. Add network monitoring as a separate build

Follow [Network Monitoring](network-monitoring.md). Install Zeek and Suricata on a supported Linux VM or use the documented gateway integration. Confirm the selected interface actually receives packets before configuring detections.

- Capture a known DNS query and HTTP request to the DMZ target.
- Confirm packet counters increase.
- Confirm Zeek writes connection/DNS logs.
- Confirm Suricata writes EVE JSON records.
- Compare sensor metadata with endpoint events by timestamp and address.
- Document capture loss, interface offload and visibility limitations.

A promiscuous-mode NIC does not automatically receive all traffic from all virtual networks. If no supported mirror/tap is configured, describe the sensor's actual visibility accurately.

## 7. Security Onion is an optional dedicated x86-64 build

Follow [Security Onion](security-onion.md) only on the Windows x64 host or supported x86-64 hardware. Check the current official hardware minimums and release requirements before allocating resources. The published standalone baseline is resource intensive; do not run it concurrently with every other SIEM on a constrained machine.

Use the dedicated management and sniffing interfaces required by the chosen deployment. Validate packet visibility and storage before enabling broad ingestion. Security Onion is not an Apple Silicon ARM guest target.

## 8. Run the penetration-testing exercises

Follow [Penetration Testing](penetration-testing.md) after the network isolation gate passes.

1. Confirm Kali's only assessment path is REDTEAM.
2. Record the written scope: target IP, ports, test window and allowed techniques.
3. Confirm the target is the lab-owned Juice Shop instance.
4. Capture baseline target service state.
5. Perform only the controlled test described in the lab guide.
6. Record tool version, command, time, output and target response.
7. Confirm endpoint/SIEM/network sensor telemetry for the activity.
8. Stop the test, disable temporary update egress and restore the target if required.

Never use this lab to scan a public IP, corporate network or third-party service without explicit written authorisation.

## 9. Complete SOC validation and evidence

Follow [SOC Validation Exercises](soc-exercises.md). Use synthetic users, benign process launches and controlled group membership changes. Do not use malware or real customer/employee data.

For each exercise preserve:

- Lab case ID and scope.
- Host and VM details.
- Original local event.
- SIEM raw document and query.
- Detection rule/version and positive/negative result.
- Timeline with timezone and ingestion delay.
- Network capture/Zeek/Suricata record where applicable.
- Firewall log and isolation test.
- Cleanup result and reviewer notes.

## 10. Operational maintenance and reset

- Apply OS and product updates during a defined maintenance window; snapshot/export first.
- Back up SIEM configuration and important lab data separately from snapshots.
- Monitor CPU, RAM, disk capacity, disk latency, agent health and ingest queues.
- Rotate lab credentials and remove unused enrollment tokens.
- Delete temporary accounts, test files, containers and firewall exceptions after exercises.
- Re-test network isolation after hypervisor, firewall or virtual NIC changes.
- Keep all evidence synthetic and sanitised.

## Final acceptance checklist

- [ ] Host and hypervisor compatibility verified.
- [ ] All VMs use the intended architecture and isolated virtual networks.
- [ ] OPNsense interface mapping verified by MAC.
- [ ] Inter-segment firewall policy tested and logged.
- [ ] AD DS/DNS and domain join verified (if included).
- [ ] Windows and Linux source events generated locally.
- [ ] One SIEM stack installed and ingestion validated.
- [ ] Network monitoring visibility demonstrated with known traffic (if included).
- [ ] Kali-to-target scope verified; no home-LAN reachability.
- [ ] Positive and negative detection tests recorded.
- [ ] Backup, rollback and cleanup tested.

**Status rule:** The presence of these instructions or a successful MkDocs build does not prove a working lab. Mark a lab as tested only after performing the steps on the target hardware and publishing reproducible, sanitised evidence.
