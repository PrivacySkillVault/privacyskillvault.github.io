# Master build sequence — dependency gates

<badge color="warning">Canonical execution order — reference guide, not yet hardware-tested</badge>

This is the authoritative Phase 6 order. Follow it from an empty host. Product pages contain installation details; this page defines prerequisites and pass/fail gates. If a gate fails, stop and fix it.

## Stage 0 — select platform and verify support

1. Complete [Hardware & Compatibility](requirements.md).
2. Record CPU architecture, host OS/build, RAM, free SSD space and hypervisor version.
3. Choose one primary Windows hypervisor.
4. On Apple Silicon, use ARM64 guest images only.
5. Decide whether Windows and Mac remain separate lab islands or will later be joined using a physical firewall/VLAN design.

**Gate 0:** every guest and product has a supported architecture. OPNsense and Security Onion are x86-64. Splunk Enterprise requires a supported x64 platform. Apple Silicon cannot run these x86-64 guests natively.

## Stage 1 — host and hypervisor

Follow [Windows Host Setup](platform-windows.md), [Mac Host Setup](platform-macos.md), and [VirtualBox Host Setup](platform-virtualbox.md) if selected.

1. Install one hypervisor from its official source.
2. Create VM, ISO, export, evidence and backup folders on SSD.
3. Download official guest images and verify checksums/signatures.
4. Create one small Ubuntu test VM of the correct architecture.
5. Verify boot, networking and time.
6. Snapshot, restore and boot again.

**Gate 1:** host reboot does not break the hypervisor; test guest boots/restores; no guest is bridged to the physical LAN without an explicit design.

## Stage 2 — design and create networks

Follow [Network Design](network-design.md), [Hypervisor Network Implementation](hypervisor-network-implementation.md) and the [Firewall Policy Matrix](firewall-policy-matrix.md). Check example subnets against home LAN, VPN and existing routes. Create and verify the actual virtual switches before attaching guests.

| Segment | Example subnet | Purpose |
|---|---|---|
| MGMT | 10.10.10.0/24 | Admin workstation and management UIs |
| ENDPOINT | 10.10.20.0/24 | Windows/Linux/Mac test endpoints |
| SERVER | 10.10.30.0/24 | AD DS/DNS, syslog relay and selected SIEM |
| REDTEAM | 10.10.40.0/24 | Kali assessment source |
| SENSOR-MGMT | 10.10.50.0/24 | Sensor administration only; capture NIC is separate/no IP |
| DMZ | 10.10.60.0/24 | Vulnerable targets |

**Gate 2:** segments exist; VM NICs are mapped; no DHCP overlap, subnet overlap or unintended bridged adapter.

## Stage 3 — routing and firewall

### Windows x64
Follow [OPNsense Firewall & Routing](firewall-routing.md). Create an x86-64 OPNsense VM with WAN on hypervisor NAT and internal adapters for MGMT, ENDPOINT, SERVER, REDTEAM and DMZ. Map interfaces by MAC, not assumed adapter order. Configure DNS/DHCP only where required, default-deny between segments, narrowly scoped AD/management/telemetry rules, temporary update egress and encrypted configuration backup.

### Apple Silicon Mac
Follow [Mac ARM Router & Firewall](mac-arm-routing.md) and the [detailed ARM64 router implementation](mac-arm-router-implementation.md). Use Ubuntu Server ARM64 with Netplan and nftables on separate Fusion private networks. This is not OPNsense. If Fusion cannot create enough isolated networks, stop; do not collapse all guests onto one host-only network and call it segmented.

**Gate 3:** verify DHCP/static addressing, DNS, gateway, allowed and denied TCP flows, firewall logs and routes. Kali/DMZ must not reach home LAN or MGMT.

## Stage 4 — operating systems and identity

Follow [Operating Systems & Identity](operating-systems.md).

Windows x64 track: Windows Server on SERVER; create a private lab-only AD domain such as lab.psv.test; Windows 11 x64 on ENDPOINT; Ubuntu; Kali on REDTEAM; vulnerable target on DMZ.

Mac ARM64 track: Ubuntu Server ARM64, Kali ARM64 and architecture-compatible target VM/container. Windows 11 ARM is optional only after verifying the exact agent/driver support. Do not assume x64 agents work on Windows ARM.

**Gate 4:** record hostnames, OS versions, architecture, IPs, routes, DNS, time and NICs. Domain join works where used. Kali reaches only its scoped target. DMZ has no unrestricted Internet/home-LAN path.

## Stage 5 — generate endpoint telemetry locally

Follow [Windows Endpoint Telemetry](windows-endpoint-telemetry.md) and the [Cross-platform Endpoint Telemetry Implementation](endpoint-telemetry-implementation.md).

1. Configure Windows Advanced Audit Policy through a lab-only GPO.
2. Install/configure Sysmon using Microsoft's current instructions and a reviewed configuration.
3. Generate a benign process-creation event and verify it in the local Sysmon Operational channel.
4. Generate a controlled Windows Security event and verify it locally.
5. On Linux, enable required auditd/journald sources and verify local records.
6. On macOS, use only telemetry sources supported by the chosen agent and OS version.

**Gate 5:** raw source event exists locally with host, timestamp and event identity. Do not troubleshoot SIEM ingestion before this passes.

## Stage 6 — firewall and network monitoring

Follow [Network Monitoring](network-monitoring.md) and the [Zeek/Suricata sensor implementation](network-sensor-implementation.md). Prove packet visibility before installing analyzers.

1. On Windows OPNsense, enable Suricata in alert-only IDS mode on relevant internal interfaces, not only WAN. WAN capture after NAT may lose original internal source identity.
2. Enable logging on the firewall rules used for pass/block tests.
3. Generate known allowed and denied connections; verify firewall logs show rule and endpoints.
4. Enable OPNsense Suricata EVE/syslog output and verify the local alert.
5. Install Zeek only after a real packet mirror/tap is configured. Hyper-V port mirroring works only when source and destination adapters share the relevant virtual switch; Workstation/Fusion/VirtualBox promiscuous mode is not a universal SPAN.
6. Generate known DNS/HTTP traffic and verify Zeek logs and Suricata EVE JSON locally.
7. Record exactly which segments/interfaces are visible.

On Mac ARM, use supported ARM64 Zeek/Suricata builds only after verifying packet visibility. Verify nftables firewall logs locally.

**Gate 6:** firewall pass/block events, IDS alerts, Zeek logs (if enabled) and endpoint events exist locally. Packet visibility is proven with a known flow.

## Stage 7 — telemetry collection and forwarding

Follow the [rsyslog relay implementation](syslog-relay-implementation.md) and [Telemetry Collection & Forwarding](telemetry-pipeline.md).

1. Create a Linux syslog relay on SERVER.
2. Configure OPNsense or the Mac Linux router to send firewall events to the relay.
3. Verify messages arrive and are written to the expected per-source files.
4. Verify Zeek/Suricata files exist, are readable and rotate safely.
5. Configure log rotation, disk limits, file permissions, source identity and timestamps on the relay and sensor.
6. Keep endpoint collection explicit: Windows Event Channels/Sysmon, Linux journald/auditd and macOS Unified Logging where supported. Prove each event exists locally.
7. Do not configure SIEM-specific agents/forwarders yet; the destination SIEM does not exist at this stage.

**Gate 7:** firewall/router events arrive at the relay and are written to the correct source-specific files; Zeek/Suricata files exist locally on the sensor; endpoint source events exist locally; timestamps and host identity are preserved. This gate proves source generation and pre-SIEM relay only—not SIEM ingestion.

## Stage 8 — install one SIEM and connect sources

Choose one stack per iteration:

- [Elastic](elastic-siem.md): Fleet/Elastic Agent, Windows and System integrations, Filestream for firewall/sensor files.
- [Splunk](splunk-siem.md): Enterprise on supported x64; Universal Forwarder monitors endpoint, relay and sensor files. Use rsyslog/syslog-ng plus UF or Splunk Connect for Syslog, not direct Splunk UDP input as default.
- [Wazuh](wazuh-soc.md): central stack plus agents on endpoints, relay and sensor; Logcollector monitors firewall/sensor files. Prefer relay-file-plus-agent; direct manager syslog is an optional, explicitly configured input with source allowlisting, depending on the installed release.

For each stack, confirm current OS/architecture support and licence; configure TLS/authentication; install supported agents/forwarders on endpoints, relay and sensor; connect one source at a time; inspect raw events and parsed fields; measure ingestion delay; check duplicates; then add detections. On the Mac router track, forward nftables messages from its local rsyslog file to the SERVER relay over the configured restricted transport, or collect the local file with a supported agent. Do not assume an agent supports ARM64 without checking its matrix.

**Gate 8:** every required source has a raw searchable SIEM event with correct source/host/time fields and measured ingest delay. Agent online alone does not pass.

## Stage 9 — optional Security Onion

Security Onion is x86-64 only and resource intensive. Build on Windows x64 or dedicated x86-64 hardware after network and packet visibility stages. It is an alternative integrated NSM/SOC platform, not an ARM Mac guest or a prerequisite for other SIEMs.

## Stage 10 — controlled penetration testing

Follow [Penetration Testing](penetration-testing.md). Define target IPs/ports and test window; re-check Kali REDTEAM isolation and DMZ egress; record baseline firewall/endpoint/sensor events; run only the lab-owned test; correlate firewall, IDS, Zeek, endpoint and SIEM records; remove temporary rules and restore the target.

**Gate 10:** scope and isolation pass before scanning. Unexpected reachability is a stop condition.

## Stage 11 — SOC validation

Follow [SOC Validation Exercises](soc-exercises.md). Test benign process creation, account/group change, DNS/HTTP and blocked network activity. Preserve source event, relay record, SIEM document, query, rule/version, alert, timeline, analyst conclusion and cleanup.

## Stage 12 — operations and recovery

Back up firewall configuration, AD/system state, SIEM configuration and required data separately from snapshots. Document retention, patch windows, credential rotation, agent health, storage growth and restore tests. Re-test segmentation after hypervisor/firewall/NIC changes.

## Stop conditions

Stop if a guest has an unexpected bridged NIC, Kali/DMZ can reach home LAN, interface mapping is uncertain, source events are absent, sensor feed is unproven, collector files are empty, or product architecture is unsupported. Fix the dependency; do not bypass it by disabling security controls.
