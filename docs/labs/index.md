# Enterprise-style cybersecurity home lab

<badge color="warning">Dependency-ordered build programme — reference guides, not yet hardware-tested</badge>

This programme has two distinct host tracks: Windows x64 and Apple-silicon Mac ARM64. They share security objectives, but not identical firewall appliances, guest architectures or hypervisor networking.

**Build rule:** complete each stage and its acceptance gate before proceeding. A SIEM is not installed until firewall, endpoint and network telemetry sources exist, produce events, and have a verified forwarding path.

## Correct dependency order

| Stage | Build activity | Required outcome |
|---:|---|---|
| 0 | [Hardware and compatibility](requirements.md) | Host architecture, RAM, storage, guest and product support recorded |
| 1 | [Windows host](platform-windows.md) or [Mac host](platform-macos.md) | Hypervisor installed; test VM boots and snapshot restore works |
| 2 | [Network design](network-design.md) and [hypervisor implementation](hypervisor-network-implementation.md) | Segments, actual virtual switches, adapter mapping and isolation boundaries documented |
| 3 | [Windows OPNsense firewall](firewall-routing.md) or [Mac ARM router](mac-arm-routing.md) plus [Mac router implementation](mac-arm-router-implementation.md) | Routing, default-deny policy, DNS/DHCP/NTP and egress controls validated |
| 4 | [Operating systems and identity](operating-systems.md) | Domain controller, endpoints, Linux hosts, Kali and target deployed |
| 5 | [Endpoint telemetry](windows-endpoint-telemetry.md) | Windows Security/Sysmon and Linux/macOS source events verified locally |
| 6 | [Network monitoring](network-monitoring.md) and [sensor implementation](network-sensor-implementation.md) | Firewall IDS, Suricata and Zeek visibility proven; logs written locally |
| 7 | [Syslog relay implementation](syslog-relay-implementation.md) and [telemetry pipeline](telemetry-pipeline.md) | Firewall/router events reach the relay; endpoint events and sensor files are verified locally |
| 8 | [Elastic](elastic-siem.md), [Splunk](splunk-siem.md) or [Wazuh](wazuh-soc.md) | Install one SIEM, configure collectors/agents, and prove end-to-end ingestion |
| 9 | [Security Onion](security-onion.md) — optional x86-64 alternative | Dedicated NSM/SOC deployment after network visibility is ready |
| 10 | [Penetration testing](penetration-testing.md) | Scope, isolation, target and telemetry gates passed |
| 11 | [SOC validation](soc-exercises.md) | End-to-end detection, investigation, evidence and cleanup demonstrated |

Do not skip ahead to a SIEM because its installer is available. A running service or online agent does not prove that the required events are being collected.

## Platform tracks

### Windows x64 PC

This is the full x86-64 track. Choose one primary hypervisor: Hyper-V, VMware Workstation or VirtualBox. Run OPNsense as an x86-64 firewall VM with WAN plus separate internal network adapters. Start Suricata in alert-only IDS mode on relevant internal interfaces. Add a Zeek sensor only after a real packet mirror/tap or offline PCAP path is verified.

This track supports Windows Server/Windows 11 x64, Ubuntu x86-64, Kali x86-64, Splunk Enterprise on a supported x64 OS, and Security Onion x86-64 when hardware meets vendor requirements.

### Apple-silicon Mac

Use VMware Fusion or another hypervisor supporting ARM64 guests. Use ARM64 Ubuntu, Kali and Windows 11 ARM images. OPNsense is x86-64 only; do not attempt to install it as an ARM64 guest. For a Mac-only isolated lab use the [ARM64 Linux router/firewall path](mac-arm-routing.md). It uses Ubuntu Server ARM64 and nftables; it is not an OPNsense replacement. Splunk Enterprise and Security Onion are not native ARM64 guest targets.

### Combining Windows and Mac

Fusion host-only networks and Windows hypervisor private networks are local to their host; they do not automatically form one shared enterprise network. Start with two independently isolated labs. A single cross-host VLAN design requires a separate physical firewall/switch architecture. Never bridge REDTEAM or DMZ onto home Wi-Fi.

## Data-flow model

    Endpoint events ───────────────> endpoint agent / forwarder ─┐
    Firewall rule logs ────────────> syslog relay ───────────────┤
    Firewall Suricata EVE alerts ──> syslog relay ───────────────┤
    Zeek / sensor Suricata files ──> sensor collector/agent ─────┤
                                                                v
                                                     One selected SIEM
                                                                |
                                                      searches/detections
                                                                |
                                                      SOC investigation

Every arrow must be configured and tested. A firewall does not automatically export logs, and a sensor does not automatically send data to a SIEM.

## Resource planning

These are home-lab starting allocations, not universal vendor minimums:

| Component | Starting allocation |
|---|---|
| Windows Server AD DS/DNS | 2–4 vCPU, 6–8 GB RAM, 80 GB disk |
| Windows 11 endpoint | 2–4 vCPU, 6–8 GB RAM, 80 GB disk |
| Ubuntu endpoint | 2 vCPU, 2–4 GB RAM, 40–60 GB disk |
| Kali | 2–4 vCPU, 4–8 GB RAM, 60 GB disk |
| Linux syslog relay | 2 vCPU, 2–4 GB RAM, 30–50 GB disk |
| Zeek/Suricata sensor | 4 vCPU, 8 GB RAM, SSD-backed log storage |
| Elastic single-node learning stack | 4–8 vCPU, 12–16 GB RAM, 150–200 GB disk |
| Splunk Enterprise learning stack | 4 vCPU, 8–12 GB RAM, 100–150 GB disk; check current release requirements |
| Wazuh all-in-one | Use current official sizing; current quickstart reference is 4 vCPU, 8 GiB RAM, 50 GB for 90 days of indexed alert data |
| Security Onion Standalone | Vendor bare minimum: 4 CPU cores, 24 GB RAM, 200 GB storage, 2 NICs |

Run one major SIEM stack at a time. Security Onion is a separate, resource-intensive platform.

## Evidence standard

For every stage record host/guest architecture, versions, checksums, VM resources, adapter mapping, IPs/routes, firewall rules, source event, collector receipt, SIEM document, timestamps, expected/actual results, rollback and cleanup. Never publish employer logs, customer data, credentials, tokens or private certificates.

**Status:** These are build instructions. Do not label a stage “lab-tested” until executed on the target hardware with sanitised evidence.
