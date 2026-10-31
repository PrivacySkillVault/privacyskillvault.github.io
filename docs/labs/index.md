# Enterprise-style cybersecurity home lab

<badge color="warning">VM-based dual-SIEM build programme — design baseline, not yet hardware-tested</badge>

This programme builds an enterprise-style segmented lab using virtual machines. The Windows x64 host runs the selected hypervisor and management tools; guest operating systems, firewalls, endpoints, collectors and SIEM products run inside VMs. The Apple-silicon Mac is a separate ARM64 track.

**Primary architecture:** OPNsense firewall, Windows Server AD DS/DNS, Windows 11 endpoint, Ubuntu Vector broker, Elastic Security, Splunk Enterprise, Ubuntu Zeek/Suricata sensor, Kali and an isolated vulnerable DMZ target. The full design, resource plan, IP matrix, port policy and dual-output pipeline are documented in the [Enterprise Dual-SIEM VM Lab Runbook](enterprise-dual-siem-vm-lab.md).

## Canonical build order

| Stage | Build activity | Required outcome |
|---:|---|---|
| 0 | [Hardware & Compatibility](requirements.md) | Host capacity, architecture and support verified |
| 1 | [Windows Host Setup](platform-windows.md) | One hypervisor installed; test VM snapshot/restore works |
| 2 | [Network Design](network-design.md) and [Hypervisor Network Implementation](hypervisor-network-implementation.md) | Isolated segments, adapter mapping and capture design proven |
| 3 | [OPNsense Implementation](opnsense-implementation.md) and [Firewall Policy Matrix](firewall-policy-matrix.md) | Routing, DNS, DHCP, NTP and default-deny policy validated |
| 4 | [Operating Systems & Identity](operating-systems.md) | All guest OSs installed inside VMs |
| 5 | AD DS/DNS and DMZ applications | Domain join and isolated targets verified |
| 6 | [Endpoint Telemetry](endpoint-telemetry-implementation.md) | Windows/Linux events exist locally |
| 7 | [Network Monitoring](network-monitoring.md) and [Sensor Implementation](network-sensor-implementation.md) | Packet visibility, Zeek and Suricata events proven |
| 8 | [Syslog Relay](syslog-relay-implementation.md) and [Telemetry Pipeline](telemetry-pipeline.md) | Firewall and sensor events reach the broker |
| 9 | [Elastic SIEM](elastic-siem.md) | Elastic raw event ingestion verified |
| 10 | [Splunk SIEM](splunk-siem.md) | Splunk raw event ingestion verified |
| 11 | Dual-output Vector and endpoint coexistence | Same controlled sources searchable in both SIEMs |
| 12 | [Penetration Testing](penetration-testing.md) and [SOC Exercises](soc-exercises.md) | Controlled detection and investigation validated |
| 13 | Operations and recovery | Backups, retention, health and restore tests documented |

Do not skip gates. A service showing active, an agent showing online, or a successful documentation build does not prove end-to-end telemetry.

## Platform tracks

### Windows x64 PC — primary full build

Choose exactly one hypervisor: VMware Workstation Pro (default Type-2 path), Hyper-V or VirtualBox. Run OPNsense x86-64 as a VM. Deploy x86-64 Windows/Linux/Kali guests and supported x86-64 SIEM components. Keep the WAN NIC on hypervisor NAT; do not bridge REDTEAM or DMZ to home Wi-Fi.

### Apple-silicon Mac — separate ARM64 build

Use VMware Fusion and ARM64 guest images. Use Ubuntu ARM64 with nftables as the router path; OPNsense and Security Onion are not ARM64 guest targets. Do not assume Splunk Enterprise is supported natively on ARM64. Verify Elastic components and every endpoint agent against current support matrices.

### Cross-host operation

Fusion host-only networks and Windows hypervisor private networks are local to their host. They do not automatically form one shared VLAN. Keep two isolated lab islands unless a separate physical VLAN/firewall design is built and reviewed.

## Resource planning

Planning values only; check current vendor requirements and host capacity before deployment.

| Component | Home-lab starting allocation |
|---|---|
| OPNsense VM | 2 vCPU, 4 GB RAM |
| Windows Server AD DS/DNS | 2–4 vCPU, 6–8 GB RAM |
| Windows 11 endpoint | 2–4 vCPU, 6–8 GB RAM |
| Ubuntu Vector broker | 2–4 vCPU, 4–8 GB RAM |
| Elastic single-node learning stack | 4–8 vCPU, 12–16 GB RAM |
| Splunk Enterprise learning stack | 4 vCPU, 8–12 GB RAM |
| Zeek/Suricata sensor | 4–8 vCPU, 8–16 GB RAM |
| Kali | 2–4 vCPU, 4–8 GB RAM |
| DMZ Ubuntu target | 2–4 vCPU, 4 GB RAM |

A 64 GB host should use staged operation and stop idle VMs; simultaneous operation is not guaranteed. 96 GB is more practical and 128 GB preferred for running both SIEMs and all supporting VMs concurrently. Storage needs headroom for indexes, snapshots, PCAP and log retention.

## Data-flow model

- Windows endpoint: Elastic Agent → Elastic; Splunk UF → Splunk, after coexistence and duplicate tests.
- Firewall/router: syslog → Vector broker → Elasticsearch and Splunk HEC.
- Sensor: Zeek/Suricata files → supported agent or broker input → both SIEMs.
- Linux target: local audit/journal → selected supported collection path → both SIEMs.

Vector is not a universal mandatory hop for every endpoint. Kafka and Logstash are not part of the initial design. Port 5044 is not opened unless a Beats input is deliberately deployed.

## Evidence standard

For every stage record host/guest architecture, versions, checksums, VM resources, adapter mapping, IPs/routes, firewall rules, source event, broker receipt, SIEM document, timestamps, expected/actual results, rollback and cleanup. Screenshots labelled as genuine lab evidence must be captured from the actual running VM. Official vendor screenshots and diagrams must be labelled as references or illustrations. Never publish credentials, tokens, private keys, employer logs or customer data.

**Status:** architecture and runbooks are documentation, not proof of hardware execution. Mark a stage lab-tested only after its acceptance gate passes on the target host.
