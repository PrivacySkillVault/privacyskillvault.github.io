# Master build sequence — enterprise dual-SIEM VM lab

<badge color="warning">Canonical dependency order — design baseline, not yet hardware-tested</badge>

This sequence builds the Windows x64 enterprise-style lab entirely inside VMs. The Windows host runs the selected hypervisor and management tools only. Follow the [Enterprise Dual-SIEM VM Lab Runbook](enterprise-dual-siem-vm-lab.md) for the architecture, IP plan, port matrix, policy model, deployment details and validation criteria.

## Stage 0 — host capacity and compatibility

1. Complete [Hardware & Compatibility](requirements.md).
2. Record CPU architecture/model, host OS/build, physical RAM, free SSD/NVMe capacity and hypervisor version.
3. Confirm firmware virtualization support and Windows edition compatibility.
4. Choose exactly one primary hypervisor.
5. Check every guest and product against its current OS/architecture support matrix.
6. Decide whether the Apple-silicon Mac remains a separate ARM64 lab island.

**Gate 0:** capacity and architecture are known. Do not plan simultaneous execution of all VMs on a host that cannot support their combined memory and storage requirements.

## Stage 1 — hypervisor installation and test VM

Follow [Windows Host Setup](platform-windows.md) and the selected hypervisor guide.

1. Install the hypervisor from its official source.
2. Create VM, ISO, export, evidence and backup folders on local SSD.
3. Download official guest images and verify checksums/signatures where published.
4. Create one small test VM of the intended guest architecture.
5. Verify boot, network behavior and time.
6. Snapshot, restore and boot again.

**Gate 1:** host reboot does not break the hypervisor; test guest boots/restores; no guest is bridged to the physical LAN unintentionally.

## Stage 2 — virtual networks and sensor visibility

Follow [Network Design](network-design.md) and [Hypervisor Network Implementation](hypervisor-network-implementation.md). Use the six PSV segments: MGMT, ENDPOINT, SERVER/SOC, REDTEAM, SENSOR-MGMT and DMZ, plus a NAT-backed WAN for the firewall.

Create and verify actual virtual networks before attaching guests. Record adapter number, switch name, MAC, subnet and role. A capture NIC must be connected to a proven mirror/tap or an explicit offline PCAP workflow; promiscuous mode alone is not proof of packet mirroring.

**Gate 2:** no subnet overlap, DHCP collision, unintended bridge or unverified capture path. REDTEAM and DMZ cannot reach the home LAN.

## Stage 3 — firewall, DNS, DHCP, NTP and segmentation

Follow [OPNsense Implementation](opnsense-implementation.md), [Firewall Policy Matrix](firewall-policy-matrix.md), and the separate [Mac ARM Router Implementation](mac-arm-router-implementation.md) only for the Mac track.

1. Install OPNsense x86-64 as a VM on the Windows x64 track.
2. Attach WAN to hypervisor NAT and each internal interface to its intended private segment.
3. Identify interfaces by MAC address; do not assume adapter order.
4. Configure gateway addresses and static/reserved infrastructure addressing.
5. Configure DNS/DHCP/NTP deliberately.
6. Apply default-deny inter-segment rules and narrow AD, management, telemetry and update flows.
7. Enable logging on validation rules.

**Gate 3:** test permitted and denied TCP flows, DNS, NTP, routes and firewall logs. Kali/DMZ must not reach host management or home LAN.

## Stage 4 — install guest operating systems

Follow [Operating Systems & Identity](operating-systems.md) and the detailed dual-SIEM runbook.

Deploy the firewall, domain controller, Windows endpoint, collector, Elastic, Splunk, sensor, DMZ target and Kali VMs. Install OSs only inside their respective VMs. Set hostnames before domain join/certificate generation. Configure static addressing, DNS, NTP, guest tools and clean snapshots.

**Gate 4:** every VM has the expected OS/build/architecture, IP, route, DNS, time and NIC mapping.

## Stage 5 — identity and target applications

1. Promote the Windows Server VM to AD DS/DNS for a private lab-only domain.
2. Configure DNS forwarders and test records.
3. Create lab OUs, users and groups.
4. Join the Windows endpoint after DNS points to the DC.
5. Configure a separate member server/service for Kerberoasting exercises; do not invent an SPN for a service that does not exist.
6. Deploy Nginx and deliberately vulnerable applications in the isolated DMZ. Do not publish vulnerable services to the physical WAN.

**Gate 5:** domain authentication works; target applications are reachable only from authorized lab segments.

## Stage 6 — local endpoint telemetry

Follow [Windows Endpoint Telemetry](windows-endpoint-telemetry.md) and [Cross-platform Endpoint Telemetry Implementation](endpoint-telemetry-implementation.md).

Configure Windows Advanced Audit Policy and Sysmon, Linux auditd/journald, and required sensor logs. Verify known events locally before installing agents.

**Gate 6:** each source event exists locally with timestamp, host identity and event/channel details.

## Stage 7 — firewall and network monitoring

Follow [Network Monitoring](network-monitoring.md) and [Zeek & Suricata Sensor Implementation](network-sensor-implementation.md).

1. Enable and verify firewall pass/block logging.
2. Prove packet visibility on the sensor capture NIC.
3. Configure Suricata EVE JSON and Zeek logs.
4. Generate known DNS/HTTP traffic and verify local sensor output.
5. Record exactly which segments and directions the sensor can observe.

**Gate 7:** known packet flows are visible and local firewall/Suricata/Zeek records exist. If mirror visibility is unavailable, use documented PCAP replay; do not claim live network monitoring.

## Stage 8 — syslog and broker foundation

Follow [Syslog Relay Implementation](syslog-relay-implementation.md), [Telemetry Pipeline](telemetry-pipeline.md) and the [Enterprise Dual-SIEM VM Lab Runbook](enterprise-dual-siem-vm-lab.md).

1. Configure firewall/router syslog to the broker/relay.
2. Install Vector using a pinned supported release.
3. Configure source-specific inputs, file permissions, rotation, timestamps and bounded buffering.
4. Validate Vector configuration and one test event.
5. Do not open 5044 unless a Beats input is actually configured.
6. Do not deploy Kafka in the initial build.

**Gate 8:** a unique test event arrives at the broker with correct sender identity and timestamp. Queue, disk and retry behavior are understood.

## Stage 9 — Elastic deployment

Follow [Elastic SIEM](elastic-siem.md). Install Elasticsearch, Kibana and Fleet Server on the dedicated VM using one exact compatible release. Configure trusted certificates with correct DNS/IP SANs. Enroll one test endpoint and prove a raw event in Discover.

**Gate 9:** raw events and required fields are searchable; Fleet health alone is insufficient.

## Stage 10 — Splunk deployment

Follow [Splunk SIEM](splunk-siem.md). Install Splunk Enterprise on the supported x86-64 VM, create intended indexes, configure TCP/9997 receiving and HTTPS HEC/8088. Install required add-ons according to their actual search-time/index-time roles. Verify a raw event in the correct index.

**Gate 10:** a known event is searchable with correct host, source, sourcetype and timestamp.

## Stage 11 — dual-output and endpoint coexistence

Configure Vector outputs to Elasticsearch and Splunk HEC with TLS, least-privilege credentials, explicit index/dataset mapping and bounded retry/buffering. Test each output independently, then simulate one destination being unavailable.

On a disposable Windows endpoint, enroll Elastic Agent first, verify data, then install Splunk UF and verify the same test event in Splunk. Measure resource use, latency and duplicates. Do not install both agents on every VM by default.

**Gate 11:** the same unique source event is present in both SIEMs without unexplained gaps or duplicates. Failure/recovery behavior is measured, not assumed.

## Stage 12 — controlled purple-team validation

Follow [Penetration Testing](penetration-testing.md) and [SOC Validation Exercises](soc-exercises.md). Use only lab-owned targets and explicit scope. Validate firewall, IDS, Zeek, Windows, Linux and AD detections. A custom User-Agent does not automatically trigger Suricata; auditd requires matching rules; event IDs are not guaranteed unless source policy and test behavior are configured.

**Gate 12:** each exercise has source evidence, SIEM raw event, query/rule, alert result, timestamp comparison and cleanup record in both SIEMs where applicable.

## Stage 13 — operations and recovery

Back up firewall, AD, SIEM and broker configurations separately from VM snapshots. Document retention, disk limits, updates, credentials, agent health, restore procedures and evidence sanitization. Re-test segmentation after hypervisor or NIC changes.

## Apple-silicon Mac track

Keep the Mac as a separate ARM64 lab island using VMware Fusion and ARM64 guests. Use the Ubuntu ARM64/nftables router path, not OPNsense. Do not assume Splunk Enterprise or Security Onion is supported as an ARM64 guest. Verify every agent and integration against the exact support matrix.

## Stop conditions

Stop if an unsupported guest/product is selected, a VM is unexpectedly bridged, REDTEAM/DMZ can reach home LAN, DNS/time is incorrect, source events are absent, packet visibility is unproven, broker queues are unbounded, certificates do not validate, or either SIEM cannot ingest the controlled event. Do not bypass a failed gate by disabling security controls.
