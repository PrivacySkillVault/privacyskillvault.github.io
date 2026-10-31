# Enterprise dual-SIEM VM lab — architecture and implementation runbook

<badge color="warning">Design baseline — not yet executed on physical host hardware</badge>

This runbook defines the Windows x64 primary build for a segmented, VM-only enterprise-style lab running Elastic Security and Splunk Enterprise side by side. All guest operating systems and security products are installed inside VMs. The Windows host runs only the selected hypervisor and host-management tools. The Apple-silicon Mac is a separate ARM64 learning track, not a shared x86-64 cluster.

This is a controlled home lab, not a production deployment or a claim of vendor-certified production architecture. A single-node Elastic deployment, a single Splunk instance and one Vector relay have no high availability. Enterprise-style describes segmentation, identity, telemetry, detection and operational practices—not production resilience.

## 1. Architecture decisions

1. Use one primary hypervisor on the Windows x64 host. VMware Workstation Pro is the default Type-2 path when retaining Windows as the host. Hyper-V and VirtualBox are alternatives, not components to install together.
2. Use OPNsense x86-64 as the only routed gateway between lab segments.
3. Use separate VMs for AD DS/DNS, Windows endpoint, Elastic, Splunk, Vector broker, network sensor, Kali and DMZ target.
4. Use Vector for firewall/router syslog and selected sensor/file feeds. Do not introduce Kafka or Logstash in the first build. Add a message bus only as a later, measured scaling exercise.
5. Send Windows endpoint events directly to both SIEMs using Elastic Agent and Splunk Universal Forwarder only after verifying support for the exact Windows release and agent versions. Coexistence is not inherently prohibited, but resource use, duplicate collection, driver/EDR interactions and vendor support must be tested.
6. Do not install both agents on every machine by default. Collect each source once per destination and document intentional duplication.
7. Build and validate one SIEM at a time, then enable the dual-output broker. This reduces troubleshooting variables while retaining the final dual-SIEM objective.
8. Security Onion is an optional separate x86-64 platform, not an application installed into the Ubuntu sensor VM. The default sensor is Ubuntu with Zeek and Suricata.

## 2. Host and resource gate

Before creating VMs, record CPU model/architecture, logical processors, physical RAM, free SSD/NVMe space, Windows edition/build and hypervisor version. Confirm firmware virtualization support. Keep VM disks, snapshots and evidence on a fast local SSD; exclude active VM folders from cloud-sync folders.

Planning allocations (adjust after checking current vendor requirements):

| VM | Guest and role | vCPU | RAM | Initial disk |
|---|---|---:|---:|---:|
| fw-perimeter | OPNsense x86-64 | 2 | 4 GB | 20 GB |
| ad-dc01 | Windows Server AD DS/DNS | 2–4 | 6–8 GB | 80 GB |
| win11-wks01 | Windows 11 x64 endpoint | 2–4 | 6–8 GB | 80 GB |
| soc-collector | Ubuntu 24.04 + Vector | 2–4 | 4–8 GB | 50 GB |
| soc-elastic | Ubuntu 24.04 + Elasticsearch/Kibana/Fleet | 4–8 | 12–16 GB | 200 GB |
| soc-splunk | Ubuntu 24.04 + Splunk Enterprise | 4 | 8–12 GB | 150 GB |
| soc-ndr | Ubuntu 24.04 + Zeek/Suricata | 4–8 | 8–16 GB | 100 GB plus PCAP/log capacity |
| dmz-web01 | Ubuntu 24.04 + Nginx/containers | 2–4 | 4 GB | 60 GB |
| kali-red | Kali Linux | 2–4 | 4–8 GB | 80 GB |

These are home-lab planning values, not vendor minimums. Simultaneously running all guests is not realistic on every 64 GB machine. On a 64 GB host, use staged operation, stop idle VMs and avoid full packet capture. 96 GB is more practical; 128 GB is preferred for simultaneous dual-SIEM operation. Keep additional storage headroom for snapshots, indexes, PCAP and log growth. Never allocate all host RAM to guests.

**Gate H:** host capacity, free disk, guest architecture and product support have been recorded. If capacity is inadequate, reduce concurrency or build in stages; do not silently under-allocate a SIEM below its current vendor guidance.

## 3. IP and VM inventory

Use the existing PSV address plan. Check for overlap with the home LAN, VPN, Docker/WSL networks and existing routes before applying it.

| Segment | Subnet | Gateway | Purpose |
|---|---|---|---|
| MGMT | 10.10.10.0/24 | 10.10.10.1 | Admin workstation and management |
| ENDPOINT | 10.10.20.0/24 | 10.10.20.1 | Domain-joined endpoints |
| SERVER/SOC | 10.10.30.0/24 | 10.10.30.1 | AD, broker and SIEM VMs |
| REDTEAM | 10.10.40.0/24 | 10.10.40.1 | Kali; isolated attack source |
| SENSOR-MGMT | 10.10.50.0/24 | 10.10.50.1 | Sensor administration only |
| DMZ | 10.10.60.0/24 | 10.10.60.1 | Vulnerable targets |

| Hostname | Address | Role |
|---|---|---|
| fw-perimeter | .1 on each routed segment | OPNsense gateway; WAN uses hypervisor NAT |
| ad-dc01 | 10.10.30.10 | AD DS/DNS; lab domain such as lab.psv.test |
| soc-collector | 10.10.30.30 | Vector broker and optional local rsyslog |
| soc-elastic | 10.10.30.20 | Elasticsearch, Kibana, Fleet Server |
| soc-splunk | 10.10.30.21 | Splunk Enterprise |
| soc-ndr | 10.10.50.10 | Sensor management NIC; capture NIC has no IP |
| win11-wks01 | 10.10.20.20 | Windows endpoint |
| dmz-web01 | 10.10.60.20 | Nginx and intentionally vulnerable applications |
| kali-red | 10.10.40.10 | Scoped red-team VM |

Use static addressing or DHCP reservations for infrastructure. Configure the actual hostname and DNS records before issuing certificates or enrolling agents. Do not reuse the same subnet/IP plan for multiple simultaneously connected lab islands.

## 4. Port and flow matrix

This is a starting allowlist, not a blanket instruction to open every port from every segment. Firewall rules must identify source, destination, protocol, port, direction and purpose.

| Source | Destination | Port/protocol | Purpose |
|---|---|---|---|
| Lab guests | Approved DNS server | TCP/UDP 53 | DNS |
| Lab guests | Approved NTP source | UDP 123 | Time |
| Domain endpoints | ad-dc01 | DNS 53, Kerberos 88, LDAP 389/636 as configured, SMB 445, RPC endpoint mapper 135 and required dynamic RPC range | AD; use Microsoft's current port guidance and validate actual roles |
| Firewall | soc-collector | TCP 514 for the documented isolated-lab rsyslog baseline; use TCP 6514 only after a TLS listener and matching sender trust are configured | Firewall logs |
| Sensor | soc-collector | TCP 514 or a separately documented file/agent path | Sensor/host logs |
| Windows endpoints | soc-elastic | TCP 8220 to Fleet Server; TCP 9200 only if the configured Agent output requires direct Elasticsearch | Elastic Agent |
| Windows endpoints | soc-splunk | TCP 9997 | Splunk UF forwarding |
| soc-collector | soc-elastic | TCP 9200 with TLS/auth | Elasticsearch API/bulk ingest |
| soc-collector | soc-splunk | TCP 8088 with TLS/HEC token | Splunk HEC |
| Admin workstation | SIEM UIs | TCP 5601 and 8000, restricted to MGMT | Kibana and Splunk Web |

Important:
- TCP 5044 is commonly a Logstash Beats input. It is not a generic Vector input port. Do not open it unless a Beats input is actually configured.
- Kafka 9092 is not part of the initial design.
- Splunk TCP/9997 is for forwarders; HEC TCP/8088 is for HTTP event submission. Do not interchange them.
- Fleet Server TCP/8220 is not the Elasticsearch API.
- Do not expose Elasticsearch 9200, Splunk 9997/8088, Fleet 8220 or management UIs to WAN.
- Use TLS and certificate validation on inter-VM paths where supported. Plain TCP syslog is acceptable only as a documented isolated-lab exercise with strict source allowlisting; it is not encrypted or authenticated.

## 5. Hypervisor and virtual network build

Follow [Windows Host Setup](platform-windows.md) and [Hypervisor Network Implementation](hypervisor-network-implementation.md). Create one isolated virtual network per segment plus a NAT-backed WAN network for the OPNsense WAN NIC. The firewall is the only VM with a WAN adapter. Do not bridge REDTEAM or DMZ to the physical home LAN.

For Hyper-V, use Private switches for VM-only segments and a deliberately configured NAT/management path for firewall WAN. For VMware Workstation, use host-only networks for internal segments and NAT for firewall WAN. For VirtualBox, use named Internal Networks or Host-only networks as appropriate. The UI names and adapter behavior differ by release; record the actual network names and VM adapter MAC addresses.

### Sensor visibility

A capture NIC connected to a normal virtual switch does not automatically see other VMs' unicast traffic. Configure and verify an actual mirror/port-mirroring feature supported by the selected hypervisor and switch topology. Hyper-V port mirroring requires correctly configured source and destination adapters on the relevant virtual switch. Do not claim that promiscuous mode alone creates a SPAN feed. If the chosen hypervisor cannot mirror the desired traffic, use an explicitly documented inline sensor design or replay a PCAP for detection exercises.

The sensor's management NIC has 10.10.50.10/24. The capture NIC has no IP address, no default gateway and no DNS registration. Disable offloads only when required by the selected capture method and NIC driver; validate with packet counters and test traffic rather than assuming every offload causes missed detections.

**Gate N:** prove guest-to-gateway routing, allowed and denied inter-segment flows, no Kali/DMZ access to home LAN, and actual packet visibility on the sensor capture NIC.

## 6. Firewall policy model

Start with default-deny between internal segments. Add only specific flows required by the current stage.

- MGMT → firewall/VM management: named admin source IPs and required ports only.
- ENDPOINT → AD: documented AD/DNS/RPC services to ad-dc01 only.
- Lab guests → DNS/NTP: designated services only.
- Firewall → broker: configured syslog transport only.
- Sensor/relay/endpoints → SIEM: exact agent/forwarding destinations and ports only.
- Broker → Elastic: TCP/9200 with TLS and credentials.
- Broker → Splunk: TCP/8088 with TLS and HEC token.
- REDTEAM → DMZ: only the target addresses/ports in the active exercise scope.
- DMZ → MGMT, ENDPOINT and SOC: deny by default. Permit only a deliberate, logged telemetry egress flow if required.
- REDTEAM → home LAN and host management: deny.
- WAN → internal networks: deny unsolicited inbound. No WAN port forwards to vulnerable applications.

Log both pass and block rules used in validation. Keep update egress temporary and limited to the relevant guests. Re-test isolation after changing virtual adapters or firewall rules.

## 7. Guest OS installation baseline

Install from official vendor images and verify published checksums/signatures where available. For every VM:
1. Create the VM with planned firmware, CPU, RAM, disk and NICs.
2. Attach only the intended virtual networks.
3. Mount the verified installation ISO.
4. Install the OS to the virtual disk.
5. Set hostname before joining a domain or issuing certificates.
6. Apply updates during the approved update window.
7. Configure static IP, subnet, gateway, DNS and NTP.
8. Verify Linux networking with ip -br address, ip route, resolvectl status and timedatectl. Verify Windows with Get-NetIPConfiguration, Get-DnsClientServerAddress and w32tm /query /status.
9. Confirm only intended routes and DNS resolution.
10. Install guest tools only from the selected hypervisor's official distribution.
11. Take a clean OS snapshot and record version/build and VM adapter MACs.

Use the existing PSV OS runbooks for exact Windows Server, Windows 11, Ubuntu and Kali installation screens and post-installation steps. Do not install SIEM software on the Windows host.

## 8. Active Directory and target application

Use a private lab-only domain such as lab.psv.test; do not use a real public domain you do not control. Install AD DS and DNS on ad-dc01, promote it, configure forwarders deliberately, create test OUs/users/groups, and join win11-wks01 after DNS points to the DC. Confirm domain authentication and time synchronization.

Do not create an SPN for a service that does not exist. For Kerberoasting exercises, deploy a separate member server and a deliberately configured lab service account/SPN, then verify the resulting ticket events. A Domain Controller is not automatically an SQL server.

On dmz-web01, install Docker Engine using the current official Ubuntu instructions, install the Compose plugin if needed, then deploy Nginx and intentionally vulnerable applications using pinned image tags. Bind/allow them only on the DMZ interface. Do not publish these ports to the physical WAN or home router. Take a snapshot before introducing vulnerable containers.

## 9. Endpoint telemetry before SIEM enrollment

Follow [Endpoint Telemetry Implementation](endpoint-telemetry-implementation.md). On Windows, enable only the required Advanced Audit Policy categories and command-line process auditing where needed; install Microsoft Sysmon from the official Sysinternals source and verify the signature. Prove Security 4688, the chosen account/group event and Sysmon Event ID 1 locally.

On Linux, configure auditd/journald sources and verify records locally. On the sensor, verify Zeek logs and Suricata EVE JSON locally. A file's existence does not prove the sensor can see packets; generate a known DNS/HTTP flow and verify counters/logs.

Do not install agents until local source events exist. Record event timestamp, hostname, event ID/dataset and the command/action that generated the event.

## 10. Elastic installation and validation

Use the [Elastic SIEM guide](elastic-siem.md) and current Elastic installation documentation. Pin one exact compatible release for Elasticsearch, Kibana, Fleet Server and Elastic Agent; do not use an unqualified floating version. Verify Ubuntu release and CPU architecture support.

High-level order:
1. Prepare soc-elastic static address, hostname, DNS and NTP.
2. Configure Elasticsearch host prerequisites using the current selected-release documentation. Set vm.max_map_count to the current documented requirement; do not copy an old value blindly. Configure swap deliberately rather than treating swapoff as a universal startup fix.
3. Install Elasticsearch from the official signed APT repository and verify service health locally.
4. Secure Elasticsearch; retain the generated CA and credentials securely. Do not publish private keys, passwords, enrollment tokens or CA private material.
5. Install matching Kibana and configure its connection to Elasticsearch.
6. Access Kibana only from MGMT; verify health and authentication.
7. Configure Fleet Server URL using a DNS name where possible. The certificate SAN must match the exact hostname/IP agents use. If agents connect by IP, the certificate must include that IP as an IP SAN. Do not assume the Elasticsearch HTTP CA certificate is automatically the correct Fleet Server certificate.
8. Install Fleet Server using the official command generated by the selected Kibana version. Confirm TLS validation and agent enrollment from a test endpoint.
9. Create separate endpoint and Linux policies. Add Windows/Sysmon, System and supported custom-log integrations only as required.
10. Verify a known raw event in Discover, including @timestamp, host.name, dataset and original event fields.

A green Fleet status does not prove that every integration is collecting events. Check integration diagnostics and raw documents.

## 11. Splunk installation and validation

Use the [Splunk SIEM guide](splunk-siem.md) and current Splunk Enterprise installation documentation. Pin an exact release and confirm Ubuntu x86-64 support for that release before downloading.

High-level order:
1. Prepare soc-splunk static address, hostname, DNS and NTP.
2. Download the official x86-64 Debian package and verify its published integrity information.
3. Install the package inside the VM; start Splunk and create a unique admin credential.
4. Enable boot-start using the documented service account procedure for the chosen release. Do not claim the service runs as a dedicated splunk user unless that account was created and the install method configured it.
5. Create only the required indexes: psv_windows, psv_firewall, psv_network, psv_linux and psv_web as needed. Set retention and storage limits.
6. Enable the TCP receiving port (default 9997) for approved forwarders only.
7. Enable HEC on 8088 with TLS; create a narrowly scoped HEC token restricted to intended indexes.
8. Install only the add-ons needed by the data sources. Distinguish search-time knowledge objects from parsing/index-time components; add-ons are not a magic prerequisite for all raw event ingestion.
9. Install/configure Universal Forwarder on a test endpoint only after checking OS/architecture support. Use Windows Event Log inputs on Windows and file monitors on Linux; do not reuse a Windows inputs.conf stanza on Linux.
10. Verify receiver health and search for the controlled event in the expected index and sourcetype. Inspect raw events before writing field-dependent SPL.

Do not enable HEC SSL by merely ticking a UI box and assume the certificate is trusted. Install and validate the certificate chain and hostname from the broker.

## 12. Vector dual-output broker

Use Vector as the initial broker on soc-collector. Follow the official Vector installation instructions for Ubuntu 24.04 and pin the selected package version. Do not add Kafka or Logstash unless measured throughput, buffering or routing requirements justify the added services.

Design the broker inputs explicitly:
- Firewall syslog listener: use TCP/TLS where supported and bind to the SERVER-facing address only. Use a separate UDP listener only if the sender is configured for UDP and the loss characteristics are accepted.
- Sensor and Linux file inputs: read only actual local files, with correct permissions, file rotation handling and JSON decoding for newline-delimited JSON sources.
- Do not open TCP/5044 unless a Beats protocol input is explicitly configured.

Configure two independent sinks:
- Elasticsearch output to https://10.10.30.20:9200, using certificate validation and a least-privilege credential. Route to a deliberate index/data-stream naming convention and verify ECS mappings before claiming ECS normalization.
- Splunk HEC output to https://10.10.30.21:8088, using a dedicated HEC token, intended index and explicit sourcetype.

Use Vector's documented syslog source, elasticsearch sink and splunk_hec sink schemas for the exact pinned release. Store secrets in protected environment/secret files, not in a public repository or shell history. Validate configuration with the installed vector validate command, run the service, inspect logs and monitor internal component errors/queue metrics. Configure disk buffering only after selecting and sizing the data directory; set a maximum disk budget and define backpressure behavior.

Do not silently drop one output when the other is unavailable. Test the failure mode: stop one SIEM temporarily, confirm broker retry/buffer behavior, restart the SIEM, and verify delivery without unacceptable duplicates or loss. Record measured delay; do not promise a universal two-second delivery SLA.

## 13. Endpoint co-existence and duplicate control

For Windows x64, Elastic Agent and Splunk UF may be installed side by side if the exact versions and host are supported. Start with a disposable endpoint snapshot:
1. Install and enroll Elastic Agent.
2. Verify one known Security and one Sysmon event in Elastic.
3. Install Splunk UF.
4. Configure the receiver and only the required Event Log channels.
5. Verify the same controlled events in Splunk.
6. Check CPU, RAM, disk I/O, event latency and agent health.
7. Check for duplicates within each SIEM. Duplicate ingestion can occur if the same source is also monitored by the broker or another agent.
8. Test service restart and host reboot.
9. Document exclusions and rollback.

Do not enable Elastic Defend and another EDR/endpoint driver blindly. Begin with supported telemetry integrations; add endpoint prevention/EDR only after vendor compatibility and exclusions are reviewed. Do not make blanket kernel/ETW conflict claims without evidence for the exact products.

## 14. Network sensor implementation

The default sensor is Ubuntu Server x86-64 with two adapters: management on SENSOR-MGMT and a dedicated capture adapter with no IP. Install Zeek and Suricata from supported repositories/releases after verifying OS compatibility. Configure Suricata EVE JSON and explicitly enable Zeek JSON logs if JSON ingestion is intended. Configure service capture on the capture NIC and verify interface counters, packet capture and expected DNS/HTTP records.

Do not state that promiscuous mode alone creates a mirror. Confirm the hypervisor's actual mirroring feature or use a supported offline PCAP workflow. Disable NIC offloads only where required and verify the effect. Forward sensor logs to the broker through the management network; do not route capture traffic through the sensor.

Security Onion is a separate optional deployment. Check its current hardware and x86-64 requirements; do not install it as an Ubuntu package or run it on Apple Silicon ARM64.

## 15. End-to-end validation

Use a unique test identifier and capture source-side evidence before searching either SIEM.

| Test | Controlled action | Expected source proof | Expected SIEM proof |
|---|---|---|---|
| Firewall deny | Kali attempts an explicitly denied DMZ/SERVER port | OPNsense rule log with source, destination and action | Same event in Elastic and Splunk |
| Firewall allow | Kali accesses one allowed DMZ service | OPNsense pass log | Same event in both SIEMs |
| Suricata | Generate traffic matching a deliberately installed and tested local rule | EVE JSON alert with signature ID | Alert in both SIEMs |
| Zeek | Generate DNS and HTTP traffic across mirrored path | Zeek dns/conn/http record | Records in both SIEMs |
| Linux audit | Access a dedicated watched test file | ausearch returns matching key | Record in both SIEMs |
| Windows process | Launch a benign process | Local Security 4688 and Sysmon 1 where configured | Record in both SIEMs |
| AD service ticket | Request a ticket for the deliberately configured lab SPN | DC Security event with observed ticket fields | Record and detection in both SIEMs |

A custom User-Agent does not automatically trigger a Suricata alert. A file read does not automatically appear in auditd without a matching rule. whoami /priv is not a Kerberoasting or lateral-movement test. Build and validate the detection rule before using an action as an alert test.

For each test record source event time, relay receipt time, SIEM ingest time, host identity, raw event, query, detection version, expected/actual result and cleanup. Measure latency from timestamps; do not assert a fixed sub-three-second SLA until measured on the actual host.

## 16. Rollback, recovery and evidence

Before each major stage:
- Take a VM snapshot and export the relevant configuration.
- Record the snapshot name, date, VM version and current IP/NIC mapping.
- Back up OPNsense configuration, AD system state as appropriate, SIEM configuration and broker configuration separately.
- Never put secrets, enrollment tokens, private keys, real customer data or employer logs in GitHub or screenshots.
- Keep raw evidence on the lab host; publish only sanitized screenshots and synthetic data.
- Restore-test snapshots and configuration backups. A snapshot is not a substitute for an independent backup.

## 17. Apple-silicon Mac track

The Mac track remains a separate ARM64 lab island using VMware Fusion and ARM64 guests. Use the existing Ubuntu ARM64 router/nftables runbook rather than OPNsense. Do not assume Splunk Enterprise or Security Onion can run natively as ARM64 guests. Elastic ARM64 support is component- and OS-version-specific; verify each package and integration. Do not join Mac and Windows virtual switches into one network without a separate physical VLAN/firewall design.

## 18. Completion status

This document is a reviewed design and implementation plan. It is not evidence that the VMs have been installed or that the full data path has been hardware-tested. Mark a stage implemented only after its acceptance gate passes on the actual host. Mark screenshots genuine lab evidence only when captured from the actual running VM; official vendor screenshots and diagrams must be labelled as references/illustrations.

## References

- [PSV Master Build Sequence](build-sequence.md)
- [PSV Network Design](network-design.md)
- [PSV Hypervisor Network Implementation](hypervisor-network-implementation.md)
- [PSV OPNsense Implementation](opnsense-implementation.md)
- [PSV Endpoint Telemetry Implementation](endpoint-telemetry-implementation.md)
- [PSV Syslog Relay Implementation](syslog-relay-implementation.md)
- [PSV SIEM Collector Implementation](siem-collector-implementation.md)
- [Elastic Support Matrix](https://www.elastic.co/support/matrix)
- [Elastic installation and Fleet documentation](https://www.elastic.co/guide/index.html)
- [Splunk platform requirements](https://docs.splunk.com/Documentation/Splunk/latest/Installation/Systemrequirements)
- [Splunk Universal Forwarder documentation](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Installtheuniversalforwarder)
- [Vector documentation](https://vector.dev/docs/)
- [Microsoft AD DS service ports](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
- [OPNsense documentation](https://docs.opnsense.org/)
- [Security Onion hardware requirements](https://docs.securityonion.net/en/2.4/hardware.html)
