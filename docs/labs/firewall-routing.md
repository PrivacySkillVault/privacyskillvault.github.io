# Lab — Firewall, routing, IDS and firewall-log generation

<badge color="warning">Mandatory before telemetry forwarding — reference guide, not yet hardware-tested</badge>

This page is the Windows x64 OPNsense implementation. For an Apple-silicon Mac-only build use [Mac ARM Router & Firewall](mac-arm-routing.md). OPNsense supports x86-64, not ARM64.

## 1. Windows OPNsense topology

Create one x86-64 OPNsense VM with seven adapters (WAN plus six internal segments):

| Role | Network | Address |
|---|---|---|
| WAN | Hypervisor NAT only | DHCP from hypervisor NAT |
| MGMT | Internal/host-only | 10.10.10.1/24 |
| ENDPOINT | Private/host-only | 10.10.20.1/24 |
| SERVER | Private/host-only | 10.10.30.1/24 |
| REDTEAM | Private/host-only | 10.10.40.1/24 |
| DMZ | Private/host-only | 10.10.60.1/24 |

The SENSOR capture path is separate. Do not assume a routed SENSOR interface receives copies of all packets. Use OPNsense IDS on relevant routed interfaces or a separately verified mirror/tap for Zeek.

## 2. Create the firewall VM

On Windows x64 use the selected hypervisor. Starting allocation: 2–4 vCPU, 4 GB RAM and 20 GB disk. OPNsense recommends at least 4 GB RAM and an 8 GB virtual disk for virtual installation; allocate more for IDS/log retention.

- Hyper-V: create Generation 2 VM; follow current OPNsense Hyper-V notes for Secure Boot. Add six internal NICs plus the WAN NIC and attach each to its intended switch.
- VMware Workstation: add six NICs; WAN on NAT, internal roles on separate host-only networks.
- VirtualBox: follow [VirtualBox Host Setup](platform-virtualbox.md); WAN on NAT, MGMT host-only, remaining segments named Internal Networks.

Record every virtual NIC MAC before boot. At OPNsense console map roles by MAC and link state. Adapter number is not a reliable interface identifier.

## 3. Install OPNsense

1. Download the current x86-64 DVD ISO from the official OPNsense site and verify its checksum.
2. Boot and follow the current official installer. Installation erases the selected virtual disk.
3. Set a strong unique administrative password.
4. Reboot and detach the ISO.
5. Assign WAN and internal interfaces using the MAC mapping.
6. Configure WAN by DHCP from hypervisor NAT and internal addresses from the topology table.
7. From MGMT, open the OPNsense HTTPS UI. Do not expose GUI/SSH on WAN.

## 4. DNS, DHCP and time

1. Configure Unbound DNS to listen only on required internal interfaces.
2. Create DHCP scopes only for client networks; keep DC, relay and SIEM static/reserved.
3. Do not run a second DHCP service on the same segment.
4. Use a consistent time source/timezone for all guests.
5. For AD DS, domain clients use the domain controller for DNS; configure upstream resolution deliberately.

For the exact source/destination/port matrix, including AD DS dependencies and the selected SIEM's common receiver ports, use the [Firewall Policy Matrix](firewall-policy-matrix.md). The table is a design aid: enable only the rows required by the chosen services and verify every rule.

## 5. Least-privilege policy

Retain a safe management path and console access before narrowing rules.

- MGMT: allow only named admin workstation to firewall and server management ports.
- ENDPOINT: allow DNS/NTP, required AD DS traffic to DC, and later telemetry to relay/SIEM on explicit ports.
- SERVER: allow management from MGMT, required endpoint-to-server services and relay-to-SIEM forwarding.
- REDTEAM: allow Kali only to the written target IP/ports in DMZ; deny home LAN, MGMT and unrelated destinations.
- DMZ: allow only target service ports; deny initiation to MGMT, SERVER, ENDPOINT and home LAN.
- WAN: no inbound management. Update egress is temporary and controlled.

Do not guess Active Directory ports. Use Microsoft's current port documentation and test the exact services enabled, including dynamic RPC.

## 6. Generate firewall logs

OPNsense does not necessarily log every pass rule by default. Edit the specific firewall rules used for allow/deny exercises and enable the rule's Log option.

1. Generate a known allowed connection, such as endpoint DNS to the lab resolver.
2. Generate a known denied connection, such as REDTEAM to a prohibited MGMT address.
3. Open the live firewall log and verify source, destination, port, interface, rule/action and timestamp.
4. Save sanitised evidence.

If a rule is not logged, inspect its Log setting and live-log filters before concluding enforcement failed.

## 7. Enable Suricata IDS in alert-only mode

OPNsense Intrusion Detection is based on Suricata. Start with IDS/alert-only; do not begin with inline IPS blocking.

1. Open Services → Intrusion Detection.
2. Enable the service and select the internal interfaces carrying traffic of interest. WAN-only capture may show NAT-translated addresses.
3. Set HOME_NET to the lab subnets actually protected.
4. Enable a reviewed ruleset such as ET Open and understand its licence/update process.
5. Update rules and check service health.
6. Generate controlled test traffic and verify the service processes packets and produces the expected alert when the selected rule matches.
7. Confirm the alert in the OPNsense IDS view and local log.

OPNsense offers different capture modes and driver requirements. IDS is the safer initial mode. IPS/netmap can interrupt traffic and may require disabling hardware offloads; do not enable IPS until exact release, NIC driver and recovery access are validated.

## 8. Enable EVE/syslog for later forwarding

1. Enable EVE syslog output in Intrusion Detection if available in the installed release.
2. In System → Settings → Logging → Remote, add the Linux relay destination.
3. Select Suricata/application filters where the UI provides them and choose the transport/port configured on the relay.
4. Apply changes.
5. Generate a known IDS event and confirm it reaches the relay.

Follow [Telemetry Collection & Forwarding](telemetry-pipeline.md) for the complete relay and SIEM collector setup. Do not install a SIEM before the source-to-relay test passes.

## 9. Validation and backup

- [ ] NIC roles mapped by MAC.
- [ ] Internal addresses, DHCP and DNS correct.
- [ ] Broad allow rules narrowed.
- [ ] Allowed and denied flows visible in firewall logs.
- [ ] REDTEAM/DMZ cannot reach home LAN or MGMT.
- [ ] Suricata IDS sees intended internal traffic.
- [ ] EVE/syslog test event reaches relay.
- [ ] Encrypted configuration backup exported outside the VM.

If isolation fails, disconnect Kali and DMZ guests and correct the network/firewall mapping before continuing.

## References

- [OPNsense hardware and architecture support](https://docs.opnsense.org/manual/hardware.html)
- [OPNsense virtual installation](https://docs.opnsense.org/manual/virtuals.html)
- [OPNsense interface assignments](https://docs.opnsense.org/manual/interfaces.html)
- [OPNsense firewall rules](https://docs.opnsense.org/manual/firewall.html)
- [OPNsense IDS/IPS and Suricata](https://docs.opnsense.org/manual/ips.html)
- [OPNsense remote logging](https://docs.opnsense.org/manual/settingsmenu.html)
