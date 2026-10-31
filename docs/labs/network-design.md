# Lab — network design and segmentation

<badge color="warning">Architecture baseline — validate on the selected hypervisor</badge>

This page defines the logical networks for the Windows x64 primary lab. Follow the [Enterprise Dual-SIEM VM Lab Runbook](enterprise-dual-siem-vm-lab.md) and [Master Build Sequence](build-sequence.md). The Mac ARM64 implementation is a separate lab island.

## 1. Logical segments and example address plan

Check for overlap with home LAN, VPN, Docker/WSL networks and existing routes before use.

| Segment | Subnet | Purpose | Gateway |
|---|---|---|---|
| MGMT | 10.10.10.0/24 | Admin workstation and management interfaces | 10.10.10.1 |
| ENDPOINT | 10.10.20.0/24 | Windows/Linux test endpoints | 10.10.20.1 |
| SERVER/SOC | 10.10.30.0/24 | AD DS/DNS, broker, Elastic and Splunk | 10.10.30.1 |
| REDTEAM | 10.10.40.0/24 | Kali and scoped assessment source | 10.10.40.1 |
| SENSOR-MGMT | 10.10.50.0/24 | Sensor administration only | 10.10.50.1 |
| DMZ | 10.10.60.0/24 | Vulnerable targets | 10.10.60.1 |

Suggested addresses: AD/DNS 10.10.30.10; Elastic 10.10.30.20; Splunk 10.10.30.21; Vector broker 10.10.30.30; sensor management 10.10.50.10; Windows endpoint 10.10.20.20; Kali 10.10.40.10; DMZ target 10.10.60.20. The firewall uses .1 on each routed segment. Its WAN adapter connects to hypervisor NAT, not the REDTEAM subnet.

A sensor has a management NIC with an address on SENSOR-MGMT and one or more separate capture NICs with no IP, gateway, DNS registration or forwarding. Capture NICs receive traffic only through a verified virtual switch mirror, physical SPAN/TAP, deliberately designed inline path or offline PCAP. SENSOR-MGMT is not the capture network.

## 2. Windows x64 hypervisor implementation

Choose exactly one hypervisor and record actual switch names.

- **Hyper-V:** use an Internal switch for host management only where required and Private switches for VM-only segments. Configure the firewall WAN path deliberately using documented NAT; do not attach Kali/DMZ to an External switch. Port mirroring requires source and destination adapter roles configured on the relevant virtual switch.
- **VMware Workstation:** use host-only networks for isolated segments and NAT only for the firewall WAN/update path. Do not use Bridged for REDTEAM or DMZ. Do not assume promiscuous mode is equivalent to SPAN.
- **VirtualBox:** use named Internal Networks for VM-only segments and Host-only only where host access is intended. Use NAT for the firewall WAN. Promiscuous mode is not a universal packet mirror.

See [Hypervisor Network Implementation](hypervisor-network-implementation.md) for commands and verification. Record adapter number, switch/network name, MAC, subnet, IP settings, role and whether the adapter is management or capture-only.

## 3. Apple-silicon Mac implementation

Use ARM64 guests and keep the Mac lab separate. Fusion NAT, Host-only and custom networks are distinct and are not automatically connected to Windows hypervisor switches. Use the [Mac ARM Router & Firewall](mac-arm-routing.md) and its implementation runbook with Ubuntu ARM64/nftables. If the installed Fusion version cannot provide enough isolated networks, stop rather than collapsing the topology into one network.

## 4. Minimum inter-segment policy

Start with default-deny and add only flows required by the current stage.

| Source | Destination | Purpose | Policy |
|---|---|---|---|
| MGMT | Firewall/VM management | Administration | Named admin IPs and required ports only |
| ENDPOINT | AD/DNS server | Domain services | Documented AD ports to DC only, including required RPC |
| Lab hosts | Approved DNS/NTP | Name and time | Designated services only |
| Firewall | Vector broker | Firewall logs | Configured syslog transport only |
| Sensor/relay/endpoints | Selected SIEM | Telemetry | Exact agent/receiver ports only |
| Broker | Elastic | Elasticsearch ingest | TCP 9200 with TLS/auth |
| Broker | Splunk | HEC ingest | TCP 8088 with TLS/token |
| Windows forwarders | Splunk | UF receiving | TCP 9997, approved hosts only |
| Windows agents | Fleet Server | Agent management | TCP 8220, approved hosts only |
| REDTEAM | DMZ target | Authorized testing | Only scoped target IPs/ports |
| DMZ | MGMT/ENDPOINT/SOC/home LAN | None by default | Deny |
| REDTEAM | Home LAN/MGMT | None | Deny |
| Capture NIC | Routed destinations | Passive capture | No IP, gateway or forwarding |

Do not guess Active Directory ports. Include RPC endpoint mapper and the required dynamic RPC range based on the Windows Server configuration and Microsoft's current guidance.

## 5. Egress and exposure

Allow package updates only from designated infrastructure VMs during maintenance windows. Remove update access from Kali and vulnerable targets before assessments. Do not create WAN port forwards to Juice Shop, DVWA, management UIs or SIEM ports. No inbound WAN access is required for the base lab.

## 6. Validate segmentation and visibility

On Linux:

    ip -br address
    ip route
    ip neigh

On Windows:

    Get-NetIPConfiguration
    Get-NetRoute -AddressFamily IPv4
    Get-NetFirewallProfile

Test allowed and denied TCP paths to known IPs/ports. Inspect routes and firewall logs. A failed ping alone is not proof because ICMP may be blocked independently. For the sensor, generate a known DNS/HTTP flow and verify packets/counters and corresponding Zeek/Suricata output.

Record source/destination IP and port, expected rule, observed verdict, route/NIC, timestamp and result.

## 7. Cross-host integration

Hypervisor private/host-only networks are local to their host. The safe default is two isolated lab islands. A shared cross-host enterprise design is a separate project requiring a physical firewall, managed switch, VLAN plan, suitable NICs and explicit management/telemetry policy. Never bridge REDTEAM or DMZ onto home Wi-Fi.

## References

- [Hyper-V virtual switches](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/virtual-switch)
- [Broadcom Fusion networking types](https://knowledge.broadcom.com/external/article/303393/understanding-networking-types-in-vmware.html)
- [Oracle VirtualBox networking](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html)
- [Microsoft AD DS firewall ports](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts)
