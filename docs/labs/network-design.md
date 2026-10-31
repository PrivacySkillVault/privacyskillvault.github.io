# Lab — Network design and segmentation

<badge color="warning">Architecture baseline — validate on the selected hypervisor</badge>

This page defines the logical networks used by both host tracks. The Windows and Mac implementations are not interchangeable. Follow the [Master Build Sequence](build-sequence.md).

## 1. Logical segments and example address plan

Check for overlap with home LAN, VPN, corporate routes and other VM networks before using these examples.

| Segment | Subnet | Purpose | Example gateway |
|---|---|---|---|
| MGMT | 10.10.10.0/24 | Admin workstation and management interfaces | 10.10.10.1 |
| ENDPOINT | 10.10.20.0/24 | Windows/Linux/Mac test endpoints | 10.10.20.1 |
| SERVER | 10.10.30.0/24 | AD DS/DNS, syslog relay and selected SIEM | 10.10.30.1 |
| REDTEAM | 10.10.40.0/24 | Kali assessment source | 10.10.40.1 |
| SENSOR | 10.10.50.0/24 | Sensor management/capture design | Not a general client gateway |
| DMZ | 10.10.60.0/24 | Vulnerable targets | 10.10.60.1 |

Suggested Windows-track addresses: DC 10.10.30.10; syslog relay 10.10.30.30; Elastic 10.10.30.20; Splunk 10.10.30.21; Wazuh 10.10.30.22; Kali 10.10.40.10; Juice Shop 10.10.60.20. Use only the address for the SIEM currently being built.

A sensor may have a management NIC with an IP on MGMT and a passive capture NIC with no IP, gateway or forwarding. Do not attach the sniffing NIC to an ordinary routed network and assume it is receiving mirrored traffic.

## 2. Windows x64 implementation

Choose exactly one hypervisor and record actual switch names.

- **Hyper-V:** create an Internal switch for MGMT and Private switches for ENDPOINT, SERVER, REDTEAM and DMZ. Private is VM-to-VM only; Internal also permits host-to-VM. Do not create an External switch for Kali or vulnerable targets. Hyper-V port mirroring requires source and destination adapters to be configured on the same virtual switch; explicitly set and verify roles.
- **VMware Workstation:** use host-only networks for isolated segments and NAT only for controlled updates. Do not use Bridged for REDTEAM or DMZ. Do not assume a universal SPAN/mirror feature.
- **VirtualBox:** use Host-only for host management and named Internal Networks for VM-only segments; NAT only for firewall WAN/update. Promiscuous mode is not a global mirror. See [VirtualBox Host Setup](platform-virtualbox.md).

## 3. Apple-silicon Mac implementation

Use ARM64 guests. Fusion NAT, Host-only and custom networks are distinct and are not automatically connected to Windows hypervisor switches.

For a segmented Mac-only build:
1. Keep Fusion NAT as the router VM's WAN/update interface only.
2. Create independent private/host-only networks for MGMT, ENDPOINT, SERVER, REDTEAM and DMZ using features actually exposed by the installed Fusion release.
3. Disable Fusion DHCP on networks where the Linux router provides DHCP, or use static addresses consistently.
4. Deploy the ARM64 Ubuntu router in [Mac ARM Router & Firewall](mac-arm-routing.md).
5. Attach each guest only to its intended segment.
6. Do not use Bridged networking for REDTEAM or DMZ.

If the installed Fusion version cannot create enough independent networks, stop. Do not collapse all VMs onto one host-only network and call it segmentation.

## 4. Minimum inter-segment policy

Start with default-deny and add only flows required by the current stage.

| Source | Destination | Purpose | Policy |
|---|---|---|---|
| Admin workstation | Firewall/VM management | Administration | Allow named admin IPs/ports only |
| ENDPOINT | Domain controller | DNS/Kerberos/LDAP/SMB/RPC as required | Allow documented AD ports to DC only |
| Lab hosts | DNS/NTP | Name/time | Allow designated resolver/time source |
| Firewall/router | Syslog relay | Firewall/IDS logs | Allow configured TCP/UDP/TLS listener only |
| Relay/sensor/endpoint | Selected SIEM | Log forwarding | Allow documented agent/receiver ports only |
| Kali | DMZ target | Authorised testing | Allow only scoped target IPs/ports |
| DMZ | MGMT/SERVER/ENDPOINT/home LAN | None by default | Deny |
| REDTEAM | Home LAN/MGMT | None | Deny |
| Capture NIC | Routed destinations | Passive capture | No IP, gateway or forwarding |

Do not guess Active Directory ports. Use Microsoft's current port documentation and test the exact services enabled, including dynamic RPC requirements.

## 5. Update egress

Permit OS/package updates from designated infrastructure VMs during a maintenance window. Remove update access from Kali and vulnerable targets before assessments. Do not expose management interfaces on WAN or use Internet Connection Sharing as a shortcut.

## 6. Validate segmentation

On Linux:

    ip -br address
    ip route
    ip neigh

On Windows:

    Get-NetIPConfiguration
    Get-NetRoute -AddressFamily IPv4
    Get-NetFirewallProfile

Test allowed and denied TCP paths to known IPs/ports. Inspect routes and firewall logs. A failed ping alone is not proof because ICMP may be blocked independently.

Record source/destination IP and port, expected rule, observed verdict, route/NIC, timestamp and result.

## 7. Cross-host integration

Hyper-V private switches and Fusion host-only networks are local to their hosts. The safe default is two isolated lab islands with their own routing and SIEM ingestion.

A shared cross-host enterprise design is a separate project requiring an x86-64 firewall appliance, managed switch, VLAN plan, suitable physical NICs and explicit management/telemetry policy. Do not bridge REDTEAM or DMZ onto home Wi-Fi.

## References

- [Hyper-V virtual switches](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/virtual-switch)
- [Broadcom Fusion networking types](https://knowledge.broadcom.com/external/article/303393/understanding-networking-types-in-vmware.html)
- [Oracle VirtualBox networking](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html)
