# Lab 3 — Network design, segmentation and routing

<badge color="warning">Build guide — validate isolation before connecting targets</badge>

This guide defines the network layout used by all subsequent PSV labs. Build the networks first and prove isolation before installing Kali or vulnerable applications.

## 1. Segments and IP plan

Use the plan in the [lab overview](index.md#5-network-address-plan). The example uses 10.10.0.0/16 subnets; check for conflicts with your actual LAN, VPN and routes first.

| Network | Example subnet | Windows Hyper-V | VMware Workstation | VMware Fusion |
|---|---|---|---|---|
| Management | 10.10.10.0/24 | Internal | Host-only | Host-only/private, if available |
| Endpoint | 10.10.20.0/24 | Private | Custom host-only | Custom private, if available |
| Server | 10.10.30.0/24 | Private | Custom host-only | Custom private, if available |
| Red team | 10.10.40.0/24 | Private | Custom host-only | Custom private, if available |
| DMZ | 10.10.60.0/24 | Private | Custom host-only | Custom private, if available |
| Update egress | NAT only | Controlled NAT adapter | VMnet8 NAT | Shared/NAT |

The names above are logical labels. Map them to the actual switch/network names available in your hypervisor and record the mapping.

## 2. Hyper-V implementation

1. Open Hyper-V Manager → Virtual Switch Manager.
2. Create an **Internal** switch named `PSV-MGMT`.
3. Create **Private** switches named `PSV-ENDPOINT`, `PSV-SERVER`, `PSV-REDTEAM`, and `PSV-DMZ`.
4. Do not enable host sharing or attach a physical adapter to the Private switches.
5. Attach each VM NIC only to the segment it needs.
6. If inter-segment routing is required, deploy a dedicated router/firewall VM with one NIC per segment, configure explicit policies and verify there is no unintended forwarding.
7. Do not enable Windows Internet Connection Sharing as a shortcut between lab and home networks.

## 3. VMware Workstation implementation

1. Open Virtual Network Editor as administrator.
2. Keep VMnet1 host-only for management.
3. Use VMnet8 NAT only for controlled package updates.
4. Add custom host-only networks for endpoint, server, red-team and DMZ segments.
5. Disable DHCP on segments where you will use static addressing or a dedicated DHCP server. Avoid two DHCP servers on one subnet.
6. Keep the attacker and vulnerable targets on non-bridged host-only networks.
7. If using a router/firewall VM, connect one virtual NIC to each required segment and enforce default-deny rules.

## 4. VMware Fusion implementation

1. Open Fusion network settings and inspect the actual network modes available in your installed release.
2. Identify shared/NAT and host-only networks.
3. Use host-only/private networks for isolated test VMs where the version supports them.
4. Do not assume Fusion exposes the same number of custom segments as Workstation. If it does not, run a smaller standalone Mac lab or connect through a separately configured lab firewall/router.
5. Do not bridge an intentionally vulnerable target to Wi-Fi/Ethernet.
6. For cross-host lab integration, use a dedicated physical lab router with isolated VLANs or a carefully configured firewall appliance. Do not treat the home router as a lab firewall.

## 5. Static addressing

For each segment, document:
- Subnet and mask.
- Gateway address (only if a router/firewall exists).
- DHCP range and reservations.
- DNS server.
- NTP source.
- Allowed source/destination/port rules.
- Whether host-to-VM access is allowed.
- Whether Internet egress is allowed and when.

Do not assign a gateway on an isolated network unless that gateway exists. A static address alone does not provide DNS, Internet access or routing.

## 6. Firewall policy — default deny

Start with no inter-segment forwarding. Add specific flows only as required.

| Source | Destination | Purpose | Policy |
|---|---|---|---|
| Admin workstation | Management interfaces | Admin access | Allow only required ports |
| Endpoint | DNS/NTP | Name/time services | Allow to designated servers |
| Endpoint | Elastic Fleet/outputs | Telemetry | Allow documented agent destinations |
| Endpoint | Splunk receiver | Forwarded events | Allow configured receiving port only |
| Endpoint | Wazuh manager | Agent communication | Allow documented Wazuh ports only |
| Kali | DMZ target | Authorised testing | Allow only target IPs and test ports |
| Sensor mgmt NIC | Management | Sensor administration | Allow from admin workstation |
| Sensor sniff NIC | Mirrored traffic | Passive capture | No IP/gateway; no forwarding |
| Vulnerable target | Home LAN | None | Deny |
| Vulnerable target | Internet | Normally none | Deny except temporary controlled update window |

Port numbers must be taken from the exact versions and configuration you install. Do not copy a generic list without checking whether the product uses TLS, custom ports, Fleet, forwarders, or an alternative receiver.

## 7. Prove isolation before testing

On Kali, inspect routes:

```bash
ip -br address
ip route
```

On a Windows target:

```powershell
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4
Get-NetFirewallProfile
```

Run controlled connectivity checks:
- Kali can reach the assigned vulnerable target IP.
- Kali cannot reach your home router or unrelated LAN hosts.
- The target cannot initiate connections to the home LAN.
- Management access works only from the admin host.
- Endpoint telemetry reaches only the SIEM receiver required for the current lab.

A failed ping is not conclusive proof of isolation because ICMP may be blocked. Check routes, firewall rules, virtual switch membership and a targeted TCP connection test. Record the results.

## 8. Cross-host design

Hyper-V private switches and Fusion host-only networks are local to each host. They are not automatically interconnected.

For a two-host shared lab, use one of:
- A dedicated managed switch and lab firewall/router with separate VLANs, if the PC and Mac have suitable wired adapters.
- A dedicated firewall VM with carefully controlled host-only uplinks and an explicit inter-host tunnel.
- Separate per-host labs with data forwarded to a SIEM reachable through the management segment.

Do not extend the red-team/DMZ Layer 2 segment onto your home Wi-Fi. Keep the routing point controlled and logged.

## 9. Validation and rollback

Before proceeding:
- [ ] Network segments exist and are named.
- [ ] Each VM NIC is attached to the intended segment.
- [ ] Kali and vulnerable targets are not bridged.
- [ ] No accidental DHCP overlap exists.
- [ ] No default route leaks from the DMZ/red-team network.
- [ ] SIEM endpoints are reachable only on required ports.
- [ ] Sensor sniff interface has no default gateway.
- [ ] Isolation tests are recorded.

If isolation fails, power off the attacker and target VMs, disconnect their NICs, correct the switch/firewall configuration, and retest. Do not continue with offensive exercises until isolation is demonstrated.

## References

- [Hyper-V virtual switches](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/virtual-switch)
- [VMware desktop hypervisor FAQ](https://www.vmware.com/docs/desktop-hypervisor-faqs)
