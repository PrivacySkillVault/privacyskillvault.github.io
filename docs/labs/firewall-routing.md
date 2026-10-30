# Lab 3A — OPNsense virtual firewall, routing and DHCP

<badge color="warning">Build guide — not yet lab-tested</badge>

OPNsense provides the routed boundary between lab segments. It is a dedicated x86-64 firewall VM on the Windows PC. OPNsense's current installer supports x86-64, not Apple-silicon ARM. Do not try to install it as an ARM guest in VMware Fusion.

## 1. Design

Use six virtual NICs on the firewall VM:

| OPNsense interface | Virtual network | Address |
|---|---|---|
| WAN | Hypervisor NAT / update egress | DHCP from NAT |
| MGMT | Internal/host-only management | 10.10.10.1/24 |
| ENDPOINT | Private endpoint segment | 10.10.20.1/24 |
| SERVER | Private server segment | 10.10.30.1/24 |
| REDTEAM | Private attacker segment | 10.10.40.1/24 |
| DMZ | Private vulnerable-target segment | 10.10.60.1/24 |

The SENSOR capture network is separate and passive. Do not route the mirrored capture NIC through OPNsense. Use a virtual switch mirror/SPAN feed to the sensor's dedicated capture NIC.

## 2. Create the firewall VM

On Hyper-V:
1. Create a Generation 2 VM named PSV-FW01.
2. Allocate 2 vCPU, 4 GB RAM and 20 GB disk as a starting lab allocation. OPNsense documentation lists 3 GB RAM minimum and 8 GB disk recommended.
3. Disable Secure Boot for this VM, as required by the OPNsense Hyper-V documentation.
4. Add six virtual NICs and attach them to the networks in the table above. The first adapter may be used as WAN and the next as MGMT, but do not assume order; map each adapter by MAC address and switch name.
5. Attach the official OPNsense DVD ISO and boot.

On VMware Workstation:
1. Create a FreeBSD-compatible VM with 2 vCPU, 4 GB RAM, 20 GB disk.
2. Add six virtual NICs and attach each to the correct NAT/host-only network.
3. Keep WAN on VMnet8 NAT; do not bridge WAN or any lab network to your physical home LAN.
4. Attach the official OPNsense DVD ISO.

Hyper-V Generation 1/2 and VMware virtual installation are documented by OPNsense. If your hypervisor does not expose enough isolated virtual networks, build fewer segments first and expand after validation.

### VirtualBox adapter mapping (Windows x64 host)

For VirtualBox, create the firewall VM on the Windows x64 PC and attach these adapters before first boot:

| VirtualBox adapter | Attachment | Name | OPNsense role |
|---|---|---|---|
| 1 | NAT | — | WAN |
| 2 | Host-only Adapter | The dedicated MGMT host-only network | MGMT |
| 3 | Internal Network | `PSV-ENDPOINT` | ENDPOINT |
| 4 | Internal Network | `PSV-SERVER` | SERVER |
| 5 | Internal Network | `PSV-REDTEAM` | REDTEAM |
| 6 | Internal Network | `PSV-DMZ` | DMZ |

Create the MGMT host-only network with the Windows host at `10.10.10.2/24` and disable the VirtualBox DHCP server on it; OPNsense uses `10.10.10.1/24`. Create the four internal networks using exactly the names above. The OPNsense WAN should be VirtualBox NAT, not Bridged Adapter. Follow [VirtualBox Host Setup](platform-virtualbox.md) for detailed setup and verification.

Record each virtual NIC MAC address and map the OPNsense interfaces by MAC at the console. VirtualBox adapter number does not guarantee guest interface name/order. Do not guess interface assignments. VirtualBox's NAT mode provides outbound access for the firewall WAN; it is not a shared LAN for the other lab VMs.

## 3. Install OPNsense

1. Download the current x86-64 DVD ISO from the official OPNsense download site.
2. Verify the published checksum.
3. Boot the VM from the ISO.
4. At the live console, log in with installer user and the password shown in the official installation guide (currently documented as opnsense).
5. Select Quick/Easy Install and the virtual disk. This erases the selected virtual disk.
6. Set a new root password when prompted.
7. Complete installation and reboot, detaching the ISO.
8. At the console, assign WAN and MGMT first. Identify NIC names using the console interface list and compare MAC addresses with the hypervisor. Add ENDPOINT, SERVER, REDTEAM and DMZ as optional interfaces.
9. Configure MGMT as 10.10.10.1/24. Configure WAN for DHCP from the hypervisor NAT network.
10. From the admin workstation on MGMT, browse to the firewall's HTTPS management address.

Change the default root password immediately. The installer credentials are for initial setup only.

## 4. Configure interface addresses

In the OPNsense web UI, open Interfaces → Assignments. Confirm the device-to-interface mapping before enabling each interface. Enable and assign static IPv4 addresses:

- MGMT: 10.10.10.1/24
- ENDPOINT: 10.10.20.1/24
- SERVER: 10.10.30.1/24
- REDTEAM: 10.10.40.1/24
- DMZ: 10.10.60.1/24

Do not configure a gateway on internal interfaces. The WAN receives its gateway from the NAT network. Apply each interface change and verify its address from the console and UI.

## 5. Configure DNS and DHCP

1. Enable Unbound DNS under Services → Unbound DNS. Keep the resolver listening only on the firewall interfaces that need DNS.
2. Confirm the access list includes the lab subnets; add explicit ACLs only where required.
3. Configure DHCP scopes only for networks that need dynamic addressing:
   - ENDPOINT: 10.10.20.100–10.10.20.199
   - REDTEAM: 10.10.40.100–10.10.40.149
   - DMZ: 10.10.60.100–10.10.60.149
4. Set each scope's DNS server and default gateway to the OPNsense interface address for that subnet.
5. Keep SERVER addresses static/reserved for DC, SIEM and infrastructure systems.
6. Do not run another DHCP server on the same virtual network.

## 6. Firewall policy — remove broad defaults

OPNsense creates a default allow rule on the initial LAN interface. Review and replace broad default allow rules before connecting other segments. Do not simply copy the default LAN policy to every interface.

Create narrowly scoped rules, in this order, using the actual source/destination objects:

**MGMT**
- Allow admin workstation IP to OPNsense HTTPS management.
- Allow admin workstation to required management ports on lab servers.
- Allow MGMT clients to the firewall DNS resolver and NTP source.
- Do not allow all MGMT-to-all traffic without a reason.

**ENDPOINT**
- Allow DNS to 10.10.20.1 and NTP to the approved lab time source.
- Allow telemetry to the SIEM host and only the configured agent/forwarder destination ports.
- Allow domain clients to the domain controller for AD DS/DNS services required by domain operation; use Microsoft's current port documentation to define the exact rules.
- Deny access to REDTEAM and DMZ unless an exercise explicitly needs it.

**SERVER**
- Allow the domain controller to DNS/NTP and approved update destinations.
- Allow management access from MGMT.
- Allow endpoint-to-SIEM traffic only on required collector/agent ports.
- Deny unsolicited inbound access from REDTEAM and DMZ.

**REDTEAM**
- Allow Kali to the explicit target IPs/ports in the written assessment scope.
- Deny access to MGMT, home LAN, WAN and all other lab networks by default.
- Permit temporary NAT egress only for Kali updates; disable/remove it before assessment.

**DMZ**
- Allow only the service ports required for the vulnerable target.
- Deny DMZ-to-MGMT, SERVER, ENDPOINT and home LAN by default.
- Do not allow unsolicited inbound from WAN.

OPNsense uses stateful rules and evaluates policy by interface. Rules should be validated using live firewall logs and packet captures. Never remove the only management allow rule while connected remotely; retain console access and a rollback plan.

## 7. NAT and update access

Use automatic outbound NAT for the lab's temporary update path. Confirm only the networks intended for updates can reach WAN. Keep vulnerable targets without Internet egress during testing. Do not expose OPNsense Web GUI or SSH on WAN.

## 8. Validate before connecting Kali or vulnerable targets

From a Windows endpoint, verify:
- DHCP address, gateway and DNS are correct.
- The domain controller and SIEM are reachable only on required ports.
- Internet access is absent unless an update window is enabled.

From Kali:
- Its route points to 10.10.40.1.
- It can reach only the authorised target service.
- It cannot reach the admin workstation, domain controller management ports, home router or other LAN hosts.

From the firewall:
- Check live firewall logs for allowed and blocked flows.
- Confirm the expected rule matched.
- Check interface status and gateway health.

A failed ping alone does not prove isolation. Test routes, firewall logs and specific TCP connections.

## 9. Backup and rollback

Export an encrypted OPNsense configuration backup after the initial working setup and after major rule changes. Store it outside the VM. Keep console access available before changing management rules. If connectivity is lost, use the hypervisor console to restore interface assignments or the saved configuration.

## References

- [OPNsense virtual installation](https://docs.opnsense.org/manual/virtuals.html)
- [Oracle VirtualBox networking modes](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html)
- [OPNsense VirtualBox OVA installation notes](https://docs.opnsense.org/manual/how-tos/installova.html)
- [OPNsense initial installation](https://docs.opnsense.org/manual/install.html)
- [OPNsense interface assignments](https://docs.opnsense.org/manual/interfaces.html)
- [OPNsense firewall rules](https://docs.opnsense.org/manual/firewall.html)
- [OPNsense Unbound DNS](https://docs.opnsense.org/manual/unbound.html)
