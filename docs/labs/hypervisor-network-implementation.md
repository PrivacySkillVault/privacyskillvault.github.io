# Hypervisor networking and packet visibility

<badge color="warning">Configuration reference — validate against the installed hypervisor release</badge>

This runbook converts the logical topology into actual virtual switches, VM adapters and a capture design. A private switch, NAT network, host-only network and bridged adapter have different security properties. Attaching a sensor VM to an ordinary virtual network does not automatically make it see every guest's unicast traffic.

## 1. Freeze the network design

Check the example subnets against the physical LAN, VPN routes, Docker/WSL networks and existing virtual networks before use.

| Segment | Example subnet | Router IP | Purpose |
|---|---|---|---|
| MGMT | 10.10.10.0/24 | 10.10.10.1 | Admin and management |
| ENDPOINT | 10.10.20.0/24 | 10.10.20.1 | Windows/Linux endpoints |
| SERVER | 10.10.30.0/24 | 10.10.30.1 | AD/DNS, relay, SIEM |
| REDTEAM | 10.10.40.0/24 | 10.10.40.1 | Kali and scoped assessment |
| SENSOR-MGMT | 10.10.50.0/24 | 10.10.50.1 | Sensor administration |
| DMZ | 10.10.60.0/24 | 10.10.60.1 | Vulnerable targets |

SENSOR-MGMT is not a packet-mirror network. The sensor needs a separate capture NIC connected to a real mirror/tap or deliberately designed inline path. Do not assign a default route to capture-only NICs.

For every VM, record adapter number, switch/network name, MAC, IPv4/IPv6 settings, VLAN (if any), role, and whether the NIC is management or capture-only.

## 2. Hyper-V — create private switches

Run PowerShell as Administrator. Inspect existing configuration first:

~~~powershell
Get-NetAdapter | Format-Table Name,InterfaceDescription,Status,LinkSpeed
Get-VMSwitch | Format-Table Name,SwitchType,NetAdapterInterfaceDescription
Get-VMNetworkAdapter -All | Format-Table VMName,Name,SwitchName,MacAddress
Get-NetIPConfiguration
~~~

Create isolated Private switches:

~~~powershell
$segments = @("PSV-MGMT","PSV-ENDPOINT","PSV-SERVER","PSV-REDTEAM","PSV-SENSOR-MGMT","PSV-DMZ")
foreach ($name in $segments) {
    if (-not (Get-VMSwitch -Name $name -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name $name -SwitchType Private
    }
}
Get-VMSwitch | Where-Object Name -Like "PSV-*" | Format-Table Name,SwitchType
~~~

Private switches allow only attached VMs to communicate. Use Internal switches only when the host must participate; then apply Windows Firewall rules to the host vNIC.

For the firewall WAN, prefer a dedicated Hyper-V NAT uplink on an Internal switch rather than exposing the firewall VM directly to the physical LAN. Create it once (run as Administrator):

~~~powershell
New-VMSwitch -Name "PSV-WAN-NAT" -SwitchType Internal
New-NetIPAddress -IPAddress 192.168.250.1 -PrefixLength 24 -InterfaceAlias "vEthernet (PSV-WAN-NAT)"
New-NetNat -Name "PSV-WAN-NAT" -InternalIPInterfaceAddressPrefix 192.168.250.0/24
Get-NetNat -Name "PSV-WAN-NAT"
~~~

Assign the OPNsense WAN adapter to PSV-WAN-NAT and configure its WAN address statically as 192.168.250.2/24, gateway 192.168.250.1. Select an appropriate upstream DNS resolver deliberately. Confirm the host's physical interface has Internet access and that Windows host firewall permits only required host-side traffic. This creates a double-NAT path through the host's physical network; it is for controlled updates, not inbound access. If a NAT object with that name already exists, inspect it rather than creating a duplicate. To remove this lab NAT later, first disconnect the VM WAN adapter, then remove the NAT object and switch deliberately.

An External switch is an alternative only when you deliberately want the firewall WAN attached to a physical network. Bind it to the selected physical NIC, understand host-sharing consequences and keep REDTEAM/DMZ off it. Never connect REDTEAM or DMZ directly to an External switch.

Add named adapters to the OPNsense VM (replace VM name/switch names if yours differ):

~~~powershell
Add-VMNetworkAdapter -VMName "PSV-OPNSENSE" -Name "MGMT" -SwitchName "PSV-MGMT"
Add-VMNetworkAdapter -VMName "PSV-OPNSENSE" -Name "ENDPOINT" -SwitchName "PSV-ENDPOINT"
Add-VMNetworkAdapter -VMName "PSV-OPNSENSE" -Name "SERVER" -SwitchName "PSV-SERVER"
Add-VMNetworkAdapter -VMName "PSV-OPNSENSE" -Name "REDTEAM" -SwitchName "PSV-REDTEAM"
Add-VMNetworkAdapter -VMName "PSV-OPNSENSE" -Name "SENSOR-MGMT" -SwitchName "PSV-SENSOR-MGMT"
Add-VMNetworkAdapter -VMName "PSV-OPNSENSE" -Name "DMZ" -SwitchName "PSV-DMZ"
Get-VMNetworkAdapter -VMName "PSV-OPNSENSE" | Format-Table Name,SwitchName,MacAddress
~~~

Connect the WAN adapter to the chosen NAT/uplink separately. Record all MAC addresses and map interfaces by MAC inside OPNsense; never assume adapter enumeration order.

## 3. Hyper-V — configure port mirroring

Hyper-V port mirroring copies traffic sent/received by source adapters to a destination adapter. Source and destination adapters must be connected to the same virtual switch. This is not a global mirror across unrelated switches.

Example, where the monitored adapter and sensor capture adapter share the same switch:

~~~powershell
Get-VMNetworkAdapter -VMName "PSV-WIN11" |
    Format-Table VMName,Name,SwitchName,MacAddress

Set-VMNetworkAdapter -VMName "PSV-WIN11" -Name "MONITORED" -PortMirroring Source
Set-VMNetworkAdapter -VMName "PSV-SENSOR" -Name "CAPTURE" -PortMirroring Destination

Get-VMNetworkAdapter -VMName "PSV-WIN11" |
    Format-Table Name,SwitchName,PortMirroring
Get-VMNetworkAdapter -VMName "PSV-SENSOR" |
    Format-Table Name,SwitchName,PortMirroring
~~~

For multiple isolated switches, use one capture NIC per switch where supported, a documented aggregation design, router-interface capture, a physical managed-switch SPAN/TAP, or offline PCAP. Do not bridge isolated networks merely to make one sensor see them.

## 4. VMware Workstation, Fusion and VirtualBox

Create distinct host-only/private networks for each segment and a NAT network only for firewall WAN or explicitly permitted update egress. Record each virtual network's subnet and DHCP state. Disable hypervisor DHCP on any segment where the lab router or AD DHCP server owns the scope. Never run two DHCP servers on one L2 segment.

**Promiscuous mode is not SPAN.** It only permits a guest NIC to receive frames the virtual switch actually delivers. It does not guarantee that unicast traffic between other VMs is copied to the sensor. VirtualBox promiscuous policy and VMware capture behavior are not substitutes for documented port mirroring.

For VMware Fusion on Apple Silicon, use supported ARM64 guests and the network types exposed by the installed release. NAT, host-only and bridged networks do not automatically mirror traffic. If Fusion cannot provide the required isolated networks or mirror, use router-interface capture, external managed-switch SPAN/TAP, or offline PCAP. Do not label a host-only network as an enterprise SPAN.

## 5. Sensor NIC roles

The sensor should have:
- One management NIC on SENSOR-MGMT or a documented management segment.
- One or more capture NICs attached only to intended mirror/tap paths.
- No IP address, default route or DNS registration on capture-only NICs unless the chosen sensor design explicitly requires it.
- No forwarding/bridging between capture and management interfaces.
- Time synchronization through the management interface.

On Linux:

~~~bash
ip -br link
ip -br address
ip route
sudo ethtool -k <capture-interface>
~~~

Set capture NICs up without IP addresses only after confirming interface names. Do not disable offloads blindly; test packet integrity and document any changes. Measure packet loss under load.

## 6. Acceptance tests

1. Generate a unique DNS query and TCP connection from a test endpoint to a controlled target.
2. Record source, destination, ports and timestamp at the endpoint.
3. Capture on the intended sensor interface.
4. Confirm the packet tuple matches.
5. Repeat for same-segment traffic and routed traffic.
6. Generate a denied flow and verify the firewall log.
7. Compare packet counts and capture-drop counters during a sustained test.
8. Confirm the capture NIC cannot reach management or the Internet.
9. Save sanitized adapter mapping, command output and PCAP as evidence.

~~~bash
sudo tcpdump -ni <capture-interface> -c 100 'host <source-ip> and host <destination-ip>'
~~~

**Pass:** the known flow is visible on the intended interface, the capture path is documented, and no unintended network is exposed.

**Fail:** no packet is visible, only broadcast traffic appears, the sensor sees only its own traffic, or capture NIC has an unintended IP/default route. Stop before installing Zeek or Suricata.

## References

- [Microsoft Set-VMNetworkAdapter — port mirroring](https://learn.microsoft.com/powershell/module/hyper-v/set-vmnetworkadapter)
- [Broadcom VMware Fusion network types](https://knowledge.broadcom.com/external/article/303393/understanding-networking-types-in-vmware.html)
- [VirtualBox networking manual](https://www.virtualbox.org/manual/ch06.html)
