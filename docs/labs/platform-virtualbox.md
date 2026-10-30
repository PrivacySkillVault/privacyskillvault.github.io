# Lab 1B — Oracle VirtualBox on a Windows x64 host

<badge color="warning">Build guide — not yet lab-tested</badge>

This is an alternative Windows x64 hypervisor path. Use it instead of Hyper-V or VMware Workstation for the first build, not in addition to them. VirtualBox on an x86-64 Windows host can run supported x86/x64 guests. On Apple-silicon hosts, VirtualBox runs ARM64 guests only; it cannot run OPNsense or Security Onion x86-64 guests there.

## 1. Confirm host readiness

1. Confirm Windows is 64-bit x64 and record its edition/build with `winver`.
2. Confirm CPU virtualisation is enabled in UEFI/BIOS (Intel VT-x or AMD-V).
3. Confirm at least 32 GB RAM; 64 GB is preferable for multiple security VMs.
4. Keep at least 200–300 GB free on an SSD for the VM set, snapshots and evidence. This is a planning target, not a vendor minimum.
5. Save the BitLocker recovery key and back up important host data before installing hypervisor networking components.
6. Close other hypervisors and VM workloads during the initial smoke test.

Run in elevated PowerShell:

```powershell
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, VirtualizationFirmwareEnabled
Get-Volume | Select-Object DriveLetter, SizeRemaining
systeminfo.exe
```

If Windows reports that a hypervisor is present, do not disable Hyper-V, VBS, Memory Integrity or WSL2 automatically. Current VirtualBox releases can use Windows hypervisor interfaces on supported Windows hosts, although this can affect performance and feature availability. First install the current supported VirtualBox release and inspect its VM log if acceleration is unavailable. Change Windows security features only after understanding the security and operational impact.

## 2. Download and install VirtualBox

1. Open the [official Oracle VirtualBox downloads page](https://www.virtualbox.org/wiki/Downloads).
2. Select the current Windows hosts package. Do not download installers from third-party mirrors.
3. Review the supported-host list and release notes for the exact version.
4. Verify the downloaded installer is digitally signed by Oracle and that the signature is valid (File Explorer → Properties → Digital Signatures).
5. Run the installer as Administrator. Accept the required networking components. Windows may briefly reset network connectivity while virtual adapters are installed.
6. Complete installation and reboot if requested.
7. Open VirtualBox Manager and confirm the installed version under Help → About.
8. Install the Extension Pack only if you need a feature it provides. If installed, use the Extension Pack built for the exact same VirtualBox version and review its separate licence terms. Basic VM networking and the labs in this programme do not require the Extension Pack.

Verify from PowerShell:

```powershell
& "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe" --version
& "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe" list hostinfo
```

## 3. Create a dedicated VM folder

Create the following folders on an SSD volume with sufficient free space:

```text
D:\CyberLab\
  ISO\
  VMs\
  Exports\
  Evidence\
  Backups\
```

In VirtualBox Manager, open File → Preferences → General and set the Default Machine Folder to `D:\CyberLab\VMs`. Keep ISO files, exports and evidence outside the VM disk folder. Snapshots are not backups; export or back up important guest data separately.

## 4. Create the virtual networks before creating VMs

Open Tools → Network (or File → Tools → Network Manager; labels vary slightly by release).

### 4.1 Create the management host-only network

1. Open the Host-only Networks tab and create a host-only network.
2. Select its Adapter properties.
3. Set the host-side IPv4 address to `10.10.10.2` and mask to `255.255.255.0`.
4. Disable the VirtualBox DHCP server for this host-only network. OPNsense will be the lab DHCP service where dynamic addressing is required.
5. Do not configure a default gateway on the host-only adapter.
6. Record the actual network name shown by VirtualBox; use that exact name when attaching VM adapters.

The OPNsense MGMT interface will be `10.10.10.1/24`. The host-side address `10.10.10.2/24` lets the Windows host open the OPNsense management page without bridging the lab to the physical LAN.

### 4.2 Use named Internal Networks for isolated segments

Create these network names by selecting Internal Network in each VM's adapter settings. VirtualBox creates the internal switch when the first VM uses the name.

| VirtualBox network name | Purpose | Gateway after OPNsense is configured |
|---|---|---|
| `PSV-ENDPOINT` | Windows and Linux user endpoints | `10.10.20.1` |
| `PSV-SERVER` | Domain controller and SIEM server | `10.10.30.1` |
| `PSV-REDTEAM` | Kali assessment source | `10.10.40.1` |
| `PSV-DMZ` | OWASP Juice Shop and vulnerable targets | `10.10.60.1` |

Do not attach Kali or vulnerable targets to Bridged Adapter. Do not use VirtualBox's per-VM NAT mode as a substitute for the routed lab firewall: separate NAT-attached VMs are not automatically on one shared LAN.

### 4.3 Understand the network modes

- **NAT:** a guest can make outbound connections through VirtualBox. By default, separate VMs using ordinary NAT are isolated from each other. Use only as the OPNsense WAN uplink or for a temporary single-VM update path.
- **Host-only:** the host and attached VMs can communicate, but the network is not connected to the physical LAN. Use for MGMT.
- **Internal Network:** only VMs attached to the same named internal network communicate at Layer 2. Use for ENDPOINT, SERVER, REDTEAM and DMZ.
- **Bridged Adapter:** connects the guest to the physical network. Do not use for the attacker or intentionally vulnerable target VMs.

A virtual network is not itself a firewall. OPNsense must route between segments and enforce the inter-segment policy.

## 5. Build the OPNsense firewall VM

Use the Windows x64 PC for OPNsense. The OPNsense VM must use an x86-64 guest image. Follow [OPNsense Firewall & Routing](firewall-routing.md) for installation and firewall policy; this section defines the VirtualBox adapter mapping.

Create a VM named `PSV-FW01`:

- Type: BSD; Version: FreeBSD (64-bit), or the closest supported FreeBSD x64 choice shown by your VirtualBox version.
- 2 vCPU; 4 GB RAM as a starting lab allocation.
- 20 GB dynamically allocated virtual disk.
- Attach the official OPNsense x86-64 DVD ISO.
- Configure the adapters exactly as follows before first boot.

| VirtualBox adapter | Attached to | Network name | OPNsense role |
|---|---|---|---|
| Adapter 1 | NAT | — | WAN |
| Adapter 2 | Host-only Adapter | The management host-only network created above | MGMT |
| Adapter 3 | Internal Network | `PSV-ENDPOINT` | ENDPOINT |
| Adapter 4 | Internal Network | `PSV-SERVER` | SERVER |
| Adapter 5 | Internal Network | `PSV-REDTEAM` | REDTEAM |
| Adapter 6 | Internal Network | `PSV-DMZ` | DMZ |

For each enabled adapter, use an Intel PRO/1000-family adapter unless the current OPNsense/VirtualBox documentation for the selected release recommends another supported type. Keep cable connected enabled. Record each virtual NIC MAC address from Advanced settings before boot.

**Important:** VirtualBox adapter number does not guarantee the guest's interface name or assignment order. At the OPNsense console, identify interfaces by MAC address and link state. Assign WAN/MGMT/ENDPOINT/SERVER/REDTEAM/DMZ only after matching the MAC addresses. Never guess based only on names such as `em0` or `em1`.

After installation, configure the OPNsense interface addresses and policies using the main firewall guide. On MGMT, the firewall address is `10.10.10.1/24`; browse from the Windows host to `https://10.10.10.1` after the host-only adapter and firewall interface are up.

## 6. Create the first guest VM

Create an Ubuntu Server x86-64 VM as a smoke test:

- Name: `PSV-UBU-TEST01`
- Type: Linux; Ubuntu (64-bit)
- 2 vCPU, 4 GB RAM, 40 GB virtual disk
- Adapter 1: Internal Network `PSV-ENDPOINT`
- Attach the official Ubuntu Server x86-64 ISO
- Install a named non-root user; enable OpenSSH only if required

Once OPNsense DHCP is configured for ENDPOINT, boot the guest and verify:

```bash
uname -m
ip -br address
ip route
resolvectl status
sudo apt update
```

Expected architecture is `x86_64`. The guest should receive an address in the configured ENDPOINT DHCP range, gateway `10.10.20.1`, and the configured DNS resolver. If it does not, check the adapter's exact internal-network name, OPNsense interface assignment, DHCP service and firewall logs.

## 7. Snapshot, clone and baseline procedure

1. Apply guest OS updates and install only baseline utilities.
2. Verify the guest has the intended network adapter and no bridged/NAT adapter that bypasses OPNsense.
3. Shut down cleanly and take a snapshot named `baseline-clean`.
4. Record guest OS build, architecture, MAC address, IP address, VM resources and network name.
5. For repeatable endpoints, clone from a powered-off baseline. Generate a new MAC address for each clone.
6. For Windows domain members, use supported Sysprep/generalisation or the Windows deployment workflow before cloning. Do not clone an already domain-joined machine with duplicated identity/SID/hostname state.
7. Treat snapshots as rollback points, not backups of the SIEM data or domain controller.

## 8. Packet capture boundaries

VirtualBox promiscuous-mode settings are not equivalent to a physical switch SPAN port. `Allow VMs` can expose traffic to/from other VMs on the same virtual network to a monitoring VM, subject to the selected adapter mode and host implementation. It does not automatically mirror all routed traffic across every VirtualBox internal network.

For the first home lab, use one of these explicit approaches:

- Run Suricata on the OPNsense gateway to inspect traffic traversing the firewall interfaces, using the supported OPNsense plugin and documented configuration.
- Capture traffic on the individual VM or gateway interface with Wireshark/tcpdump.
- Build a separately designed mirror/tap path and prove that it receives the intended packets before claiming full network visibility.

Do not claim Zeek, Suricata or Security Onion sees all lab traffic merely because its VM adapter is set to Promiscuous Mode. Confirm packet direction, interfaces, packet counters and a known test flow.

## 9. VirtualBox troubleshooting

| Symptom | Check |
|---|---|
| VM reports VT-x/AMD-V unavailable | Confirm firmware virtualisation; inspect VirtualBox VM log; check whether another hypervisor/security feature is affecting the backend. Do not disable Windows protections blindly. |
| Guest has no DHCP address | Confirm exact Internal Network name, OPNsense interface assignment, DHCP scope and firewall rules. |
| Host cannot open OPNsense GUI | Confirm host-only adapter IP, mask, firewall MGMT address, host-only DHCP disabled, and adapter attached to the correct host-only network. |
| OPNsense sees interfaces in unexpected order | Match VirtualBox adapter MAC addresses with OPNsense console interface/MAC output; reassign by MAC. |
| Kali can reach the home LAN | Power it off immediately; remove any Bridged adapter; inspect routes, OPNsense rules and any second NIC bypass. |
| Sensor sees only some traffic | Determine which virtual switch carries the flow. Promiscuous mode is not global SPAN; validate with a known packet capture. |
| Performance is poor | Run one SIEM at a time, reduce concurrent VMs, confirm SSD free space and guest memory pressure, and review Hyper-V/VBS backend implications. |

## 10. Validation checklist

- [ ] VirtualBox version and Windows host build recorded.
- [ ] Installer signature checked; Extension Pack omitted unless needed and version-matched if installed.
- [ ] Host-only MGMT network uses `10.10.10.2/24`, with VirtualBox DHCP disabled.
- [ ] Internal networks use the exact names in the network plan.
- [ ] OPNsense WAN is NAT; no lab guest uses Bridged Adapter.
- [ ] OPNsense NICs mapped by MAC address, not guessed by adapter order.
- [ ] Windows host can reach OPNsense MGMT only through host-only networking.
- [ ] Test guest receives the correct DHCP address, gateway and DNS.
- [ ] Inter-segment allow/deny tests are recorded.
- [ ] Snapshot restore and cleanup have been tested.

## Official references

- [Oracle VirtualBox downloads](https://www.virtualbox.org/wiki/Downloads)
- [Oracle VirtualBox 7.2 User Manual — networking](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html)
- [Oracle VirtualBox host/guest architecture support](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/Introduction.html)
- [OPNsense virtual installation](https://docs.opnsense.org/manual/virtuals.html)
- [OPNsense VirtualBox OVA installation notes](https://docs.opnsense.org/manual/how-tos/installova.html)

**Current status:** Reference build guide only. No VirtualBox VM or network has been installed or tested by PSV.
