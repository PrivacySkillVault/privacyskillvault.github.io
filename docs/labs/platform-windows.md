# Lab 1 — Windows PC host and hypervisor setup

<badge color="warning">Build guide — not yet lab-tested</badge>

This page prepares a Windows x64 PC as the primary host for Windows/Linux guests, Splunk Enterprise, Elastic, Wazuh and Security Onion. Choose **one primary hypervisor** for the first build. Do not install several hypervisors and change Windows hypervisor settings repeatedly without a reason.

## 1. Preflight

1. Confirm Windows edition and build using `winver`.
2. Confirm x64 architecture, RAM, CPU model and free disk using [Hardware and platform compatibility](requirements.md).
3. Back up important host data.
4. Update Windows and firmware through the PC manufacturer's supported process.
5. Enter UEFI/BIOS and enable Intel VT-x/VT-d or AMD-V/IOMMU if available. Save and reboot.
6. Keep BitLocker recovery key accessible before firmware changes.
7. Create a dedicated VM folder on a fast SSD, for example `D:\VMs`. Do not place active VMs in OneDrive-synchronised folders.

Verify virtualisation:

```powershell
systeminfo.exe
Get-CimInstance Win32_ComputerSystem | Select-Object HypervisorPresent, TotalPhysicalMemory
```

If Windows reports a hypervisor already present, that does not by itself indicate a fault; Hyper-V, Virtual Machine Platform, WSL2 and Virtualisation-Based Security can use the Windows hypervisor.

## 2. Choose the hypervisor

### Option A — Hyper-V

Use this if your Windows edition exposes the Hyper-V feature and the hardware prerequisites are met.

1. Open **Settings → System → About** and confirm Windows edition.
2. Open **Turn Windows features on or off**.
3. Enable **Hyper-V**, including Management Tools and Platform, if available.
4. Reboot.
5. Open Hyper-V Manager and confirm the local host appears.
6. In Hyper-V Manager, open **Virtual Switch Manager**. Create:
   - an **Internal** switch for host-to-VM management traffic;
   - one or more **Private** switches for VM-only lab segments.
7. Do not use an External switch for Kali or vulnerable targets. An External switch bridges to a physical network and can expose the lab to the home LAN.
8. Record switch names and purpose.

PowerShell verification:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
Get-VMSwitch | Format-Table Name, SwitchType, NetAdapterInterfaceDescription
```

Hyper-V switch types:
- **Private:** VM-to-VM only; host cannot communicate through that switch.
- **Internal:** VM-to-VM and host-to-VM; no direct physical LAN connection.
- **External:** connected to a physical network adapter; use only where explicitly required and understood.

### Option B — VMware Workstation Pro

Use this where Hyper-V is unavailable or you prefer VMware's VM networking workflow.

1. Download VMware Workstation from the official Broadcom/VMware desktop hypervisor portal.
2. Verify the installer source and publisher signature.
3. Run the installer as an administrator and accept the licence terms shown.
4. Reboot if requested.
5. Open VMware Workstation and create a disposable test VM to verify the hypervisor works.
6. Open **Edit → Virtual Network Editor** (elevate if requested).
7. Identify:
   - VMnet8 NAT network for controlled package updates;
   - VMnet1 host-only network for host-to-VM management;
   - additional host-only/custom networks for isolated lab segments.
8. Disable host connection on a segment if it should be VM-only, and do not bridge the attacker/target segment to the physical adapter.
9. Record subnet, DHCP range, host adapter and NAT status for each VMnet.

VMware menu names and licensing screens may vary by release. Follow the current product documentation for the exact version installed.

### Option C — Oracle VirtualBox

Use VirtualBox on this Windows x64 host when you want a separate, supported x86/x64 guest environment and its internal/host-only network model. Follow the dedicated [VirtualBox host and network build guide](platform-virtualbox.md) for the exact installation, named network creation, OPNsense adapter mapping, first guest smoke test and packet-capture limitations. Do not combine this option with the Hyper-V/VMware network plan without deliberately redesigning the virtual switches.

1. Download the current Windows hosts package from Oracle's official VirtualBox downloads page.
2. Verify the Oracle digital signature and review the release's supported host/guest matrix.
3. Install as Administrator; expect a brief network adapter reset while networking components are installed.
4. Reboot if requested and verify the installed version in VirtualBox Manager.
5. Do not install the Extension Pack unless a required feature needs it. If installed, its version must match the base VirtualBox version and its separate licence terms must be reviewed.
6. Create a small Ubuntu x86-64 VM as a smoke test before creating the firewall or SIEM VMs.
7. Do not attach Kali or intentionally vulnerable targets to Bridged Adapter.

VirtualBox can operate alongside some Windows hypervisor features using its supported backend, but performance and feature availability can vary. Do not disable VBS, Memory Integrity, Hyper-V or WSL2 blindly to troubleshoot it; inspect the VirtualBox log and the current Oracle/Windows compatibility guidance first.

## 3. Storage layout

Create a simple layout on the VM SSD:

```text
D:\CyberLab\
  ISO\
  VMs\
  Exports\
  Evidence\
  Backups\
```

Keep original ISO files and checksums in `ISO`. Store exported sanitised evidence separately from VM disks. Do not treat snapshots as backups; copy important VM exports or data to a separate device.

## 4. First VM smoke test

Create an Ubuntu Server x86-64 VM:
- Generation 2 / UEFI on Hyper-V.
- 2 vCPU.
- 4 GB RAM (dynamic memory may be enabled for this small utility VM).
- 40 GB virtual disk.
- NIC attached to the management-only/internal network during initial setup.
- Attach the official Ubuntu Server x86-64 ISO.

Install using the Ubuntu installer. Create a non-root user, enable OpenSSH only if required, and apply updates. Record the Ubuntu release and kernel.

After boot:

```bash
uname -m
lsblk
ip -br address
ip route
sudo apt update
sudo apt upgrade -y
```

Expected architecture on this host: `x86_64`. If `uname -m` shows something else, stop and verify which ISO you installed.

## 5. Snapshots and baseline

Before installing agents or security tools:
1. Shut down the VM cleanly.
2. Create a snapshot/checkpoint named `baseline-clean`.
3. Record VM settings and guest OS version.
4. Boot and confirm the snapshot is visible.
5. Restore the snapshot once to prove the recovery workflow works.

For domain controllers and SIEM servers, use application-aware backups for persistent data; snapshots alone are not a safe backup strategy.

## 6. Validation checklist

- [ ] Host CPU architecture is x64.
- [ ] Firmware virtualisation is enabled.
- [ ] Hypervisor starts after reboot.
- [ ] Management and private networks are created.
- [ ] No vulnerable/attacker VM is connected to a bridged network.
- [ ] Ubuntu guest boots and reports x86_64.
- [ ] VM storage is on SSD with sufficient free space.
- [ ] Baseline snapshot/checkpoint can be restored.

## References

- [Microsoft Hyper-V hardware requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements)
- [Microsoft Hyper-V virtual switch documentation](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/virtual-switch)
- [VMware Workstation and Fusion FAQ](https://www.vmware.com/docs/desktop-hypervisor-faqs)
