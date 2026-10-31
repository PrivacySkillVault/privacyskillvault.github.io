# Lab 2 — Apple-silicon MacBook host and hypervisor setup

<badge color="warning">Build guide — not yet lab-tested</badge>

This guide is for M-series Apple-silicon Macs. VMware Fusion on Apple Silicon runs 64-bit ARM guests only; x86-64 operating-system images do not run as Fusion guests. UEFI firmware is required. Use the Broadcom Compatibility Guide to confirm support for the exact guest OS release.

## 1. Preflight

Open Terminal:

```bash
uname -m
system_profiler SPHardwareDataType
sw_vers
df -h /
sysctl hw.memsize
```

Expected host architecture: `arm64`. Record chip, unified memory, macOS version and free SSD capacity.

1. Update macOS through System Settings after backing up important data.
2. Ensure sufficient free space; use a fast SSD for VM storage.
3. Do not disable macOS security protections simply to make a VM install.
4. Create `~/CyberLab/{ISO,VMs,Evidence,Exports}` or an equivalent external SSD directory.

## 2. Install VMware Fusion

1. Download VMware Fusion from Broadcom's official desktop hypervisor portal.
2. Confirm the package supports the installed macOS version and Apple-silicon host.
3. Install, launch and approve only the system permissions requested by the installer.
4. Review the current licensing terms during setup.
5. Create a small ARM Linux VM as a smoke test.
6. For ARM guests, use UEFI firmware, virtual NVMe storage and vmxnet3 networking where the guest/hypervisor wizard offers those settings.

## 3. Install Kali ARM64

1. Download the official Kali Apple Silicon/ARM64 installer or VMware image.
2. Verify SHA-256 against the checksum published alongside the image:

```bash
shasum -a 256 ~/CyberLab/ISO/<downloaded-file>
```

3. Compare the output exactly with the official checksum. Stop if it differs.
4. In Fusion, create a VM from the ARM64 ISO/image.
5. Suggested starting allocation: 4 vCPU, 6–8 GB RAM, 60–80 GB disk, one NIC on the isolated assessment network.
6. Complete the install, update Kali, and install open-vm-tools only if recommended for that guest image.
7. Verify:

```bash
uname -m
cat /etc/os-release
ip -br address
ip route
```

Expected architecture: `aarch64` or `arm64`, depending on the command.

## 4. Install Ubuntu Server ARM64

1. Download Ubuntu Server ARM64 media from Ubuntu's official page.
2. Verify its published checksum.
3. Create a Fusion VM from the ARM64 image: 2 vCPU, 2–4 GB RAM, 40–60 GB disk.
4. Install a non-root user; enable OpenSSH only if remote administration is required.
5. Update and verify:

```bash
sudo apt update && sudo apt upgrade -y
uname -m
lsb_release -a
ip -br address
```

## 5. Windows 11 ARM guest

1. Download Windows 11 ARM media from Microsoft's official page.
2. Create a Windows 11 ARM VM using Fusion's supported wizard.
3. Configure virtual TPM and Secure Boot as required by the wizard.
4. Allocate 4 vCPU, 6–8 GB RAM and 80 GB disk as a starting point.
5. Install Windows, activate using a valid licence, update, and confirm System type reports an ARM-based processor.

**Important limitations:** VMware documents limited VMware Tools functionality for Windows ARM guests. Nested-virtualisation-dependent features including VBS, WSL2, Windows Sandbox and Windows Defender Application Guard do not function in this configuration. Do not plan to run Docker Desktop with its WSL2 backend inside this guest. Use a separate Ubuntu ARM VM for Docker-based vulnerable applications. Check endpoint-agent and EDR vendor support for Windows ARM before using this guest to represent a managed enterprise endpoint.

## 6. Configure virtual networking

Identify Fusion's shared/NAT and host-only networks. Use NAT only for temporary OS updates and host-only/private networking for lab traffic. Do not connect Kali or intentionally vulnerable targets to bridged networking.

Fusion host-only networks and Windows Hyper-V private switches are local to each host. They are not automatically Layer-2 connected. Cross-host connectivity needs a deliberate lab firewall/router or separate isolated labs forwarding telemetry over a controlled management network.

## 7. Create the isolated Fusion networks

Fusion provides NAT and Host-only networking by default. Fusion Pro also supports custom virtual networks through its Network preferences, but do not assume an arbitrary number of networks exists before creating and inspecting them.

1. Shut down VMs before changing network layout.
2. Open VMware Fusion → Settings/Preferences → Network. Unlock the settings if prompted.
3. Use the **+** control to add a custom network. Give it a descriptive name (for example, PSV-ENDPOINT); repeat for the segments your installed release permits.
4. Inspect each network's subnet and DHCP setting. Record the actual vmnet name, subnet, host connectivity and DHCP status.
5. Use the default NAT network only for the router's WAN/update path.
6. Use separate custom/host-only networks for MGMT, ENDPOINT, SERVER, REDTEAM and DMZ. Disable Fusion DHCP on internal networks served by the router; do not create duplicate DHCP services.
7. If the installed Fusion version cannot provide enough independent networks, stop and use a dedicated physical firewall/managed-switch design or reduce the lab to a clearly documented smaller topology. Do not claim segmentation when all guests share one host-only network.

Attach the ARM64 router VM to WAN plus each independent internal network. Map adapters to roles by MAC address and verify with `ip -br link` before applying Netplan. Keep Kali and vulnerable targets off Bridged networking.

## 8. Snapshot and verify

1. Shut down each VM cleanly.
2. Create a baseline snapshot.
3. Restore one snapshot to test recovery.
4. Confirm guest architecture and NIC segment.
5. Verify Kali/target cannot reach the home LAN.
6. Record Fusion version, macOS build, ISO checksum, VM settings and network plan.

## 9. References

- [Broadcom: Arm guest OS compatibility in Fusion on Apple Silicon](https://knowledge.broadcom.com/external/article/315602)
- [Broadcom: Understanding networking types in VMware Fusion](https://knowledge.broadcom.com/external/article/303393)
- [Broadcom: Add custom Fusion networks](https://knowledge.broadcom.com/external/article/311759)
- [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/)
- [Kali on VMware Fusion / Apple Silicon](https://www.kali.org/docs/virtualization/install-vmware-silicon-host/)
- [Kali official image verification](https://www.kali.org/docs/introduction/download-official-kali-linux-images/)
- [Microsoft Windows 11 ARM ISO](https://learn.microsoft.com/en-us/windows/arm/iso)
- [VMware desktop hypervisor FAQ](https://www.vmware.com/docs/desktop-hypervisor-faqs)
