# Lab 2 — Apple-silicon MacBook host and hypervisor setup

<badge color="warning">Build guide — not yet lab-tested</badge>

This guide is for M-series Apple-silicon Macs. The guest operating systems must be ARM64/AArch64 builds unless the virtualisation product explicitly documents another supported mode. This is a separate ARM lab, not an x86-64 clone of the Windows PC lab.

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
2. Confirm the downloaded package is the Apple-silicon build supported by your macOS version.
3. Open the installer and complete the installation.
4. Launch Fusion and approve only the system permissions requested by the installer.
5. Review the current free-use/licensing terms during setup.
6. Open Fusion and confirm the application starts.
7. Create a small ARM Linux VM as a smoke test before building the full environment.

VMware Fusion supports Apple-silicon hosts; the exact guest OS support depends on Fusion version and guest architecture. See the current VMware FAQ and guest OS compatibility documentation.

## 3. Install Kali ARM64

1. Open the official [Kali download page](https://www.kali.org/get-kali/).
2. Select the Apple Silicon/ARM64 installer or the official VMware ARM image appropriate to the current release.
3. Download only from Kali's official site.
4. Verify SHA-256 against the checksum published alongside the image:

```bash
shasum -a 256 ~/CyberLab/ISO/<downloaded-file>
```

5. Compare the output exactly with the official checksum. Do not continue if it differs.
6. In Fusion, choose **Create a new virtual machine → Install from disc or image**, select the ARM64 ISO, and follow the Kali installer.
7. Suggested starting allocation: 4 vCPU, 6–8 GB RAM, 60–80 GB disk, one NIC on the isolated assessment network.
8. Complete the install, update Kali, and install VMware Tools/open-vm-tools if recommended for that guest image.
9. Verify:

```bash
uname -m
cat /etc/os-release
ip -br address
ip route
```

Expected architecture: `aarch64` or `arm64` depending on the command/tool.

## 4. Install Ubuntu Server ARM64

1. Download the ARM64 Server ISO from Ubuntu's official download page.
2. Verify the checksum published by Ubuntu.
3. In Fusion, create a VM from the ISO.
4. Start with 2 vCPU, 2–4 GB RAM and 40–60 GB disk.
5. Install a non-root user and OpenSSH only if remote administration is needed.
6. Update and verify architecture:

```bash
sudo apt update && sudo apt upgrade -y
uname -m
lsb_release -a
ip -br address
```

## 5. Windows 11 ARM guest

Microsoft publishes Windows 11 ARM ISO media and documents the limitations for x64 hosts. On Apple-silicon Macs, use a virtualisation application that explicitly supports Windows 11 ARM guest setup.

1. Download Windows 11 ARM media from Microsoft's official page.
2. Create a new Windows 11 ARM VM in Fusion using the supported virtual-machine wizard.
3. Configure a virtual TPM and Secure Boot if the hypervisor's Windows 11 workflow requires them.
4. Allocate at least 4 vCPU, 6–8 GB RAM and 80 GB disk as a starting point.
5. Install Windows and use a valid licence/activation method.
6. Apply Windows updates.
7. Verify **Settings → System → About → System type** shows an ARM-based processor.

Do not install an x64 Windows ISO in this ARM VM. Do not assume every Windows driver, endpoint agent or security tool supports Windows ARM. Verify each vendor's support matrix before relying on it.

## 6. Configure virtual networking

Use Fusion's network settings to create/identify:
- Shared/NAT networking for temporary OS updates.
- Host-only networking for private host-to-VM communication.
- Additional custom private segments if the Fusion version supports them.

Do not connect Kali and intentionally vulnerable targets to bridged networking. If a segment cannot be isolated on the Mac hypervisor, keep the vulnerable target local to the VM host and do not route it to the physical LAN. Record exactly which networks the installed Fusion version exposes.

The Mac can participate in a shared lab using a dedicated lab router/firewall or a tightly controlled private overlay, but do not assume Fusion host-only networks on the Mac and Hyper-V private switches on Windows are automatically Layer-2 connected. Cross-host connectivity requires an explicit network design.

## 7. Snapshot baseline and verify

1. Shut down each VM cleanly.
2. Create a baseline snapshot/checkpoint.
3. Restore one snapshot to verify the process.
4. Confirm each guest reports the expected ARM64 architecture.
5. Confirm the Kali target segment cannot reach your home LAN.
6. Record Fusion version, macOS build, guest image checksum, VM settings and IP plan.

## 8. Mac-specific limitations

- Security Onion is not supported on ARM; use the Windows x64 PC for that lab.
- Splunk Enterprise must be installed on a platform/architecture in Splunk's current support matrix. Do not assume the Splunk Enterprise server is supported natively on Apple-silicon macOS.
- Elastic Agent publishes macOS ARM64 packages, but each integration and feature has its own support requirements.
- Wazuh central components support ARM64 Linux according to its current requirements, but use the official supported OS/version list.
- Use ARM64 Kali and Ubuntu builds; do not mix x86-64 and ARM64 package repositories.

## References

- [Kali on VMware Fusion / Apple Silicon](https://www.kali.org/docs/virtualization/install-vmware-silicon-host/)
- [Kali official image downloads and checksums](https://www.kali.org/docs/introduction/download-official-kali-linux-images/)
- [VMware desktop hypervisor FAQ](https://www.vmware.com/docs/desktop-hypervisor-faqs)
- [Microsoft Windows 11 ARM ISO](https://learn.microsoft.com/en-us/windows/arm/iso)
- [Elastic Agent standalone installation — macOS ARM64 package example](https://www.elastic.co/docs/reference/fleet/install-standalone-elastic-agent)
- [Security Onion CPU architecture requirements](https://docs.securityonion.net/en/3/dev/hardware/)
