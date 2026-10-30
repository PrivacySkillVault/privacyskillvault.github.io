# Hardware and platform compatibility

<badge color="warning">Planning guide — verify exact host models and versions</badge>

## 1. Confirm hardware before downloading images

On Windows PowerShell:

```powershell
Get-ComputerInfo | Select-Object CsName, WindowsProductName, WindowsVersion, OsArchitecture, CsTotalPhysicalMemory
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, VirtualizationFirmwareEnabled, SecondLevelAddressTranslationExtensions
Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining
systeminfo.exe
```

On Mac Terminal:

```bash
uname -m
system_profiler SPHardwareDataType
df -h /
sysctl hw.memsize
```

Expected Apple-silicon architecture: `arm64`. Record exact chip, RAM, macOS version and free storage.

For Hyper-V, confirm supported Windows edition, CPU SLAT, firmware virtualisation and DEP. Hyper-V is not available as a client feature on every Windows edition; if Windows Home is installed, use a supported alternative such as VMware Workstation.

## 2. Architecture compatibility matrix

| Workload | Windows x64 PC | Apple-silicon Mac |
|---|---|---|
| Windows 11 x64 guest | Yes, with supported hypervisor | No native x64 guest in Fusion; use Windows 11 ARM |
| Windows 11 ARM guest | Not on x64 Hyper-V host | Yes, using supported ARM virtualisation |
| Ubuntu x86-64 guest | Yes | No native x64 guest in Fusion |
| Ubuntu ARM64 guest | Depends on host hypervisor | Yes |
| Kali x86-64 guest | Yes | No native x64 guest in Fusion |
| Kali ARM64 guest | Depends on host hypervisor | Yes |
| Splunk Enterprise | Supported x64 Windows/Linux platform | ARM64 is not supported for Splunk Enterprise |
| Splunk Universal Forwarder | Supported platforms in current Splunk matrix | Do not assume ARM64 support; check the exact Darwin architecture table |
| Elastic Stack | Supported x64 Linux deployment | ARM64 Linux components are supported where listed in Elastic's current support matrix |
| Wazuh central components | Supported x64 Linux | Supported 64-bit ARM Linux on listed OS versions |
| Security Onion | Yes, x86-64 only | No; ARM is explicitly unsupported |
| Zeek / Suricata | Supported Linux builds | ARM builds where the selected release/package supports them |
| OWASP Juice Shop | Docker image/platform must match guest | Verify the published ARM64 image manifest |

**Apple Silicon limitation:** VMware Fusion on Apple Silicon supports 64-bit ARM guests only; x86 guest operating systems are not supported. Windows 11 ARM guests have additional Fusion limitations: VBS, WSL2, Windows Sandbox and Windows Defender Application Guard require nested virtualisation and are not available in this configuration.

## 3. Practical planning allocations

These are home-lab planning recommendations, not vendor minimums for every component.

- **Windows PC:** 32 GB RAM supports a reduced lab; 64 GB is a more useful target. Prefer 1 TB NVMe SSD or more and keep at least 150–250 GB free for VM disks and snapshots.
- **MacBook:** 16 GB can run one small ARM Linux VM; 24 GB or more is preferable. Keep 150 GB free for a useful subset.
- **Security Onion Standalone:** vendor bare minimum is 4 CPU cores, 24 GB RAM, 200 GB storage and 2 NICs. 32 GB RAM or more is a better home-lab target. It is x86-64 only.
- **Wazuh all-in-one quickstart:** current official sizing for 1–25 agents is 4 vCPU, 8 GiB RAM and 50 GB storage for 90 days of indexed alert data. More agents/retention require more.
- **Elastic single-node lab:** 4–8 vCPU, 12–16 GB RAM and 150–200 GB is a practical starting point, not an Elastic production minimum.
- **Splunk:** check current release-specific OS and hardware requirements. Do not treat generic RAM figures as official sizing.

Run one major SIEM stack at a time. Reserve memory for the host OS and hypervisor.

## 4. Media, support and licence checks

- Windows Server/Windows client media: Microsoft Evaluation Center/download pages; read the exact evaluation and activation terms.
- Kali: official Kali images only; verify SHA-256.
- VMware Fusion/Workstation: Broadcom's official portal; verify host and guest compatibility for exact release.
- Splunk Enterprise and Universal Forwarder: current Splunk support matrix lists supported OS/architecture combinations. Splunk Enterprise does not support ARM architecture; Windows ARM is not a supported Enterprise/Universal Forwarder platform in the cited current matrix. Use x64 Windows/Linux on the PC.
- Elastic: verify the exact Elasticsearch, Kibana, Agent and integration versions in Elastic's support matrix. Keep components on a compatible release family.
- Wazuh: central components support x86_64/AMD64 and AARCH64/ARM64 Linux on listed OS versions.
- Security Onion: x86-64 only.

## 5. References

- [Microsoft Hyper-V host requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements)
- [Microsoft Windows 11 ARM ISO](https://learn.microsoft.com/en-us/windows/arm/iso)
- [Broadcom Fusion ARM guest compatibility](https://knowledge.broadcom.com/external/article/315602)
- [Splunk Enterprise 10.6 on-premises system requirements](https://help.splunk.com/en/splunk-enterprise/administer/install-and-upgrade/10.6/plan-your-splunk-enterprise-installation/system-requirements-for-use-of-splunk-enterprise-on-premises)
- [Elastic Support Matrix](https://www.elastic.co/support/matrix)
- [Wazuh Quickstart requirements](https://documentation.wazuh.com/current/quickstart.html)
- [Security Onion hardware requirements](https://docs.securityonion.net/en/3/dev/hardware/)
