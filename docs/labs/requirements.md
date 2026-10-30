# Hardware and platform compatibility

<badge color="warning">Planning guide — verify exact host models and versions</badge>

## 1. Confirm hardware before downloading images

Record these values on both machines.

### Windows PC

Run PowerShell as Administrator:

```powershell
Get-ComputerInfo | Select-Object CsName, WindowsProductName, WindowsVersion, OsArchitecture, CsTotalPhysicalMemory
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, VirtualizationFirmwareEnabled, SecondLevelAddressTranslationExtensions
Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining
systeminfo.exe
```

For Hyper-V, confirm supported Windows edition, CPU SLAT, firmware virtualisation and DEP. Microsoft lists the Hyper-V hardware prerequisites in its official documentation. Hyper-V is not available as a client feature on every Windows edition; if the PC runs Windows Home, use a supported alternative such as VMware Workstation rather than following Hyper-V steps blindly.

### Apple-silicon Mac

Run Terminal:

```bash
uname -m
system_profiler SPHardwareDataType
df -h /
sysctl hw.memsize
```

Expected architecture for an Apple-silicon host: `arm64`. Confirm the exact M-series chip, unified memory, macOS version and free internal/external SSD space.

## 2. Architecture compatibility matrix

| Workload | Windows x64 PC | Apple-silicon Mac |
|---|---|---|
| Windows 11 x64 guest | Yes, with supported hypervisor | Not native; use Windows 11 ARM guest instead |
| Windows 11 ARM guest | Not supported by Hyper-V on x64 host | Yes, using supported ARM virtualisation |
| Ubuntu x86-64 guest | Yes | Not native; avoid relying on emulation for performance |
| Ubuntu ARM64 guest | Hyper-V/VMware support depends on host and product | Yes |
| Kali x86-64 guest | Yes | Not native |
| Kali ARM64 guest | Depends on host virtualisation support | Yes; use Kali's Apple Silicon instructions |
| Splunk Enterprise | Use supported x64 Windows/Linux platform | Do not assume native Splunk Enterprise support on macOS ARM |
| Elastic Stack | Use a supported x64 Linux deployment | ARM64 deployment is possible only where the exact Elastic component/version supports it |
| Wazuh central components | Supported x64 Linux host | Wazuh documentation supports ARM64 Linux for central components, subject to version-specific support |
| Security Onion | Yes, x86-64 only | No: current Security Onion documentation explicitly excludes ARM |
| Zeek / Suricata | Supported Linux builds | ARM builds can be used where project/package support exists; validate the chosen release |
| OWASP Juice Shop | Yes, Docker supported | Yes, Docker supported; check image platform manifest |

**Important architecture rule:** a VM guest must match the virtualisation platform's supported guest architecture. Do not assume an x86-64 ISO can be installed as an ARM64 VM or that translation is equivalent to native virtualisation.

## 3. Practical minimums

- **Windows PC:** 32 GB RAM can build a reduced lab; 64 GB is a much better target for the full programme. Prefer 1 TB NVMe SSD or more. Keep 150–250 GB free for VM growth and snapshots. A dedicated GPU is useful for other workloads but not required for these SIEM labs.
- **MacBook:** 16 GB can run one small ARM Linux VM; 24 GB or more is preferable. Keep 150 GB free for a useful subset. Do not plan to run Security Onion or several x86 SIEM VMs on the Mac.
- **External storage:** use a fast SSD formatted for the host OS and supported by the hypervisor. Do not store active VM disks on slow removable flash media. Keep backups separate from snapshots.

These are planning recommendations, not minimums published by every vendor.

## 4. Licence and media

- Windows client and Server evaluation media must come from Microsoft. Evaluation periods and activation conditions vary by release; read the terms displayed for the exact image.
- Kali images must come from Kali's official download site. Verify SHA-256 before importing or installing.
- Download VMware Fusion/Workstation from Broadcom's official VMware desktop hypervisor portal. The current vendor FAQ describes free availability and supported host families; verify the terms during download.
- Download Splunk Enterprise and any Universal Forwarder only from Splunk. Confirm current trial/developer/free licence terms before the install; do not assume a trial can be used indefinitely or that all features remain available after expiry.
- Download Elastic components from Elastic and keep Elasticsearch, Kibana, Fleet Server and Elastic Agent on a compatible release family. Prefer the same version family for a learning deployment.
- Download Wazuh components from official Wazuh repositories and use the documented installation assistant.

## 5. Sizing reality

A VM's configured RAM is reserved or consumed differently by different hypervisors. The practical limit is the total active workload, not the sum of VM settings alone. Start with one VM, measure host memory pressure and disk latency, then add the next service.

Do not enable nested virtualisation unless a lab specifically requires it. Nested hypervisors add complexity and are not needed for the core SOC/pentest labs.

## References

- [Hyper-V host hardware requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements)
- [Windows 11 ARM ISO and architecture limitations](https://learn.microsoft.com/en-us/windows/arm/iso)
- [VMware desktop hypervisor FAQ](https://www.vmware.com/docs/desktop-hypervisor-faqs)
- [Kali official downloads and verification](https://www.kali.org/docs/introduction/download-official-kali-linux-images/)
- [Security Onion hardware and CPU architecture](https://docs.securityonion.net/en/3/dev/hardware/)
- [Wazuh quickstart requirements](https://documentation.wazuh.com/current/quickstart.html)
