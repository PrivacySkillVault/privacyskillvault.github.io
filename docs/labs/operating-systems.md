# Lab 4 — Operating system installation and identity

<badge color="warning">Build guide — not yet lab-tested</badge>

This creates the Windows and Linux endpoints used by the SIEM and SOC labs. Use x64 media on the Windows PC and ARM64 media on the Apple-silicon Mac.

## A. Windows Server on the Windows PC

1. Download the current Windows Server Evaluation ISO from Microsoft's Evaluation Center. Check the release's evaluation period and terms.
2. Create a Generation 2 Hyper-V VM (or supported VMware VM): name PSV-DC01; 2–4 vCPU; 6 GB RAM; 80 GB disk; NIC on SERVER segment; UEFI and supported Secure Boot template.
3. Install Desktop Experience for GUI learning, patch the OS and install guest integration tools.
4. Set a static address such as 10.10.30.10/24. Configure a gateway only if the lab router exists.
5. Rename and reboot:

```powershell
Rename-Computer -NewName "PSV-DC01" -Restart
```

6. Install AD DS and DNS, then create the private lab forest:

```powershell
Install-WindowsFeature AD-Domain-Services,DNS -IncludeManagementTools
Install-ADDSForest -DomainName "lab.psv.test" -DomainNetbiosName "PSVLAB" -InstallDNS
```

Follow the prompts and set a unique Directory Services Restore Mode password. The server reboots after promotion. Use the reserved .test namespace, not a domain you do not own.

7. Verify:

```powershell
Get-ADDomain
Get-ADForest
Get-Service NTDS,DNS
dcdiag /v
nslookup -type=SRV _ldap._tcp.dc._msdcs.lab.psv.test
```

8. Create synthetic lab OUs/users only. Do not use real employee identities. Keep domain-controller DNS pointed to itself; configure DNS forwarders only if update access is required.

## B. Windows 11 endpoint on the Windows PC

1. Download official Windows 11 x64 media.
2. Create VM: 2–4 vCPU, 6–8 GB RAM, 80 GB disk, Generation 2, virtual TPM and Secure Boot as required by Windows 11/hypervisor, NIC on ENDPOINT.
3. Install a Windows edition that supports the domain-join features you intend to practise. Patch and install guest tools.
4. Rename the endpoint and reboot:

   ```powershell
   Rename-Computer -NewName "PSV-W11-01" -Restart
   ```

5. Set DNS to 10.10.30.10. Verify the domain controller resolves.
6. Join the lab domain:

```powershell
Add-Computer -DomainName "lab.psv.test" -Credential (Get-Credential) -Restart
```

Use a delegated join account rather than Domain Admin for routine joining. On PSV-DC01, create the lab workstation OU and move the joined endpoint computer object into it (replace the computer name if yours differs):

~~~powershell
New-ADOrganizationalUnit -Name "Lab-Workstations" -Path "DC=lab,DC=psv,DC=test" -ProtectedFromAccidentalDeletion $true
Get-ADComputer "PSV-W11-01" | Move-ADObject -TargetPath "OU=Lab-Workstations,DC=lab,DC=psv,DC=test"
~~~

Verify after reboot:

```powershell
systeminfo | findstr /B /C:"Domain"
nltest /dsgetdc:lab.psv.test
```

If joining fails, investigate DNS, time skew, routing, firewall policy and join permissions; do not disable security controls as a shortcut.

## C. Apply Windows audit policy with Group Policy

After the Windows endpoint is joined to the lab domain, use Group Policy Management on PSV-DC01:

1. Create a GPO named `PSV-Lab-Endpoint-Auditing` and link it to the `Lab-Workstations` OU.
2. Under **Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies**, enable:
   - **Account Management → Audit Security Group Management:** Success.
   - **Detailed Tracking → Audit Process Creation:** Success.
   - **Logon/Logoff → Audit Logon:** Success and Failure for this lab OU.
3. Under **Administrative Templates → System → Audit Process Creation**, enable **Include command line in process creation events** if you need Event 4688 command-line evidence. Command lines can contain secrets; keep this lab-only and sanitise evidence.
4. If practising PowerShell logging, enable **Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging** on the lab OU only. Script contents can contain sensitive data.
5. On the endpoint create the output folder, refresh policy, and verify the applied policy:

   ```powershell
   New-Item -ItemType Directory -Path C:\Temp -Force | Out-Null
   gpupdate /force
   gpresult /h C:\Temp\gpresult.html
   gpresult /r
   ```
6. Make a controlled local group membership change on the disposable endpoint. Confirm Event ID 4732 and TargetSid `S-1-5-32-544` for the built-in local Administrators group. The event proves a group membership change occurred; it does not prove malicious intent.

Do not apply this test GPO to production systems. Audit policy changes should be approved, event volume measured, and the GPO unlinked/removed after the lab if no longer required.

## C. Ubuntu Server on either host

Download the matching architecture ISO from Ubuntu and verify its published SHA-256 checksum. Create a VM with 2 vCPU, 2–4 GB RAM, 40–60 GB disk, and the appropriate SERVER or ENDPOINT NIC. Install a named non-root user; enable OpenSSH only if needed.

```bash
sudo apt update && sudo apt full-upgrade -y
sudo reboot
uname -m
cat /etc/os-release
lsblk -f
ip -br address
ip route
systemctl --failed
```

Expected architecture: x86_64 on Windows PC; aarch64 on Apple Silicon Mac.

Optional audit telemetry:

```bash
sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd
sudo auditctl -s
```

Add only the audit rules needed for the exercise and measure event volume before forwarding.

## D. Kali Linux

Download the official Kali image matching the host/guest architecture and verify the checksum. Create a VM with 2–4 vCPU, 4–8 GB RAM and 60 GB disk. Attach it only to REDTEAM; use temporary NAT only for updates and disconnect it before testing.

```bash
sudo apt update && sudo apt full-upgrade -y
sudo reboot
uname -m
cat /etc/os-release
ip -br address
ip route
```

Use Kali repositories for tools. Start with Nmap, Wireshark, Burp Suite Community and browser developer tools. Test only lab-owned targets.

## E. Windows 11 ARM on the Mac

Use Microsoft's official Windows 11 ARM ISO and a virtualisation application that explicitly supports Windows 11 ARM. Configure the required virtual TPM and Secure Boot using the hypervisor wizard. Start with 4 vCPU, 6–8 GB RAM and 80 GB disk. Install, activate with a valid licence, update, and verify System type reports ARM-based processor.

Do not install x64 Windows media in an ARM VM. Confirm that every endpoint agent, driver and security product supports Windows ARM before relying on it.

For the exact local event-generation tests and Windows Security/Sysmon, Linux auditd/journald and macOS Unified Logging procedures, follow the [Cross-platform Endpoint Telemetry Implementation Runbook](endpoint-telemetry-implementation.md).

## F. Mac endpoint telemetry considerations

macOS host and guest telemetry uses Apple's Unified Logging system and other OS-specific sources; it is not Windows Event Log. Use an agent only when the vendor documents support for the exact macOS release and Apple-silicon architecture. Wazuh documents collection from macOS Unified Logging; Elastic Agent and other products must be checked against their current macOS support matrix. Do not assume Sysmon for Windows, Windows Event Channel integrations or x64 endpoint agents work on macOS/Windows ARM.

## G. Baseline evidence

For each VM record ISO URL/checksum, OS build, architecture, hypervisor/version, CPU/RAM/disk, virtual NIC and IP. Patch the VM, create a clean snapshot, and verify it restores. A snapshot is not a backup, especially for domain controllers or SIEM databases.

## Official references

- [Microsoft Windows Server Evaluation Center](https://www.microsoft.com/en-us/evalcenter/)
- [Install AD DS using PowerShell](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-a-new-windows-server-2016-active-directory-forest)
- [Windows 11 download](https://www.microsoft.com/software-download/windows11)
- [Windows 11 ARM ISO](https://learn.microsoft.com/en-us/windows/arm/iso)
- [Ubuntu Server installation](https://ubuntu.com/server/docs)
- [Kali downloads](https://www.kali.org/get-kali/)
