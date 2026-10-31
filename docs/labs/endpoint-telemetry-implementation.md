# Endpoint telemetry implementation — Windows, Linux and macOS

<badge color="warning">Pre-SIEM source configuration — verify locally before installing collectors</badge>

This guide proves endpoint event generation on each platform. The Windows x64 and Apple Silicon Mac tracks are not interchangeable: Windows Security Event Log/Sysmon, Linux audit/journal and macOS Unified Logging are different data sources. Do not install a Windows collector or Sysmon configuration on macOS and assume equivalent coverage.

## 1. Common preparation

For each endpoint record hostname, OS/build, architecture, IP, DNS, NTP/timezone, interface, agent support matrix and snapshot. Use a dedicated synthetic lab account and benign test actions. Do not collect employer, customer or personal data.

The endpoint must have:
- A stable hostname and correct time.
- Network access only to required DNS/NTP, domain services (where used), and the later SIEM/agent endpoints.
- A local event source configured and verified before any SIEM agent is installed.
- A written retention plan and an evidence directory that excludes credentials and tokens.

## 2. Windows 11 x64 — Advanced Audit Policy

Complete domain join and lab GPO preparation in [Operating Systems & Identity](operating-systems.md).

Create a lab-only GPO and link it only to the test workstation OU. Configure:
- Account Management → Audit Security Group Management: Success.
- Detailed Tracking → Audit Process Creation: Success.
- Logon/Logoff → Audit Logon: Success and Failure.
- Administrative Templates → System → Audit Process Creation → Include command line in process creation events: Enabled only if command-line capture is needed.

Command lines may contain passwords, tokens or personal data. Keep command-line auditing confined to disposable lab endpoints and sanitize evidence.

On the endpoint:

~~~powershell
New-Item -ItemType Directory -Path C:\Temp -Force | Out-Null
gpupdate /force
gpresult /h C:\Temp\psv-gpo-result.html
auditpol /get /category:*
~~~

Generate a controlled local Administrators group membership change on the disposable endpoint. Run PowerShell as Administrator and use a temporary local account:

~~~powershell
$Password = Read-Host "Temporary lab account password" -AsSecureString
New-LocalUser -Name "PSV-LabTestUser" -Password $Password -Description "Temporary telemetry test"
Add-LocalGroupMember -Group "Administrators" -Member "PSV-LabTestUser"
Get-LocalGroupMember -Group "Administrators"
~~~

Confirm Security Event ID 4732 and verify the target group SID is S-1-5-32-544. Then remove the test membership and account:

~~~powershell
Remove-LocalGroupMember -Group "Administrators" -Member "PSV-LabTestUser"
Remove-LocalUser -Name "PSV-LabTestUser"
~~~

Event 4732 shows a membership change, not malicious intent; the removal should also generate a corresponding group-membership event.

Generate a benign process event:

~~~powershell
Start-Process notepad.exe
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id = 4688
  StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 5 | Format-List TimeCreated,Id,ProviderName,Message
~~~

If no 4688 appears, verify the audit subcategory, effective GPO, policy precedence and process creation; do not troubleshoot the SIEM yet.

## 3. Windows 11 x64 — Sysmon

Download Sysmon only from Microsoft's Sysinternals page. Create the tools directory, extract the downloaded archive into it, verify the Microsoft signature and record the file version:

Install using the Microsoft Sysmon default configuration for the first smoke test:

~~~powershell
New-Item -ItemType Directory -Path C:\CyberLab\Tools\Sysmon -Force | Out-Null
# Change the source path if the browser saved the official ZIP elsewhere.
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\Sysmon.zip" -DestinationPath C:\CyberLab\Tools\Sysmon -Force
cd C:\CyberLab\Tools\Sysmon
$Signature = Get-AuthenticodeSignature .\Sysmon64.exe
if ($Signature.Status -ne 'Valid') { throw 'Sysmon signature validation failed; do not install this binary.' }
$Signature | Format-List Status,SignerCertificate
.\Sysmon64.exe -accepteula -i
Get-Service Sysmon64
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
~~~

Generate Notepad process creation and verify Sysmon Event ID 1 locally:

~~~powershell
Start-Process notepad.exe
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1
  StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 5 | Format-List TimeCreated,Id,Message
~~~

The default Sysmon configuration can generate substantial telemetry. Before broad collection, review Microsoft's configuration guidance, select only required event classes, estimate event volume, and document exclusions. Do not install an unknown community XML configuration without reviewing its rules and provenance.

To inspect configuration and version:

~~~powershell
.\Sysmon64.exe -c
.\Sysmon64.exe -?
~~~

For a controlled uninstall after the lab, use the documented Sysmon uninstall command and verify the service/event channel state. Snapshot before major configuration changes.

## 4. Linux — journald and auditd

On supported Ubuntu Server:

~~~bash
sudo apt update
sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd
sudo systemctl status auditd --no-pager
sudo auditctl -s
sudo journalctl --since '10 minutes ago' --no-pager | tail -n 50
~~~

Add only lab-specific audit rules. Example: monitor changes to a dedicated test file, not the entire filesystem:

~~~bash
sudo install -d -m 0750 /opt/psv-audit-test
sudo auditctl -w /opt/psv-audit-test -p wa -k psv_lab_file_change
sudo touch /opt/psv-audit-test/test.txt
sudo sh -c 'echo test >> /opt/psv-audit-test/test.txt'
sudo ausearch -k psv_lab_file_change -ts recent -i
~~~

For persistence, create /etc/audit/rules.d/psv-lab.rules containing the same reviewed watch rule (`-w /opt/psv-audit-test -p wa -k psv_lab_file_change`). Then run `sudo augenrules --check`, `sudo augenrules --load`, and `sudo auditctl -l` to confirm it is active. Do not rely on runtime-only auditctl rules after reboot. Confirm auditd log rotation and disk capacity.

For system logs:

~~~bash
sudo journalctl -u ssh --since '1 hour ago' --no-pager
sudo journalctl -k --since '1 hour ago' --no-pager
~~~

The service name and journal contents vary by distribution. Record the exact source and event query used.

## 5. macOS — Unified Logging

macOS uses Unified Logging, not Windows Event Log. Start with local proof on the Apple Silicon Mac or a supported macOS VM:

~~~bash
uname -m
sw_vers
sudo -v
log show --last 10m --style json --predicate 'process == "sudo"'
~~~

Generate a harmless test event, then query the relevant process/subsystem. Unified Logging privacy controls can redact sensitive fields. Do not try to bypass macOS privacy protections or collect protected data without explicit permission.

### Wazuh macOS collection

Wazuh documents a macOS Unified Logging input using the agent's localfile configuration. The example below is a minimal test input; validate against the exact Wazuh agent version and query syntax:

~~~xml
<localfile>
  <location>macos</location>
  <log_format>macos</log_format>
  <query type="log,trace,activity">
    process == "sudo"
  </query>
</localfile>
~~~

On macOS the Wazuh agent configuration path is commonly /Library/Ossec/etc/ossec.conf. Back up the file, validate XML, restart the agent using the installed package's documented service method, and inspect the agent log. Confirm the test record appears in the Wazuh manager with correct host/time fields.

### Elastic Agent on macOS

Elastic Agent provides macOS integrations, including macOS Security Events based on Unified Logging, but the exact integration categories and required permissions depend on macOS and Elastic versions. Check the Elastic Support Matrix and integration documentation before deployment. Enrol through Fleet using the generated command, grant only the documented permissions, and verify actual raw events in Discover. Do not assume that every Unified Logging category is accessible to a non-privileged process.

### Splunk on macOS

Check the current Splunk Universal Forwarder platform matrix for the exact macOS release and ARM64 architecture. Splunk Enterprise is not an ARM64 macOS deployment target. Do not assume that Windows Event Log inputs or Sysmon channels exist on macOS. Use only supported macOS inputs and validate raw events.

## 6. Windows ARM caveat

Windows 11 ARM is not equivalent to Windows 11 x64 for security agents, kernel drivers and endpoint products. Check each agent/driver vendor support matrix for the exact Windows ARM release. If unsupported, treat Windows ARM as a general endpoint exercise only; use Windows x64 on the PC for the fully supported Windows telemetry path.

## 7. Local source acceptance gate

- [ ] Windows Security 4688 exists after controlled process creation.
- [ ] Windows Security 4732 exists after controlled group membership change.
- [ ] Sysmon Event ID 1 exists after Notepad launch.
- [ ] Linux auditd test event exists and survives reboot if persistence was configured.
- [ ] Linux journal test query returns expected local records.
- [ ] macOS Unified Logging query returns the intended test event.
- [ ] Agent support is confirmed for exact OS/build/architecture.
- [ ] Time, hostname, event identity and source channel are recorded.
- [ ] Event volume, permissions and retention are understood.
- [ ] Test changes are reverted and evidence sanitized.

Only after this gate passes should you configure Elastic Agent, Splunk Universal Forwarder or Wazuh agent as described in the selected SIEM guide.

## References

- [Microsoft Advanced Audit Policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Microsoft process creation auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Linux audit documentation](https://man7.org/linux/man-pages/man8/auditd.8.html)
- [Wazuh macOS Unified Logging](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html)
- [Elastic macOS Security Events integration](https://www.elastic.co/docs/reference/integrations/macos)
- [Elastic Support Matrix](https://www.elastic.co/support/matrix)
- [Splunk platform support](https://www.splunk.com/en_us/download/universal-forwarder.html)
