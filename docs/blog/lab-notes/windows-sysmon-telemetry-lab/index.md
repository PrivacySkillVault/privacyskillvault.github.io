# Lab Notes: Building a Windows Endpoint Telemetry Pipeline with Sysmon

<small>LAB NOTES · CONTROLLED HOME LAB · 01 NOV 2026</small>

<p class="psv-article-breadcrumb"><a href="../">← Lab Notes</a><span> / </span><a href="../../">Cyber Journal</a></p>

A SIEM dashboard is only as useful as the telemetry feeding it. This lab focuses on one endpoint and one objective: generate Windows activity, collect Sysmon events, forward them to a central analysis platform, and prove that the events arrive with useful fields.

**Scope:** an isolated virtual machine that you own. Do not run simulations on production endpoints or networks. This article is a build plan and validation guide; it does not claim that a specific deployment has already been tested.

## 1. Lab architecture

~~~text
[Windows test VM]
  Windows Event Log
  Sysmon service
       |
       | Windows Event Channel
       v
[Telemetry shipper / agent]
       |
       | authenticated transport
       v
[SIEM / log collector]
       |
       v
[Search, dashboards, detection rules]
~~~

Keep the endpoint and SIEM on a lab network. Use snapshots before changing audit policy or installing agents. Synchronise system clocks and record the timezone.

## 2. Prepare the Windows endpoint

1. Install a supported Windows version in a virtual machine.
2. Apply updates and install the guest tools required by your hypervisor.
3. Set a clear hostname and static or reserved lab address.
4. Confirm DNS and time synchronisation.
5. Create a non-administrator test account for ordinary activity.
6. Take a clean snapshot before installing monitoring components.

## 3. Install Sysmon from Microsoft

Download Sysmon only from the official Microsoft Sysinternals page. Review the licence and current requirements before installation.

Sysmon writes structured events to the Windows Event Log. The common channel on modern Windows systems is:

~~~text
Applications and Services Logs
  Microsoft
    Windows
      Sysmon
        Operational
~~~

For a basic lab installation, Microsoft documents the command pattern:

~~~powershell
sysmon64.exe -accepteula -i
~~~

For ongoing use, prefer a reviewed configuration file. Do not blindly enable every event type: some sources, particularly image-load and process-access events, can generate substantial volume. Validate the configuration schema against the Sysmon binary installed.

## 4. Select useful event types

Start with a small, explainable set:

| Event ID | Event | Investigation value |
|---|---|---|
| 1 | Process creation | Process, parent, command line, hashes, Process GUID |
| 3 | Network connection | Process-associated network activity; disabled by default |
| 11 | File creation | Files created or overwritten |
| 12–14 | Registry events | Registry key/value creation and modification |
| 22 | DNS query | Process-associated DNS lookups |

Treat these as telemetry, not verdicts. A process creation event does not mean the process is malicious. Configure only what you can collect, retain, and investigate.

## 5. Forward events to the SIEM

Configure your chosen supported shipper to read the Sysmon Operational channel. Use the vendor's current integration or agent documentation for the exact configuration syntax; do not copy an outdated configuration from an unrelated version.

At minimum, verify:

- The correct channel is subscribed.
- The agent service is running.
- The endpoint can reach the collector over the approved lab path.
- Transport authentication and certificate validation are enabled where supported.
- The event timestamp, host identity, channel, provider, and event ID are preserved.
- Agent errors and dropped-event counters are monitored.

## 6. Generate safe test activity

Use benign actions on the lab VM:

- Launch Notepad and PowerShell interactively.
- Create a text file in a test directory.
- Query a public documentation domain using a normal browser or DNS lookup.
- Create and remove a harmless test registry value in a dedicated lab key.

Do not use malware, credential-dumping tools, destructive payloads, or real phishing infrastructure for this validation.

## 7. Validate end to end

| Test | Expected evidence | Pass condition |
|---|---|---|
| Process launch | Sysmon Event 1 | Process and parent fields visible |
| File creation | Sysmon Event 11 | Test file path and process context visible |
| DNS query | Sysmon Event 22 | Query and process context visible |
| Network event | Event 3 if explicitly enabled | Connection record visible |
| Forwarding | SIEM event search | Same event ID, host and timestamp are searchable |
| Resilience | Restart agent in lab | Collection resumes and any gap is documented |

A green agent status is not proof of complete telemetry. Compare event counts at the source and destination and inspect the agent's own logs.

## 8. Common troubleshooting points

- Wrong channel name or permissions.
- Agent subscription not restarted after configuration changes.
- Host clock drift or timezone confusion.
- Parser mapping the event ID or provider incorrectly.
- Firewall rule blocking collector traffic.
- Excessive event filtering.
- Disk or queue limits causing drops.
- Duplicate collection by two agents.

## 9. What to document

Record VM specifications, Windows build, Sysmon version, configuration hash, agent version, SIEM version, network path, event IDs enabled, test actions, search results, known gaps, and snapshot/rollback procedure.

## References

- [Microsoft Sysmon — official download and documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Microsoft Sysmon event guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft PowerShell logging](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging)

*Lab status: build guide, not a claim of successful execution. Add screenshots and measured results only after you perform the steps in your own environment.*