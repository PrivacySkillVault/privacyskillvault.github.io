# Living off the Land: Why Legitimate Tools Can Look Suspicious

<small>THREAT ANALYSIS · DEFENSIVE EXPLAINER · 01 NOV 2026</small>

<p class="psv-article-breadcrumb"><a href="../">← Threat Analysis</a><span> / </span><a href="../../">Cyber Journal</a></p>

A Windows administrator may use PowerShell, WMI, Remote Desktop, or system utilities every day. Attackers can use many of the same tools. This behaviour is often called **living off the land**: using software and capabilities already present in an environment instead of relying only on newly installed malware.

The challenge for a defender is clear: the executable may be legitimate, while the way it is used is not.

## Why attackers use built-in tools

Using trusted utilities can reduce the need to introduce custom binaries. It can also blend into normal administrative activity, especially where logging is weak or the organisation has no clear baseline for remote administration.

Examples of dual-use capabilities include:

- PowerShell and Windows scripting hosts.
- WMI and Windows Management Instrumentation consumers.
- Remote administration protocols and services.
- System utilities used to query users, services, processes, or network state.
- Signed tools that can access or package files.

These tools are not inherently malicious. Their presence is expected on many systems.

## The executable name is not the investigation

A rule that alerts every time PowerShell runs will usually create noise. A better investigation considers:

1. **Parent process:** what launched the tool?
2. **User and privilege:** which identity ran it, and was that expected?
3. **Command line:** what operation was requested?
4. **Host role:** is this an admin workstation, server, kiosk, or user endpoint?
5. **Time and frequency:** does the activity match a known maintenance window?
6. **Network context:** did the process communicate with unusual destinations?
7. **Follow-on actions:** were files created, services changed, scheduled tasks added, or credentials accessed?

A suspicious chain is more meaningful than an isolated process event.

## Example investigation

**Illustrative scenario:** a user workstation launches a scripting process from an unexpected parent process. The command retrieves remote content, writes a file to a temporary directory, and then initiates outbound network traffic.

The analyst should preserve the full process tree, command line, hashes, script content where available, DNS and network events, file metadata, and relevant user logon records. The analyst should also check whether the activity was part of approved software deployment or support work.

Do not label the activity malicious solely because a script interpreter was used.

## Useful Windows telemetry

| Source | What it can show | Caveat |
|---|---|---|
| Security Event 4688 | Process creation when auditing is configured | Command-line inclusion requires policy configuration |
| PowerShell 4104 | Script block content when Script Block Logging is enabled | Can contain sensitive data; protect access and retention |
| Sysmon Event 1 | Process creation with parent and command-line context | Requires Sysmon deployment and suitable configuration |
| Sysmon Event 3 | Network connections initiated by processes | Network connection logging is disabled by default |
| Sysmon Events 12–14 | Registry object/value changes | Volume and filtering need consideration |

Sysmon is a telemetry source, not an automated verdict engine. Microsoft explicitly describes its events as observations that need context and correlation.

## Detection engineering: think in behaviour

Prefer detections that combine several conditions rather than relying on a single process name. For example, a detection may look for an unusual parent-child relationship plus a rare command-line pattern and unexpected outbound communication.

Tune against real administrative workflows. Maintain an allowlist only where it is justified, scoped, owned, and reviewed. Broad exclusions can hide the exact behaviour a detection was meant to catch.

## Defensive measures

- Enable and centrally collect appropriate process and script logging.
- Protect logs against unauthorised modification and excessive access.
- Use application control and least privilege where practical.
- Restrict administrative tools to managed workstations and approved identities.
- Monitor unusual remote execution and privileged account use.
- Build host-specific baselines rather than one universal definition of normal.
- Test detections with safe simulations in an isolated lab.

## Key takeaways

- Legitimate tools can be abused; tool presence alone is weak evidence.
- Parent process, identity, command line, host role, and follow-on activity provide context.
- Telemetry must be enabled, collected, protected, and retained to be useful.
- Detection logic should describe suspicious behaviour, not simply blacklist utilities.

## References

- [MITRE ATT&CK — System Binary Proxy Execution (T1218)](https://attack.mitre.org/techniques/T1218/)
- [Microsoft Sysmon documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Microsoft PowerShell logging](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging)
- [Windows Event 4688 — Process Creation](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)

*This is defensive analysis. Run any simulations only in systems you own or are authorised to test.*