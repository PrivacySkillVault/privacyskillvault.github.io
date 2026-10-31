# How to Investigate Suspicious PowerShell Activity

<small>SOC INVESTIGATIONS · ANALYST WORKFLOW · 01 NOV 2026</small>

<p class="psv-article-breadcrumb"><a href="../">← SOC Investigations</a><span> / </span><a href="../../">Cyber Journal</a></p>

PowerShell is a legitimate administration and automation platform. It is also frequently relevant in investigations because it can execute commands, interact with Windows components, and automate system tasks. A PowerShell alert is a starting point—not a conclusion.

This guide provides a repeatable triage workflow for an authorised SOC investigation.

## 1. Validate the alert

Record the alert identifier, detection name, host, user, timestamp, data source, and rule version. Confirm whether the alert is based on a command-line pattern, script content, parent process, reputation, or a behavioural sequence.

Check whether the event is duplicated, delayed, or missing surrounding context.

## 2. Reconstruct process lineage

Start with the process that launched PowerShell and work both backwards and forwards.

Questions to answer:

- Was PowerShell launched by an interactive shell, management agent, Office application, browser, service, or scheduled task?
- Which account and logon session were involved?
- Was the process elevated?
- What was the complete command line?
- Did it spawn child processes?
- Were files created, modified, or downloaded?
- Did the process initiate network connections?

Preserve process IDs and process GUIDs where available. Process IDs can be reused; a stable process GUID is preferable for correlation when the telemetry provides one.

## 3. Review the relevant Windows logs

| Telemetry | Useful information | Important limitation |
|---|---|---|
| Security 4688 | Process creation | Requires process-creation auditing; command-line capture must be configured |
| PowerShell 4104 | Script block content | Only available when Script Block Logging is enabled |
| Sysmon Event 1 | Process, parent, command line, hashes, Process GUID | Depends on installation and configuration |
| Sysmon Event 3 | Process-associated network connection | Disabled by default; enable selectively |
| Sysmon Event 11 | File creation | Does not establish that a file is malicious |

Microsoft documents Event 4104 under Microsoft-Windows-PowerShell/Operational when Script Block Logging is enabled. Protect this log carefully: script content can include secrets or other sensitive information.

## 4. Inspect command and script context

Look for encoded content, unusual download or execution patterns, suspicious file paths, unexpected use of reflection, and commands that alter security settings or establish persistence. These are investigative leads, not automatic proof of maliciousness.

If content is encoded, decode it only in a safe analysis environment. Do not execute an unknown script on an analyst workstation. Preserve the original command line and record the exact transformation used during analysis.

## 5. Correlate network and file activity

Use endpoint and network telemetry to identify DNS queries, outbound connections, downloaded files, and subsequent execution. Compare timestamps and process identifiers where possible.

A network connection alone does not prove data exfiltration. Determine the destination, protocol, volume, timing, process association, and whether the traffic is expected for the host.

## 6. Check business context

Ask the system owner or service team whether the activity corresponds to an approved script, deployment, maintenance task, or support operation. Validate the script path, signer, hash, deployment record, and execution schedule.

Do not rely only on a process name or a familiar administrator account. Legitimate accounts can be compromised, and approved tooling can be misused.

## 7. Decide and document

A useful outcome classification might be:

- **Expected activity:** supported by a matching approved task and consistent telemetry.
- **Suspicious, unresolved:** enough anomaly to continue investigation, but evidence is incomplete.
- **Malicious activity:** corroborated evidence of unauthorised behaviour.
- **Telemetry insufficient:** the necessary records were not enabled or retained.

Document evidence, counter-evidence, confidence, containment actions, and the reason for the conclusion.

## Analyst checklist

- [ ] Alert and source event preserved.
- [ ] Host, user, process lineage and logon context identified.
- [ ] Full command line and script content reviewed safely.
- [ ] File, DNS and network activity correlated.
- [ ] Approved administrative activity checked.
- [ ] Evidence gaps and time offsets documented.
- [ ] Escalation and containment follow the organisation's playbook.

## References

- [Microsoft PowerShell logging](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging)
- [Microsoft Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Windows Security Event 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

*This workflow is for authorised defensive investigations. Do not execute untrusted scripts outside an isolated, approved analysis environment.*