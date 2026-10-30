# Detection 001 — PowerShell encoded-command execution

<badge color="warning">Triage signal, not malware verdict</badge>

## Analytic intent

Identify PowerShell process-creation events whose command line includes the commonly used \`-EncodedCommand\` / \`-enc\` parameter. Encoded commands can be used by administrators and software deployment tools as well as adversaries. This analytic flags the execution pattern for review; it does not decode the payload, establish malicious intent, or prove compromise.

- **Rule ID:** PSV-WIN-001
- **Sigma ID:** \`2b3e1e76-7e3b-4a9d-9d81-001000000001\`
- **Data source:** Sysmon Operational, Event ID 1
- **Sigma logsource:** Windows / process_creation
- **ATT&CK mapping:** T1059.001 — PowerShell (behavioural mapping, not attribution)
- **Initial Sigma level:** medium
- **Owner:** Detection Engineering
- **Status:** test

## Required telemetry

| Field | Purpose | Expected source |
|---|---|---|
| Event ID | Process creation event | Sysmon Event ID 1 |
| Image | Executable path | Sysmon \`Image\` |
| CommandLine | Process command line | Sysmon \`CommandLine\` |
| ParentImage | Parent executable context | Sysmon \`ParentImage\` |
| ProcessGuid / ParentProcessGuid | Stronger process correlation than PID alone | Sysmon GUID fields |
| User | Execution identity | Sysmon user field, where populated |

Do not silently substitute Windows Security Event ID 4688 for Sysmon Event ID 1. Windows process-creation auditing can be used as a separate source, but command-line collection requires the relevant policy and has different field semantics.

## Sigma rule

Source file: [windows-powershell-encoded-command.yml](rules/windows-powershell-encoded-command.yml)

\`\`\`yaml
title: PowerShell Encoded Command Execution
id: 2b3e1e76-7e3b-4a9d-9d81-001000000001
status: test
description: Detects PowerShell process creation with an encoded-command argument. Review context; this is not a malware verdict.
author: Privacy Skill Vault
date: 2026/10/31
logsource:
    product: windows
    category: process_creation
detection:
    selection_image:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_encoded:
        CommandLine|contains:
            - '-EncodedCommand '
            - '-encodedcommand '
            - '-enc '
            - '-ENC '
    condition: all of selection_image, selection_encoded
fields:
    - Image
    - CommandLine
    - ParentImage
    - User
    - ProcessGuid
    - ParentProcessGuid
falsepositives:
    - Approved software deployment or endpoint management scripts
    - Administrative automation using encoded PowerShell
    - Security products or installers that launch encoded PowerShell
level: medium
tags:
    - attack.execution
    - attack.t1059.001
\`\`\`

The Sigma file is provided as source. CI validates it against the Sigma 2.1.0 JSON schema. Before operational use, also run the current Sigma CLI, convert it for the intended backend and pipeline, and test the converted query against raw events from the target SIEM. Schema validation does not prove detection semantics, backend compatibility, or production effectiveness.

The explicit command-line patterns are intentionally conservative and may miss unusual quoting, parameter abbreviations, or obfuscation. Expand only after testing the resulting noise and coverage.

## Elastic Security — KQL starting query

Assumptions: the Windows/Sysmon integration maps process creation into ECS fields and the selected data view contains the events.

\`\`\`kql
event.code : "1"
and process.name : ("powershell.exe" or "pwsh.exe")
and process.command_line : (*-EncodedCommand* or *-encodedcommand* or *-enc*)
\`\`\`

If the actual integration maps the executable or command line differently, inspect the raw document and correct the mapping. Do not assume every deployment populates \`process.name\` from Sysmon \`Image\`.

## Splunk — raw Sysmon SPL starting query

Replace \`YOUR_INDEX\` and the sourcetype with the actual values in your deployment. Confirm field extractions from a raw event first.

\`\`\`spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(Image, "(?i)\\\\\\\\(powershell|pwsh)\\\\.exe$")
    AND match(CommandLine, "(?i)(^|\\\\s)-(enc|encodedcommand)(\\\\s|$)")
| table _time host User Image CommandLine ParentImage ProcessGuid ParentProcessGuid
\`\`\`

This SPL uses raw Sysmon field names. If your collector uses a different sourcetype or normalises to CIM, adapt the query to the observed schema. Do not copy an index or sourcetype name from this example into production.

## Test matrix

| Test | Input | Expected |
|---|---|---|
| Positive | PowerShell image and \`-EncodedCommand\` argument | Match |
| Positive | PowerShell image and \`-enc\` argument | Match |
| Negative | PowerShell with \`-File\` only | No match |
| Negative | \`cmd.exe\` with text containing \`-EncodedCommand\` | No match |
| Benign positive | Approved management script using encoded PowerShell | Match, then close as expected activity with owner/change evidence |
| Telemetry gap | Sysmon Event ID 1 not collected | No detection; record as coverage gap, not a true negative |

## Analyst triage

1. Retrieve the full event and adjacent process events for the host and time window.
2. Correlate by Sysmon Process GUID and Parent Process GUID where available; use PID only with host and time because PIDs are reused.
3. Identify the parent process, user, integrity context, executable path, signer, hash and command-line context.
4. Decode the command only in an approved, isolated analysis workflow. Treat decoded content as untrusted.
5. Correlate file creation, DNS, network, PowerShell Operational logs, EDR telemetry and change-management records.
6. Check whether the script, parent process, account and execution time match an approved administrative task.
7. Record evidence, alternative explanations, confidence and data gaps. Escalate using the organisation's incident process.

## Tuning and release

- Do not suppress all encoded PowerShell or all activity from a management agent.
- Build narrow exceptions from verified signer, path, parent, host role, account and approved change context; set an owner and expiry.
- Review positive and negative tests after every exception change.
- Measure event delay, alert volume, benign-positive rate, investigation context and missed-test cases.
- Obtain peer review and change approval before enabling.

## References

- [Microsoft Sysmon Event ID 1](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Sigma Specification 2.1.0](https://github.com/SigmaHQ/sigma-specification/releases/tag/v2.1.0)
- [Elastic ECS Process fields](https://www.elastic.co/docs/reference/ecs/ecs-process)
