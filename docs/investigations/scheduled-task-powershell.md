# Investigation Walkthrough: Suspicious PowerShell from a Scheduled Task

<badge color="info">Simulated training scenario</badge>

This case is synthetic. Host names, timestamps, users, event records, and command lines are invented for training. It is not a description of a real customer, employer, bank, or production incident.

## Scenario

An endpoint alert reports PowerShell execution shortly after a scheduled task was created on a workstation. The command line contains encoded content. The analyst must determine whether this is expected administration, a policy violation, or evidence of compromise.

**Initial alert is not a verdict.** Encoded PowerShell, an unfamiliar task, or an unusual parent process can justify investigation, but none independently proves malicious activity.

## Investigation objectives

1. Establish what happened and when.
2. Identify the account, process, task definition, and affected host.
3. Correlate independent endpoint, identity, and network telemetry.
4. Test benign and malicious explanations.
5. State the conclusion, confidence, evidence gaps, and recommended next steps.

## Synthetic evidence set

| Time (UTC) | Source | Synthetic observation |
|---|---|---|
| 09:12:04 | Endpoint alert | Encoded PowerShell execution detected on `WS-TRAIN-07` |
| 09:11:58 | Process telemetry | `powershell.exe` started; parent process and full command line available |
| 09:10:31 | Task audit | A scheduled task registration was recorded; task XML and registering account require retrieval |
| 09:12:10 | DNS telemetry | A query was recorded shortly after process start; destination context is not yet established |
| 09:12:18 | Network telemetry | One outbound connection was observed; process attribution must be corroborated |

These rows are intentionally incomplete. They provide investigation leads, not proof that the task, DNS query, and connection belong to one causal chain.

## Step 1 — Preserve and scope

- Record the alert ID, host identifier, event source, original timestamps, collection time, and analyst actions.
- Preserve the original event records and task definition before making changes.
- Confirm the host owner, business function, maintenance window, and whether an approved change exists.
- Establish whether similar activity appears on other endpoints.
- Record which telemetry sources are available and their retention windows.

Do not modify or delete the task before preserving the relevant evidence unless an authorised containment decision requires immediate action.

## Step 2 — Reconstruct process execution

Review the process event and collect, where available:

- Image path, hash, signer, and file metadata
- Full command line and parent command line
- Parent and child process identifiers or process GUIDs
- User, logon session, integrity level, and host
- Process start and termination times

Validate the parent-child relationship using the raw event. Parent process names can vary by Windows version and execution path; do not assume one fixed Task Scheduler process chain.

For Sysmon, Event ID 1 is Process Create. Its presence depends on Sysmon installation and configuration. Correlate process identifiers and timestamps rather than relying only on process names.

## Step 3 — Inspect the scheduled task

Retrieve the task's:

- Full task path and name
- Registration and modification times
- Author and security principal
- Trigger and execution conditions
- Action, executable path, arguments, and working directory
- Run level and task history
- Creation or modification source, where available

Compare the task definition with the organisation's approved software deployment, administration scripts, and change records. A task can be legitimate, misconfigured, or unauthorised; classify it only after checking ownership and intent.

## Step 4 — Correlate independent telemetry

| Evidence source | Questions to answer | Important limitation |
|---|---|---|
| Windows process telemetry | Which process launched PowerShell? What command and account were used? | Collection and command-line visibility depend on configuration |
| Task Scheduler logs / audit | When was the task registered, changed, and executed? | Relevant logging may not have been enabled or retained |
| PowerShell operational logs | Is script-block or module content available? | Logging policy and version affect visibility |
| DNS | Which name was queried, by which host, and at what time? | A query alone does not prove a successful connection |
| Network / proxy / firewall | Was a connection established? What process or host initiated it? | Network records may not identify the originating process |
| Identity logs | Was the account's sign-in or privilege use expected? | Correlation requires correct time and identity context |
| File telemetry | Were scripts or payloads created, modified, or executed? | Absence of a file event is not proof that no file existed |

Build the timeline using UTC and preserve the original timestamps. Distinguish event time from collection or ingestion time.

## Step 5 — Test competing hypotheses

### H1: Approved administration

Supporting evidence could include a known task owner, approved change, expected script path and signature, documented execution window, and matching activity on similarly managed endpoints.

Evidence against it could include an unknown registering account, unapproved arguments, an unexpected script location, or activity outside the change window.

### H2: Unauthorised but non-malicious activity

A legitimate user may have created a task outside the change process. This can still be a policy or control issue even when there is no evidence of malware.

### H3: Malicious persistence or execution

Supporting evidence could include an unexplained task, concealed or user-writable execution path, obfuscated arguments, untrusted script content, suspicious account use, corroborated command-and-control activity, or related actions on other hosts.

No single indicator is sufficient. Corroborate the task, process, identity, and network evidence.

## Step 6 — Document the conclusion

Use a conclusion format that separates facts from interpretation:

- **Observed:** what the source records directly show.
- **Correlated:** which independent records align by host, identity, process identifier, and time.
- **Interpretation:** what the combined evidence suggests.
- **Alternative explanations:** plausible benign or non-malicious causes considered.
- **Confidence:** low, moderate, or high, with a reason.
- **Gaps:** missing logs, incomplete retention, uncertain attribution, or unverified ownership.
- **Next steps:** further collection, owner confirmation, remediation, or escalation under approved procedures.

Example conclusion for this training case:

> The available records establish that PowerShell executed shortly after a scheduled task was registered. They do not yet establish who authorised the task or whether the outbound connection was caused by that process. The case remains unresolved pending task-definition review, account validation, and process-to-network correlation.

## Step 7 — Response considerations

If evidence supports compromise, follow the organisation's incident-response process. Preserve volatile and relevant endpoint evidence, identify scope, and obtain the required approval for containment actions. Do not isolate a host, disable an account, or remove a task solely because an encoded command or one suspicious event was observed.

If the activity is approved, document the owner and change reference. If it is unauthorised but not malicious, route it through the appropriate control-remediation process.

## Analyst checklist

- [ ] Original alert and raw records preserved
- [ ] Host, user, and time zone confirmed
- [ ] Process and parent process reviewed
- [ ] Scheduled task definition and owner verified
- [ ] PowerShell logging availability checked
- [ ] DNS and network records correlated
- [ ] Alternative explanations considered
- [ ] Scope and affected assets assessed
- [ ] Confidence and evidence gaps documented
- [ ] Response actions aligned with approved procedure

## Learning references

- [Microsoft: Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft: Read and tune Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/read-tune-sysmon-events)

**Evidence status:** Simulated scenario. No real incident or production investigation is claimed.
