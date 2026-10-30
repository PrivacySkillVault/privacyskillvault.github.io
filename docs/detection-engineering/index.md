# Detection Engineering — Operational Pack

<badge color="warning">Reference pack — validate against your own telemetry before enabling</badge>

This pack contains two Windows detections with Sigma source, Elastic KQL and Splunk SPL equivalents, synthetic test cases, and a repeatable release procedure. It is designed to be adapted—not imported blindly—into a real SIEM.

## Scope and source assumptions

| Component | Assumption used in this pack | Must be confirmed in the target environment |
|---|---|---|
| Endpoint telemetry | Windows Security log and Sysmon Operational log | Windows build, audit policy, Sysmon version/configuration, event forwarding |
| Sigma | Sigma Rules Specification 2.1.0 | Installed Sigma CLI and backend/pipeline versions |
| Elastic | ECS-compatible fields; Elastic Security | Elastic Stack, integration version, data stream, mappings, rule type |
| Splunk | Raw Sysmon XML/event fields | Splunk version, index, sourcetype, field extractions, CIM mapping |
| ATT&CK | Technique IDs listed on each analytic | ATT&CK release used by your organisation |

**Important:** the Elastic and Splunk queries below are authored equivalents for the stated field assumptions. They are not generated output from a verified converter run and are not asserted to work unchanged against every deployment. The Sigma YAML files are authored against the published Sigma structure; they still require parsing, backend conversion, and data-level testing in the target stack.

## Included detections

1. [PowerShell encoded-command execution](windows-powershell-encoded-command.md) — Sysmon Event ID 1 / process creation.
2. [Addition to the local Administrators group](windows-local-admin-membership.md) — Windows Security Event ID 4732.

## Data collection prerequisites

### Sysmon process creation

Microsoft documents Sysmon Event ID 1 as Process Create, with process image, command line, parent process, hashes and Process GUID available according to configuration and event version. Process creation logging is a prerequisite for the PowerShell analytic. Sysmon Event ID 3 network connections are disabled by default; do not assume they are collected.

### Windows Security group management

Windows Security Event ID 4732 records a member added to a security-enabled local group. The event is generated on domain controllers, member servers and workstations. Configure and verify the applicable Advanced Audit Policy and event forwarding; absence of an event is not proof that no group change occurred.

## Validation lifecycle

For each rule, use the following release gates:

1. Confirm the source event is generated locally on a controlled test endpoint.
2. Confirm the same event arrives in the SIEM and inspect its raw payload.
3. Confirm each required field is populated and mapped as expected.
4. Parse the Sigma file with the current Sigma toolchain and convert it with the intended backend and processing pipeline.
5. Compare converted output with the native query; review any semantic differences.
6. Run positive, negative and benign-administration test cases.
7. Review duplicates, alert context, search latency, event volume and query cost.
8. Obtain peer review and change approval before enabling in production.
9. Monitor the analytic and document tuning, owner, rollback and next review date.

### Sigma CLI reference workflow

The Sigma project documents installation of `sigma-cli`, backend plugins, and conversion with a selected backend and processing pipeline. For a controlled workstation:

```bash
python -m pip install 'sigma-cli==3.1.0'
sigma plugin install splunk
sigma plugin install sysmon
sigma convert -t splunk -p sysmon docs/detection-engineering/rules/windows-powershell-encoded-command.yml
```

This repository's CI pins Sigma CLI 3.1.0 because the currently published Sysmon pipeline is not compatible with pySigma 2.x; do not force-install an incompatible plugin. Recheck the [Sigma CLI releases](https://github.com/SigmaHQ/sigma-cli/releases), [Sysmon pipeline releases](https://github.com/SigmaHQ/pySigma-pipeline-sysmon/releases), and plugin compatibility before upgrading. CI currently converts the Sysmon process-creation rule to Splunk SPL. The Windows Security Event 4732 rule is schema-validated and its SPL example is manually authored; verify the target source pipeline and run the conversion yourself before using it. A successful conversion proves that the selected toolchain accepted the rule for that backend; it does not prove that the query matches your telemetry or detects malicious activity.

## Synthetic test fixture

The examples below are intentionally synthetic. They are test inputs, not live indicators or evidence of a real incident.

```json
{
  "case": "DET-PSV-001-positive",
  "source": "Sysmon/Operational",
  "EventID": 1,
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -NoProfile -EncodedCommand QQ==",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "expected": "match"
}
```

```json
{
  "case": "DET-PSV-001-negative",
  "source": "Sysmon/Operational",
  "EventID": 1,
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -NoProfile -File C:\\Admin\\Inventory.ps1",
  "ParentImage": "C:\\Windows\\System32\\services.exe",
  "expected": "no-match"
}
```

```json
{
  "case": "DET-PSV-002-positive",
  "source": "Security",
  "EventID": 4732,
  "TargetSid": "S-1-5-32-544",
  "TargetUserName": "Administrators",
  "MemberName": "CONTOSO\\svc-maint",
  "SubjectUserName": "ops-admin",
  "expected": "match"
}
```

```json
{
  "case": "DET-PSV-002-negative",
  "source": "Security",
  "EventID": 4732,
  "TargetSid": "S-1-5-32-545",
  "TargetUserName": "Users",
  "MemberName": "CONTOSO\\new-user",
  "SubjectUserName": "helpdesk",
  "expected": "no-match"
}
```

These fixtures document expected analytic behaviour. They are not automatically replayed against a live SIEM by this website build.

## Local synthetic fixtures

The [synthetic fixture set](fixtures/synthetic-events.jsonl) contains two positive and two negative examples. These are simplified constructed inputs, not genuine exported event XML and not automatically replayed by the CI workflow. Use them to record intended logic, then validate against actual source events in an isolated lab.

## Operational ownership

Every production rule should have:
- A named service and technical owner.
- A documented data-source owner and telemetry-health check.
- A severity/priority mapping approved by the organisation.
- An analyst runbook and escalation route.
- A versioned query, test set and change history.
- A suppression/exception owner and expiry/review date.
- A rollback procedure and disablement authority.

Do not use Sigma `level` as a substitute for your incident severity matrix. Sigma metadata and organisational incident priority are different concepts.

## Authoritative references

- [Sigma Rules Specification 2.1.0](https://github.com/SigmaHQ/sigma-specification/releases/tag/v2.1.0)
- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)
- [Microsoft Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft Event 4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732)
- [Elastic detection rule concepts](https://www.elastic.co/docs/solutions/security/detect-and-alert/detection-rule-concepts)
- [Elastic ECS reference](https://www.elastic.co/docs/reference/ecs)
- [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1098.007 — Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/)
