# Detection 002 — Addition to local Administrators group

<badge color="warning">Review privileged change; validate local group scope</badge>

## Analytic intent

Identify Windows Security Event ID 4732 where the target group SID is the built-in local Administrators group SID `S-1-5-32-544`. This indicates a membership addition to that security-enabled local group. It does not establish whether the change was authorised.

- **Rule ID:** PSV-WIN-002
- **Sigma ID:** `2b3e1e76-7e3b-4a9d-9d81-001000000002`
- **Data source:** Windows Security log, Event ID 4732
- **ATT&CK mapping:** T1098.007 — Additional Local or Domain Groups
- **Initial Sigma level:** high
- **Status:** test

## Required event fields

| Field | Meaning |
|---|---|
| EventID | 4732 — member added to a security-enabled local group |
| TargetSid | SID of the target group; expected built-in Administrators SID for this analytic |
| TargetUserName / TargetDomainName | Resolved target group name/domain, if available |
| MemberName / MemberSid | Account added to the group |
| SubjectUserName / SubjectDomainName | Actor recorded as performing the change |
| SubjectLogonId | Logon session identifier for correlation on the same host |

Group display names may be localised or renamed. The well-known SID is a more stable selector for the built-in local Administrators group, but confirm that the event field is correctly parsed and that your environment's group semantics match this analytic.

## Sigma rule

Source file: [windows-local-admin-membership.yml](rules/windows-local-admin-membership.yml)

```yaml
title: Member Added to Built-in Local Administrators Group
id: 2b3e1e76-7e3b-4a9d-9d81-001000000002
status: test
description: Detects a member added to the built-in local Administrators group using Windows Security Event 4732.
author: Privacy Skill Vault
date: 2026/10/31
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4732
        TargetSid: 'S-1-5-32-544'
    condition: selection
fields:
    - SubjectUserName
    - SubjectDomainName
    - SubjectLogonId
    - MemberName
    - MemberSid
    - TargetUserName
    - TargetSid
falsepositives:
    - Approved endpoint provisioning
    - Privileged access management workflows
    - Software deployment or support activity
level: high
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1098.007
```

## Elastic Security — KQL starting query

Assumptions: Windows Security events are ingested and the raw Windows event data is available in `winlog.event_data`.

```kql
event.code : "4732"
and winlog.event_data.TargetSid : "S-1-5-32-544"
```

Check the actual field mapping in Discover before deploying. Some integrations expose additional normalised fields; retain the original raw event fields for auditability.

## Splunk — raw Windows Security SPL starting query

Replace the index and source value with values verified from your deployment. The CI conversion using the Sigma Splunk Windows pipeline emits the source constraint shown here; your ingestion configuration may use a different source/sourcetype mapping.

```spl
index=YOUR_INDEX source="WinEventLog:Security" EventCode=4732 TargetSid="S-1-5-32-544"
| table _time host SubjectUserName SubjectDomainName SubjectLogonId MemberName MemberSid TargetUserName TargetSid
```

## Test matrix

| Test | Event | Expected |
|---|---|---|
| Positive | 4732, TargetSid S-1-5-32-544 | Match |
| Negative | 4732, TargetSid S-1-5-32-545 (Users) | No match |
| Negative | 4735 group changed, no 4732 member-add event | No match |
| Benign positive | Approved IT provisioning adds a technician | Match; verify ticket, requester, approver and device scope |
| Coverage gap | Security audit event not generated/forwarded | No detection; record telemetry gap |

## Analyst triage

1. Confirm the host and original event XML; verify `TargetSid`, `MemberSid`, actor, time and logon ID.
2. Identify the added principal by SID and directory source; determine whether it is a user, computer or service account.
3. Confirm whether the target is the local Administrators group on an endpoint or a different group with a similar name.
4. Correlate the actor's logon session, process creation, remote administration activity, change ticket and privileged access records.
5. Determine whether the member was newly created, recently enabled, or used for subsequent interactive/network logons.
6. Search for follow-on privileged activity and lateral movement from the affected host.
7. Record the authorisation decision and evidence. Containment or removal requires the organisation's approved authority and change process.

## Tuning

Do not blanket-exclude IT administrators or provisioning accounts. Tune by approved workflow identity, source host, target group, actor, ticket evidence and expected timing. Every exception needs an owner and periodic review.

## References

- [Microsoft Event 4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732)
- [MITRE ATT&CK T1098.007](https://attack.mitre.org/techniques/T1098/007)
- [MITRE ATT&CK Detection Strategy DET0310](https://attack.mitre.org/detectionstrategies/DET0310/)
