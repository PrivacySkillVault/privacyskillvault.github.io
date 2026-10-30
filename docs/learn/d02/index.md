# D02 — Security Monitoring & Detection

Learn how security telemetry is collected, normalised, searched, correlated, and converted into detections that can be tested and maintained.

## Hands-on SIEM labs

Build and validate [Elastic](../../labs/elastic-siem.md), [Splunk](../../labs/splunk-siem.md) or [Wazuh](../../labs/wazuh-soc.md) one at a time. Add [Zeek/Suricata](../../labs/network-monitoring.md) or [Security Onion](../../labs/security-onion.md) only after packet visibility and resource requirements are confirmed.

## Authoritative foundations

- [NIST CSF 2.0](../../standards/index.md#nist-cybersecurity-framework-csf-20) — use the Detect Function outcomes to structure monitoring and adverse-event analysis.
- [MITRE ATT&CK](../../standards/index.md#mitre-attck) — describe adversary behaviour using supported tactic and technique references; do not infer attribution from a technique match.
- [Sigma Specification 2.1.0](../../standards/index.md#sigma-detection-format) — author portable detection logic using the published rule structure and condition semantics.
- [CIS Controls v8.1](../../standards/index.md#cis-critical-security-controls-v81) — use applicable safeguards to inform monitoring and operational priorities.

## 1. Telemetry engineering

A detection is only as reliable as its data source and field semantics. For each source, document:

- System, product, version, host role, and collection method
- Event channel, event ID or dataset, and audit policy/configuration
- Required fields and their source-native meaning
- Timestamp source, time zone, clock synchronisation, and ingestion delay
- Parsing, normalisation, enrichment, and field-mapping stages
- Retention, access control, integrity protection, and data owner
- Known blind spots and conditions that stop events being generated

Do not assume that identically named fields mean the same thing across Windows Event Log, Sysmon, Elastic ECS, Splunk CIM, or a vendor-specific schema. Validate field mappings against raw records from the deployed version.

## 2. Detection engineering lifecycle

Use the following lifecycle for every detection change. This is an operational workflow informed by NIST CSF and Sigma; it is not a verbatim sequence mandated by either source.

1. **Define the analytic question.** State the behaviour or security outcome being monitored.
2. **Identify required telemetry.** Record source, event types, audit settings, fields, and collection dependencies.
3. **Describe the behaviour.** Map to MITRE ATT&CK only where the behaviour and evidence support the technique.
4. **Author the analytic.** Use the target SIEM's native language or a Sigma rule with a defined logsource and condition.
5. **Validate syntax and semantics.** Parse against the relevant schema; for Sigma, use a maintained Sigma toolchain and confirm backend support.
6. **Test against evidence.** Use known-positive, known-negative, and benign administrative samples. Record the test dataset and expected result.
7. **Measure operational impact.** Review event volume, false positives, duplicates, latency, query cost, and analyst context.
8. **Approve and deploy.** Use the organisation's change process, version control, peer review, and rollback plan.
9. **Monitor and maintain.** Review performance, data-source health, rule status, environment changes, and threat changes.

A rule that parses is not necessarily correct. A query that returns events is not necessarily a useful detection. A clean test set does not establish production effectiveness.

## 3. Sigma rule structure

The Sigma Rules Specification 2.1.0 defines required and optional fields including `title`, `logsource`, `detection`, and `condition`. It also defines search identifiers, logical conditions, value modifiers, status, tags, and schema.

A minimal illustrative rule structure is shown below. This is a syntax example, not a validated production detection:

```yaml
title: Example Process Creation Analytic
status: test
description: Illustrates the structure of a process-creation rule.
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\example.exe'
    condition: selection
level: low
```

The sample uses an intentionally generic executable name and is not intended to detect malicious activity. The `level` value is Sigma metadata, not a universal incident priority or response SLA.

Official references:
- [Sigma Rules Specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma specification repository and JSON schemas](https://github.com/SigmaHQ/sigma-specification)
- [Sigma rule-writing guide](https://sigmahq.io/docs/basics/rules.html)

## 4. ATT&CK mapping discipline

For each mapped detection, record:

- ATT&CK domain and release/data version used
- Technique or sub-technique ID and name
- The exact event behaviour that supports the mapping
- Whether the analytic detects the technique directly, a related observable, or only a prerequisite
- Data-source requirements and known coverage gaps
- Test evidence and confidence

Do not claim full technique coverage because one analytic has an ATT&CK tag. ATT&CK is a knowledge base for describing behaviour; the quality of a detection depends on telemetry, logic, testing, and operational context.

## 5. Alert quality and operational acceptance

Before production use, define and measure the criteria approved by the organisation. Useful measures include:

- Detection test pass/fail against a versioned test set
- Alert volume by source and rule
- Confirmed true-positive, benign-positive, and false-positive outcomes using the organisation's definitions
- Time from event occurrence to searchable telemetry
- Time from alert creation to analyst acknowledgement and disposition
- Percentage of alerts with required investigation context
- Data-source health and missing-event rates

Do not invent universal thresholds for these measures. Set targets from the service's risk, baseline, coverage, staffing, and approved service-level objectives.

## 6. Applied lab

Continue with the [Windows Endpoint Telemetry: Sysmon to Elastic lab](../../labs/windows-endpoint-telemetry.md). It is explicitly a reference design until the actual Windows build, Sysmon configuration, Elastic integration version, event, and search result are recorded.

## 7. Operational detection pack

The [PSV Detection Engineering Pack](../../detection-engineering/index.md) contains two example detections with Sigma source, Elastic KQL and Splunk SPL starting queries, synthetic test cases, telemetry requirements, triage steps, and release gates:

- PowerShell encoded-command execution (Sysmon Event ID 1)
- Addition to the built-in local Administrators group (Windows Security Event ID 4732)

These are test-status examples. The backend queries are authored starting points based on stated field assumptions, not confirmed output from a specific live SIEM. CI validates both Sigma files against the Sigma 2.1.0 schema and converts them to Splunk SPL with the applicable Sysmon and Splunk Windows pipelines. This does not validate the queries against a live SIEM; test them against raw events from your own environment.

## Evidence record for a detection change

| Record | Required detail |
|---|---|
| Change identity | Rule ID, version, author, reviewer, date |
| Purpose | Behaviour and security question |
| Data dependency | Source, event IDs/dataset, audit configuration, fields |
| Logic | Sigma or native query and exact backend/version |
| Validation | Parser/schema result and test cases |
| Results | Positive/negative tests, observed output, false positives |
| Operations | Volume, latency, cost, owner, escalation path |
| Change control | Approval, deployment time, rollback |
| Maintenance | Review date, related threat/data changes |

**Operational note:** Detection examples are not production-ready until adapted to the actual event schema and tested in the target environment.
