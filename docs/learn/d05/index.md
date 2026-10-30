# D05 — Operations, Maintenance & Capstone

Connect security controls and detection content to stable, supportable operations. The objective is to demonstrate that a system or control can be operated, monitored, changed, recovered, and improved—not merely installed.

## Authoritative foundations

- [NIST CSF 2.0](../../standards/index.md#nist-cybersecurity-framework-csf-20) — use the Govern and Identify outcomes to establish ownership and context, and the Protect, Detect, Respond, and Recover outcomes to organise operational work.
- [NIST SP 800-61 Rev. 3](../../standards/index.md#nist-sp-800-61-revision-3-incident-response) — integrate response preparation, detection, response, recovery, and improvement into risk management.
- [CIS Controls v8.1](../../standards/index.md#cis-critical-security-controls-v81) — select applicable safeguards and validate implementation.
- [SAMA Counter-Fraud Framework](../../standards/index.md#sama-counter-fraud-framework-banking-sector-2022) — where the banking-sector framework applies, retain evidence of control operation, monitoring, measurement, and periodic evaluation.

## Operational disciplines

### Service health and capacity

Record service objectives, dependencies, resource baselines, alert thresholds approved by the service owner, and the evidence used to identify degradation. For distributed platforms, correlate application, operating-system, database, container, network, and hypervisor telemetry before attributing a fault to one layer.

### Change and release management

For each material change, retain:
- Change reference, business reason, scope, owner, and approver
- Affected components, dependencies, and risk assessment
- Pre-change health and baseline evidence
- Test plan, acceptance criteria, and test results
- Deployment window and communication
- Rollback criteria, procedure, and decision owner
- Post-change validation and closure evidence

Do not describe a change as successful solely because deployment completed. Verify service health, functional behaviour, security controls, monitoring, and rollback readiness.

### Vulnerability management

Keep the scanner finding, technical validation, affected asset, version, exposure, exploit intelligence, business criticality, compensating controls, remediation owner, target date, exception approval, and retest evidence together.

CVSS communicates vulnerability severity using a defined version and vector. It is one input to prioritisation, not the complete organisational risk decision. Follow applicable regulatory and contractual deadlines and the organisation's approved risk policy.

### Backup, recovery, and disaster recovery

A backup job reporting success is not proof that recovery will work. Record the recovery objective approved by the service owner, backup scope, protection and access controls, retention, restore test, integrity verification, dependency order, measured recovery result, and unresolved gaps.

Do not invent universal RTO or RPO targets. They must come from business impact analysis, service requirements, and approved continuity plans.

### Automation

Automation should be version-controlled, reviewed, least-privileged, observable, idempotent where practical, and safe under partial failure. Document inputs, outputs, secrets handling, error handling, retries, rate limits, audit trail, and rollback.

## Operational measures

Use measures with clear definitions and owners. Examples include:

- Service availability and error rate, with the measurement window and exclusions defined
- Event collection coverage and telemetry delay
- Detection test pass rate against a versioned test set
- Alert acknowledgement and investigation time, defined by the organisation
- Change failure and rollback rate
- Backup restore-test success and measured recovery time
- Vulnerability remediation status against approved due dates
- Fraud detection rule effectiveness and false-positive trends, using documented outcome labels

These are example measures, not universal mandatory KPIs or regulatory thresholds. Define targets using business impact, risk appetite, service design, staffing, and approved obligations.

## Operational deliverables

Use the [Detection Engineering Pack](../../detection-engineering/index.md) for test-status Sigma rules, SIEM query starting points, and detection release gates.

Use the [Operational Templates](../../operational-templates/index.md) for detection change records, fraud case records, and incident reports. Complete these in approved internal systems; do not publish customer or production evidence.

## Capstone approach

Choose a small, authorised lab environment and define a measurable security objective. Build the environment, generate benign test activity, collect telemetry, implement a detection, validate the detection, investigate the result, tune false positives, document operational requirements, and demonstrate recovery or rollback.

## Completion evidence

- Scope, architecture, dependencies, assumptions, and authorisation
- Exact versions and configuration references
- Test cases, expected results, observed results, and raw evidence
- Security and operational risks
- Monitoring, ownership, and escalation arrangements
- Change and rollback record
- Recovery or restore-test evidence
- Known limitations and improvement actions

**Completion status:** A capstone is complete only when the evidence exists and the result has been reviewed. A proposed architecture or unexecuted procedure is not a completed lab.
