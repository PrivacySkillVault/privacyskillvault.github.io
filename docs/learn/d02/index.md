# D02 — Security Monitoring & Detection

Learn how security telemetry is collected, normalised, searched, correlated, and converted into actionable detections.

## Learning areas

- Log sources: Windows Security, Sysmon, Linux audit logs, firewall, DNS, proxy, web, and identity events.
- SIEM foundations: ingestion, parsing, field mapping, timestamps, retention, searches, and dashboards.
- Alert triage: context gathering, severity, scope, false positives, escalation, and documentation.
- Detection engineering: Sigma concepts, rule logic, exclusions, testing, and change control.
- Threat hunting: hypotheses, data requirements, pivots, baselines, and recording findings.

## Practical exercise

Generate benign process and authentication activity in a controlled endpoint. Confirm that expected events are collected, identify the fields needed for a detection, test a query against available data, and document false-positive conditions.

A rule is not production-ready merely because it parses or returns results. Record the data source, tested event samples, expected matches, false positives, performance considerations, and review date.
