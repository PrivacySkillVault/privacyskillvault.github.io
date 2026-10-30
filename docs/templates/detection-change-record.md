# Detection Change & Validation Record

> Copy this template into the organisation's approved change-management or detection repository. Do not complete it with production secrets in a public repository.

## 1. Identification

- Rule name:
- Rule ID / stable identifier:
- Version / commit:
- Author:
- Technical owner:
- Peer reviewer:
- Request / change ticket:
- Created / modified date:
- Target SIEM and version:
- Status: draft / test / approved / enabled / disabled / retired

## 2. Analytic definition

- Behaviour to detect:
- Threat / fraud scenario:
- ATT&CK technique and version (if supported):
- Business/service scope:
- Severity mapping and approved rationale:
- Expected analyst action:
- Explicit non-goals (what this rule does not prove):

## 3. Telemetry dependencies

| Source | Product/version | Event/dataset | Audit/collection setting | Required fields | Health owner |
|---|---|---|---|---|---|
| | | | | | |

- Raw sample event reference:
- Parser/normalisation version:
- Field mapping reviewed:
- Timestamp/time-zone handling:
- Retention and access controls:
- Known blind spots:

## 4. Logic and implementation

- Sigma source path/hash (if used):
- Native SIEM query:
- Rule type:
- Schedule/lookback:
- Suppression/grouping:
- Exceptions and expiry:
- Actions/connectors:
- Required permissions:

## 5. Validation evidence

| Test ID | Scenario | Input source / fixture | Expected | Actual | Pass/fail | Evidence reference |
|---|---|---|---|---|---|---|
| | Positive | | Match | | | |
| | Negative | | No match | | | |
| | Benign-positive | | Match and explain | | | |
| | Boundary / missing field | | Documented behaviour | | | |

- Sigma parser/schema validation and tool version:
- Backend conversion and plugin/pipeline version:
- Query preview result:
- Event schema/raw record reviewed:
- Duplicate and late-arriving event checks:
- Performance/search-cost review:
- False-positive review and tuning:
- Test dataset hash/version:

## 6. Operational readiness

- Runbook:
- Queue/case destination:
- Analyst owner and escalation:
- Data-source health alert:
- Monitoring/metrics:
- Change approval:
- Deployment window:
- Rollback/disable procedure:
- Customer/business impact considered:
- Exception owner and review date:

## 7. Approval and post-deployment review

| Role | Name/ID in approved system | Decision | Date/time | Reference |
|---|---|---|---|---|
| Detection owner | | | | |
| Peer reviewer | | | | |
| Service/change approver | | | | |

- Deployment result:
- First review date:
- Observed volume and latency:
- Confirmed useful detections:
- False-positive/benign-positive findings:
- Required changes:
- Closure decision:
