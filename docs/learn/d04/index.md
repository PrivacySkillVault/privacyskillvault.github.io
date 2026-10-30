# D04 — Security Operations & Investigations

Develop an evidence-led approach to suspicious activity across endpoint, network, identity, application, transaction, and fraud-monitoring systems.

## Authoritative foundations

- [NIST SP 800-61 Rev. 3](../../standards/index.md#nist-sp-800-61-revision-3--incident-response) — current NIST incident-response guidance, finalised April 2025; it supersedes Rev. 2.
- [NIST CSF 2.0](../../standards/index.md#nist-cybersecurity-framework-csf-20) — relevant outcomes include Detect, Respond, and Recover.
- [SAMA 2022 Counter-Fraud Framework](../../standards/index.md#sama-counter-fraud-framework--banking-sector-2022) — Banking Sector framework, subject to SAMA applicability.
- [SAMA 2025 Counter-Fraud Fundamental Requirements](../../standards/index.md#sama-counter-fraud-fundamental-requirements--payment-systems-and-payment-services-providers-effective-13-april-2026) — separate requirements for payment systems and payment services providers; verify entity scope.
- [EMVCo 3-D Secure](../../standards/index.md#emv-3-d-secure-3ds) — authoritative 3DS protocol specifications and version bulletins.
- [MITRE ATT&CK](../../standards/index.md#mitre-attck) — a knowledge base for describing observed adversary behaviour, not a verdict or attribution engine.

## 1. Separate security incidents from fraud cases

Security incident response and counter-fraud investigation can overlap, but they are not interchangeable.

A single event may require parallel workstreams:
- Cybersecurity incident handling for compromised endpoints, accounts, infrastructure, malware, or unauthorised access.
- Counter-fraud case handling for suspicious customer or employee activity, unauthorised transactions, social engineering, account takeover, or attempted loss.
- Payment operations, customer support, legal, compliance, and other stakeholder involvement according to the organisation's approved process.

Record the case owner, incident owner, hand-offs, and decision authority. Do not assume that one team can perform every containment, payment, customer-contact, or regulatory action.

## 2. Triage and prioritisation

NIST CSF 2.0 identifies incident triage and validation, categorisation and prioritisation, escalation, and recovery initiation as incident-management outcomes. Apply the organisation's approved severity and escalation model.

At minimum, capture:

- What was observed, by which system, and at what time
- Affected customer, account, device, application, service, or asset identifiers in the authorised case system
- Potential ongoing loss, service impact, customer impact, and scope
- Whether the activity is ongoing, stopped, or not yet established
- Available evidence and telemetry gaps
- Immediate actions already taken and by whom
- Required escalation, decision owner, and next review time

Do not infer severity solely from a keyword, transaction value, CVSS score, ATT&CK technique, or a single fraud signal. Use the approved organisational model and documented impact assessment.

## 3. Investigation evidence and provenance

Preserve original records and record how evidence was obtained. For every important artefact, capture:

- Source system, source record identifier, and collection method
- Original timestamp, time zone, and normalised UTC timestamp
- Collection timestamp and any ingestion delay
- Collector or analyst identity and access context
- Original value and any transformation or enrichment
- Hash or integrity mechanism where appropriate and supported
- Retention, access restrictions, and chain-of-custody requirements
- Known gaps, clock skew, parsing errors, and source limitations

Do not overwrite original evidence with enriched values. Keep enrichment and analyst interpretation as separate fields or records.

## 4. Account takeover and transaction investigation

The following is a collection and correlation checklist, not a claim that any single signal proves account takeover.

| Evidence domain | Investigative questions |
|---|---|
| Identity and authentication | Was there a password reset, MFA change, new authenticator, failed-login sequence, unusual authentication method, or recovery-channel change? |
| Device and session | Is the device identifier stable and trustworthy? Are device fingerprint, app version, session ID, IP, ASN, and user-agent consistent across the available records? |
| Customer profile | Were phone, email, address, beneficiary, limit, or profile details changed before the disputed activity? |
| Transaction | What were amount, currency, channel, beneficiary, payment rail, timestamp, status, and authorisation outcome? |
| Step-up and 3-D Secure | What authentication flow was used? Capture the available 3DS version, transaction identifiers, ECI, result/status, challenge outcome, and liability-shift indicators where applicable and available. Do not treat a 3DS result as proof that the legitimate customer initiated the transaction. |
| Application/API | Are request IDs, trace IDs, gateway logs, application logs, and backend outcomes available? Did the transaction pass through expected services? |
| Network and endpoint | Are source IP, DNS, TLS, endpoint, proxy, and EDR records available to corroborate the session? |
| Fraud controls | Which rules/models fired, what data was evaluated, what decision was returned, and were any controls bypassed, disabled, or overridden? |
| Customer contact | Was the customer contacted through an independently verified channel? Record the result according to approved procedures. |

### Device identifiers are not identity proof

A device ID, cookie, app-generated identifier, or fingerprint can be copied, replayed, reset, or appear differently across application versions and collection layers. Treat it as one signal. Correlate it with server-side session records, authentication events, device attestation signals where implemented, application telemetry, and transaction evidence.

### 3-D Secure is not a standalone fraud verdict

3-D Secure data should be interpreted using the relevant EMV 3-D Secure specification and the payment provider's documented field semantics. Record the actual message fields and result codes received. Do not invent an authentication outcome from a generic “3DS passed” label.

## 5. SAMA Counter-Fraud Framework: banking-sector operational references

The SAMA 2022 Banking Sector Counter-Fraud Framework has four domains: Governance, Prevent, Detect, and Respond. Its Rulebook includes 3.3 (policy and procedures), 4.1 (risk management), 5.1 (fraud detection standards), 5.2 (fraud detection systems), 6.2 (alert and case management), and 6.3 (fraud investigation). In particular, 5.2 addresses data quality, behavioural baselining, rules, risk scoring, feedback loops, calibration, and system metrics. The framework states a minimum maturity level of 3 for Member Organisations, while applicability is subject to SAMA's notification and discretion. Confirm the legal entity's status and applicable obligations with Compliance.

A separate SAMA Counter-Fraud Fundamental Requirements framework became effective on 13 April 2026 for Finance Sector — Payment Systems and Payment Services Providers. Its section 4.1 contains specific elevated-risk controls, including real-time detection, 24/7 monitoring, real-time protective actions, and stronger authentication requirements. Do not transfer those control IDs to the 2022 Banking Sector framework or assume the PSP scope applies to every bank.

For card-not-present transactions, interpret actual EMV 3DS message fields and result codes using the applicable EMVCo version and bulletin set, plus the implementation documentation of the issuer/acquirer/provider. A generic 3DS success label is not proof of legitimate customer initiation.

Official sources:
- [SAMA 2022 Counter-Fraud Framework](https://rulebook.sama.gov.sa/en/counter-fraud-framework-0)
- [SAMA 2025 Counter-Fraud Fundamental Requirements](https://rulebook.sama.gov.sa/en/counter-fraud-fundamental-requirements)
- [SAMA 2025 elevated-risk controls, section 4.1](https://rulebook.sama.gov.sa/en/41-counter-fraud-solutions-and-controls-elevated-risk)
- [EMVCo 3-D Secure](https://www.emvco.com/emv-technologies/3-d-secure/)

## 6. Containment and response decisions

Containment may include account protection, transaction blocking, session revocation, credential reset, device restrictions, endpoint isolation, or service-level controls. These actions can affect customers and business operations.

Before acting, confirm:
- The authority and approval path for the action
- The specific account, transaction, endpoint, or service in scope
- The evidence supporting the action and the risk of delay
- Customer impact, payment reversibility, and downstream dependencies
- Whether evidence must be preserved first
- How the action will be recorded, reviewed, and reversed if incorrect

Use approved playbooks and escalation paths. This page does not authorise operational actions or define an organisation's response SLA.

## 7. Investigation conclusion format

A defensible report separates:

1. **Observed facts:** directly supported by original records.
2. **Correlated facts:** independently sourced records linked by validated identifiers and time.
3. **Analysis:** interpretation of the combined evidence.
4. **Alternative explanations:** plausible benign or non-malicious causes.
5. **Assessment:** supported conclusion and confidence with rationale.
6. **Impact:** confirmed and potential customer, financial, operational, and security impact.
7. **Evidence gaps:** unavailable logs, uncertain attribution, incomplete retention, or unverified data.
8. **Actions:** decisions, approvals, owner, timestamp, and outcome.
9. **Follow-up:** control improvement, monitoring, customer communication, recovery, and lessons learned.

Avoid absolute conclusions when the evidence is incomplete. “Not observed in available logs” is not the same as “did not occur.”

## Applied walkthrough

Use the [Suspicious PowerShell from a Scheduled Task investigation](../../investigations/scheduled-task-powershell.md) to practise timeline reconstruction and competing-hypothesis analysis. It is a synthetic scenario.

**Last reviewed:** 31 October 2026. Confirm current standards, regulatory scope, and internal procedures before operational use.
