# Industry Standards & Authoritative References

A working reference for the standards, frameworks, knowledge bases, and specifications used across the Privacy Skill Vault learning paths.

<badge color="success">Source-reviewed 31 October 2026</badge>

This page links to primary publishers wherever possible. Version labels below are the versions verified during this review; standards and knowledge bases can change, so check the publisher's release page before using a requirement in a formal assessment, control mapping, production procedure, or audit.

## How to interpret these sources

| Source type | What it provides | What it does not automatically provide |
|---|---|---|
| Standard | Defined requirements or technical specifications | Proof that an organisation complies |
| Framework | A structure for managing or assessing outcomes | A universal implementation sequence or mandatory control set |
| Knowledge base | A maintained catalogue of adversary behaviours or security knowledge | A compliance standard or a complete detection rule |
| Format / protocol | A common way to represent or exchange information | Proof that the information is accurate or trustworthy |
| Scoring system | A repeatable method to describe a defined risk dimension | A complete business-risk or remediation-priority decision |

Never describe a framework mapping as certification, compliance, or proof of implementation. Applicability depends on the organisation, service, jurisdiction, contractual obligations, and formal scope.

## Core cybersecurity frameworks

### NIST Cybersecurity Framework (CSF) 2.0

- **Publisher:** National Institute of Standards and Technology (NIST)
- **Publication:** CSWP 29, published 26 February 2024
- **Structure:** Govern, Identify, Protect, Detect, Respond, Recover
- **Use it for:** Organising cybersecurity outcomes, communicating risk, developing Current and Target Profiles, and identifying improvement priorities.
- **Do not use it as:** A fixed technical checklist or a certification by itself.

The six Functions are supported by Categories and Subcategories. Use the official Core and Informative References when mapping a control. Record the exact Subcategory ID and the organisation-specific evidence that demonstrates the outcome.

Official resources:
- [NIST CSF 2.0 publication and Core](https://www.nist.gov/cyberframework)
- [NIST CSF 2.0 PDF](https://doi.org/10.6028/NIST.CSWP.29)
- [NIST CSF 2.0 Reference Tool](https://csrc.nist.gov/Projects/cybersecurity-framework)

### NIST SP 800-61 Revision 3 — Incident Response

- **Publisher:** NIST
- **Final publication:** 3 April 2025
- **Status:** Supersedes SP 800-61 Revision 2
- **Use it for:** Integrating incident response into cybersecurity risk management, preparation, detection, response, recovery, and continual improvement.
- **Important:** Do not build a current incident-response programme solely around the older Rev. 2 lifecycle diagram. Use Rev. 3 as the current NIST publication.

Official resources:
- [SP 800-61 Rev. 3 final publication](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST incident response project](https://csrc.nist.gov/Projects/incident-response)

### CIS Critical Security Controls v8.1

- **Publisher:** Center for Internet Security (CIS)
- **Version reviewed:** 8.1
- **Use it for:** Prioritised safeguards and implementation planning. The Controls include Implementation Groups to help organisations select safeguards appropriate to their risk and resources.
- **Important:** Select the appropriate Implementation Group and assess the safeguard's actual applicability. Do not claim that a control is implemented because it appears in a plan.

Official resources:
- [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1)

## Threat-informed defence and detection engineering

### MITRE ATT&CK

- **Publisher:** MITRE
- **Type:** Maintained knowledge base of adversary tactics and techniques
- **Use it for:** Describing observed behaviour, threat-informed defence, detection coverage analysis, adversary emulation planning, and consistent technique references.
- **Important:** ATT&CK is not a compliance framework. Map behaviour to a technique only when the evidence supports it. A technique mapping does not prove attribution to a threat group or prove that a detection is effective.

Use the live Enterprise matrix and the official data resources rather than copying technique names or IDs from an old screenshot.

Official resources:
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [ATT&CK data and tools](https://attack.mitre.org/resources/working-with-attack/)
- [ATT&CK knowledge base on GitHub](https://github.com/mitre-attack/attack-stix-data)

### Sigma Detection Format

- **Publisher:** SigmaHQ
- **Specification reviewed:** Sigma Rules Specification 2.1.0, released 2 August 2025
- **Use it for:** Writing portable, YAML-based detection rules with a defined log source, detection selections, condition, metadata, and optional fields.
- **Important:** A valid Sigma rule is not automatically a working SIEM detection. Backend support, field mappings, event collection, data normalisation, query translation, and test data all matter.

The specification defines condition logic, value modifiers, status, logsource, tags, and schema. Use maintained Sigma tooling such as the official Sigma CLI / pySigma ecosystem for conversion; then inspect the generated query and test it against the target SIEM and actual event schema.

Official resources:
- [Sigma specification repository](https://github.com/SigmaHQ/sigma-specification)
- [Sigma Rules Specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma rule-writing guide](https://sigmahq.io/docs/basics/rules.html)
- [Sigma main detection repository](https://github.com/SigmaHQ/sigma)

### OASIS STIX 2.1 and TAXII 2.1

- **Publisher:** OASIS Open
- **Type:** Standards for representing and exchanging cyber threat intelligence
- **STIX 2.1:** Defines the language and object model for representing threat intelligence.
- **TAXII 2.1:** Defines an application-layer protocol and API resources for exchanging cyber threat intelligence.
- **Important:** STIX is the representation model; TAXII is the exchange protocol. Neither guarantees that an indicator is current, malicious, or relevant to your environment.

Official resources:
- [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
- [OASIS TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html)
- [OASIS CTI documentation](https://oasis-open.github.io/cti-documentation/)

## Vulnerability and application security

### FIRST Common Vulnerability Scoring System (CVSS) v4.0

- **Publisher:** FIRST
- **Version reviewed:** CVSS v4.0, Specification Document 1.2
- **Metric groups:** Base, Threat, Environmental, Supplemental
- **Use it for:** Communicating vulnerability severity using defined technical metrics and a vector string.
- **Important:** CVSS is not a complete organisational risk score. Consider asset criticality, exposure, compensating controls, exploit intelligence, business impact, and applicable regulatory deadlines separately.

A published CVSS result should include the score and vector string. Do not silently mix CVSS v3.1 and v4.0 vectors or scores.

Official resources:
- [FIRST CVSS specification](https://www.first.org/cvss/specification-document)
- [CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document)
- [FIRST CVSS resources](https://www.first.org/cvss/)

**PSV tool compatibility:** The current CVSS calculator on the Tools page implements CVSS v3.1. It must not be used to calculate or label a CVSS v4.0 vector. The v3.1 calculator is retained as a version-specific tool, not represented as the latest CVSS version.

### OWASP Application Security Verification Standard (ASVS)

- **Publisher:** OWASP
- **Version reviewed:** ASVS 5.0.0, published 30 May 2025
- **Use it for:** Testable security requirements for designing, developing, and verifying web applications and web services.
- **Important:** ASVS is more appropriate for verification requirements than treating the OWASP Top 10 risk list as a complete test plan. Select verification requirements appropriate to the application's architecture and risk.

Official resources:
- [OWASP ASVS](https://asvs.owasp.org/)
- [OWASP ASVS project](https://owasp.org/www-project-application-security-verification-standard/)

### PCI DSS v4.0.1

- **Publisher:** PCI Security Standards Council (PCI SSC)
- **Version reviewed:** v4.0.1, published June 2024
- **Scope:** Entities that store, process, or transmit cardholder data or sensitive authentication data, and entities that can impact the security of the cardholder data environment.
- **Use it for:** Payment account data security requirements and assessment where the entity and environment are in scope.
- **Important:** Applicability and validation obligations depend on the payment ecosystem, acquirer/payment brand requirements, and the entity's scope. Use PCI SSC documents and a qualified assessor where required.

Official resources:
- [PCI DSS overview](https://www.pcisecuritystandards.org/standards/pci-dss/)
- [PCI SSC document library](https://www.pcisecuritystandards.org/document_library/)

### EMV® 3-D Secure (3DS)

- **Publisher:** EMVCo
- **Type:** Payment-card authentication protocol specifications and associated bulletins
- **Use it for:** Understanding the 3DS message flow, roles, data elements, authentication outcomes, SDK behaviour, and version-specific requirements.
- **Important:** 3DS version, message fields, and result semantics must be read from the applicable specification and bulletin set used by the issuer, acquirer, directory server, ACS, 3DS Server, SDK, and payment provider. Do not treat a generic “3DS passed” label as proof that the legitimate account holder initiated the payment or that fraud is impossible.

Official resources:
- [EMVCo 3-D Secure](https://www.emvco.com/emv-technologies/3-d-secure/)
- [EMVCo 3DS documentation and specification versions](https://www.emvco.com/dynamic/emv-3-d-secure-whitepaper-v2/3-d-secure-documentation/)
- [EMVCo 3DS v2.3.1 specification page](https://www.emvco.com/whitepapers/emv-3-d-secure-whitepaper-v2/3-d-secure-documentation/3-d-secure-specification-v2-3-1/)

## Saudi financial-sector counter-fraud requirements

These sources are jurisdiction- and sector-specific. They must not be conflated.

### SAMA Counter-Fraud Framework — Banking Sector

- **Publisher:** Saudi Central Bank (SAMA)
- **Framework reference:** Circular 000044021528, dated 11 October 2022
- **Rulebook status shown during review:** In Force
- **Scope shown in the Rulebook:** Banking Sector
- **Domains:** Governance, Prevent, Detect, Respond

Relevant operational sections include:
- **3.3 — Counter-Fraud Policy and Procedures:** policy and associated procedures should be defined, approved, communicated, and implemented.
- **3.3 — Counter-Fraud Policy and Procedures:** approved and communicated policy and procedures.
- **4.1 — Risk Management:** fraud risk management framework, KPIs, fraud risk assessment, risk appetite, and KRIs. This is not the separate 2025 elevated-risk control set.
- **5.1 — Fraud Detection Standards:** approved detection standards aligned to internal and external fraud risks.
- **5.2 — Fraud Detection Systems:** data timeliness, completeness and accuracy; behavioural baselining; rule libraries; risk scoring; case-management linkage; calibration; false-positive/false-negative feedback; and monitoring of system metrics.
- **6.2 — Alert and Case Management:** case ownership, lifecycle tracking, investigative steps, evidence repository, outcomes, losses, corrective actions, and retention.
- **6.3 — Fraud Investigation:** time sensitivity, materiality, information gathering, collaboration, documentation, retention, outcomes, reporting, corrective action, notifications, root cause and lessons learned.

The framework describes six maturity levels (0–5) and states that Member Organisations should operate at level 3 or higher. Confirm the entity's applicability and current interpretation with Compliance and current SAMA communications.

Official resources:
- [SAMA Counter-Fraud Framework — Rulebook](https://rulebook.sama.gov.sa/en/counter-fraud-framework-0)
- [SAMA Counter-Fraud Framework — official document](https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Counter_Fraud_Framework.pdf)
- [SAMA elevated-risk controls, section 4.1](https://rulebook.sama.gov.sa/en/41-counter-fraud-solutions-and-controls-elevated-risk)

### SAMA Counter-Fraud Fundamental Requirements — payment systems and payment services providers

The SAMA Rulebook separately lists Counter-Fraud Fundamental Requirements with scope stated as **Finance Sector — Payment Systems and Payment Services Providers**, and an effective date of 13 April 2026.

Do not automatically apply this scope statement to every bank or assume it replaces the Banking Sector Counter-Fraud Framework. Confirm the legal entity's licence, regulated activity, applicability, and current SAMA instructions.

Official resource:
- [SAMA Counter-Fraud Fundamental Requirements](https://rulebook.sama.gov.sa/en/counter-fraud-fundamental-requirements)

### SAMA Counter-Fraud Fundamental Requirements — payment systems and payment services providers (effective 13 April 2026)

This is a separate Rulebook framework from the 2022 Banking Sector Counter-Fraud Framework above.

- **Publisher:** Saudi Central Bank (SAMA)
- **Rulebook reference:** No. 106897184, dated 14 April 2025
- **Effective date:** 13 April 2026
- **Scope shown in the Rulebook:** Finance Sector — Payment Systems and Payment Services Providers
- **Status shown during review:** In Force
- **Use it for:** Requirements applicable to entities and activities within that stated scope. Do not automatically apply this framework to every bank or treat it as a replacement for the 2022 Banking Sector framework.

The Rulebook's separate section **4.1 — Counter-Fraud Solutions and Controls for Elevated Risk** includes numbered controls such as:
- **4.1.1:** real-time fraud detection and prevention across transactional and non-transactional data.
- **4.1.2:** 24/7 operation with appropriate resources to manage system outputs.
- **4.1.4:** timely real-time actions, including account freezing and transaction blocking where compromise is suspected.
- **4.1.8–4.1.9:** multi-factor authentication for specified higher-risk activities and a requirement that SMS OTP alone not be the only factor.
- **4.1.11–4.1.12:** mule-account controls and updates to rules/models for emerging typologies.

These are the control IDs of the 2025 Counter-Fraud Fundamental Requirements, not section numbers from the 2022 Banking Sector Counter-Fraud Framework.

Official resources:
- [SAMA Counter-Fraud Fundamental Requirements](https://rulebook.sama.gov.sa/en/counter-fraud-fundamental-requirements)
- [Section 4.1 — Counter-Fraud Solutions and Controls for Elevated Risk](https://rulebook.sama.gov.sa/en/41-counter-fraud-solutions-and-controls-elevated-risk)

## Practical mapping: from standard to operational evidence

| Operational activity | Authoritative reference | Evidence to retain |
|---|---|---|
| Establish security outcomes and priorities | NIST CSF 2.0 | Current/Target Profile, risk decisions, owners, evidence |
| Prepare and improve incident response | NIST SP 800-61 Rev. 3 | Plan, roles, exercises, lessons learned, improvement actions |
| Prioritise safeguards | CIS Controls v8.1 | Applicable safeguards, implementation group, owner, validation |
| Describe observed adversary behaviour | MITRE ATT&CK | Source events, technique rationale, confidence, coverage gap |
| Author portable detections | Sigma specification | Rule YAML, schema validation, backend translation, test results |
| Exchange threat intelligence | STIX 2.1 / TAXII 2.1 | Source, object IDs, markings, timestamps, confidence, expiry/revocation |
| Communicate vulnerability severity | FIRST CVSS v4.0 | Score, vector, source, threat and environmental context |
| Verify application security | OWASP ASVS 5.0 | Requirement ID, test procedure, result, evidence, exception |
| Protect payment account data | PCI DSS v4.0.1 | Scope, applicable requirement, testing evidence, assessor decision |
| Manage bank counter-fraud operations | SAMA 2022 Banking Sector Counter-Fraud Framework | Applicable control reference, approved policy/procedure, operating evidence, KPI/KRI |
| Payment-service-provider elevated-risk controls | SAMA 2025 Counter-Fraud Fundamental Requirements, where in scope | Applicable control ID, entity scope confirmation, implementation and operating evidence |
| Interpret card-not-present authentication evidence | EMVCo 3-D Secure specifications | Actual message version, identifiers, relevant data elements, authentication result and provider semantics |

This table is a navigation aid, not a formal crosswalk. It does not assert that one framework requirement is equivalent to another.

## How PSV will maintain accuracy

Every standards-based page should include:

1. Publisher and exact standard/framework/specification version.
2. Official source link and publication/release date where available.
3. Exact control, requirement, category, subcategory, or technique ID when referenced.
4. Applicability and scope notes.
5. An implementation example clearly separated from the source requirement.
6. Evidence required to demonstrate execution.
7. Last-reviewed date and a note to recheck the publisher before formal use.

If a publisher changes a version or retires a requirement, update the reference before presenting it as current. Where a document is paywalled or licensed, link to the official source rather than reproducing proprietary text.

**Last source review:** 31 October 2026. This is a point-in-time review, not an automated standards-change monitoring service.
