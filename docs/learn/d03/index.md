# D03 — Offensive Security & Application Testing

Use authorised testing to identify, validate, explain, and help remediate security weaknesses. This domain focuses on evidence-based verification rather than tool output alone.

## Authoritative foundations

### OWASP Application Security Verification Standard 5.0.0

OWASP ASVS provides testable security requirements for web applications and web services. Use the requirement identifiers and verification guidance from the selected ASVS release. Record the exact version and requirement ID in test evidence.

ASVS is a verification standard. The OWASP Top 10 is an awareness document about prominent application security risks; it is not a substitute for a complete verification plan.

Official sources:
- [OWASP ASVS 5.0.0](https://asvs.owasp.org/)
- [OWASP ASVS project](https://owasp.org/www-project-application-security-verification-standard/)

### FIRST CVSS v4.0

CVSS v4.0 defines Base, Threat, Environmental, and Supplemental metric groups. A Base score communicates technical vulnerability severity under the CVSS model; it does not by itself determine organisational risk or remediation priority.

For each finding, preserve:
- CVE or other vulnerability identifier, if one exists
- Affected product and exact version/configuration
- Reproduction conditions and evidence
- CVSS version, score, and full vector
- Threat and environmental assumptions
- Asset criticality, exposure, compensating controls, and business context
- Remediation recommendation and retest evidence

Official source: [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document).

**PSV tool limitation:** the current calculator on the Tools page implements CVSS v3.1, not v4.0. Do not enter a v4.0 vector into it or report its result as CVSS v4.0.

## Testing workflow

1. **Authorisation and scope:** written permission, in-scope assets, excluded systems, dates, source IPs, test accounts, and emergency contacts.
2. **Rules of engagement:** allowed techniques, rate limits, data-handling requirements, stop conditions, and reporting route.
3. **Reconnaissance:** use only approved sources and methods; record timestamps and evidence.
4. **Validation:** confirm the weakness with the least intrusive method that proves the issue.
5. **Impact assessment:** describe confidentiality, integrity, availability, affected roles, preconditions, and realistic boundaries.
6. **Reporting:** include exact affected asset/version, reproducible steps, sanitised evidence, severity methodology, and practical remediation.
7. **Retesting:** verify the fix using the same relevant conditions and record the result.

## Practical exercise

Use an intentionally vulnerable local application. Select an ASVS requirement that is relevant to the application's feature, define a safe test, record expected and observed behaviour, and explain whether the requirement is satisfied. Do not claim ASVS compliance from a small sample of tests.

Only test systems you own or have explicit written permission to assess. Avoid destructive payloads, production data, persistence, or unnecessary service disruption.

## Finding record

| Field | What to capture |
|---|---|
| Scope | Asset, owner, environment, authorisation reference |
| Requirement | ASVS version and requirement ID, if applicable |
| Weakness | Accurate technical description and affected component |
| Reproduction | Preconditions, steps, and expected/observed result |
| Evidence | Sanitised request/response, logs, screenshots, timestamps |
| Severity | CVSS version, vector and score, plus contextual risk rationale |
| Remediation | Specific change and references |
| Retest | Build/version, test conditions, observed result, date |

A scanner finding is a lead, not a confirmed vulnerability. Validate applicability and exploitability before reporting it as confirmed.
