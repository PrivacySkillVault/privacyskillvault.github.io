# How to Prioritise Vulnerabilities Beyond the CVSS Score

<small>VULNERABILITIES · RISK-BASED PATCHING · 01 NOV 2026</small>

<p class="psv-article-breadcrumb"><a href="../">← Vulnerabilities</a><span> / </span><a href="../../">Cyber Journal</a></p>

A vulnerability scanner may return hundreds or thousands of findings. If a team sorts only by CVSS score, it can miss flaws that are actively exploited or exposed on critical systems. Conversely, a high score does not automatically mean every installation is equally urgent.

CVSS is valuable, but it is one input to vulnerability risk management—not the whole decision.

## 1. Start with technical severity

Review the CVSS score and vector. The vector explains assumptions such as attack vector, privileges required, user interaction, and impact. A score without its vector hides important context.

CVSS v4.0 also distinguishes Base, Threat, Environmental, and Supplemental metrics. Where available, use the relevant Threat and Environmental context rather than assuming a Base score describes your organisation's exact risk.

## 2. Check known exploitation

CISA's Known Exploited Vulnerabilities (KEV) catalog identifies vulnerabilities for which CISA has reliable evidence of exploitation in the wild, according to its inclusion criteria. KEV status is a strong prioritisation signal.

A public proof-of-concept is not the same as confirmed exploitation. Nor does absence from KEV prove a vulnerability is safe or never exploited.

## 3. Consider exploitation likelihood

FIRST's EPSS estimates the probability that a publicly disclosed vulnerability will be exploited in the wild within the next 30 days. Scores range from 0 to 1 and are updated daily.

EPSS is not an impact score and does not know whether your particular asset is exposed, important, or protected. Use it as a threat-likelihood input alongside local context.

## 4. Understand your asset

For each affected asset, ask:

- Is it internet-facing or reachable only through restricted networks?
- Does it support a critical business service?
- Does it process sensitive data?
- Is the vulnerable component enabled and reachable?
- Are compensating controls effective and tested?
- Is the system shared, clustered, or part of a dependency chain?
- Is a vendor patch available, and what is the change risk?

A vulnerability on an exposed identity provider may deserve more urgent attention than the same issue on an isolated, disposable test system.

## 5. Build a transparent prioritisation record

| Dimension | Example evidence |
|---|---|
| Technical severity | CVSS version, score and vector |
| Exploitation status | CISA KEV, vendor advisory, credible incident intelligence |
| Exploitation likelihood | EPSS score and retrieval date |
| Exposure | Internet reachability, network zone, attack surface |
| Asset criticality | Business owner, service tier, data sensitivity |
| Mitigations | WAF, segmentation, configuration, EDR, access controls |
| Remediation | Patch availability, workaround, outage/change constraints |

Avoid inventing a universal formula. Organisations may use scoring models, but the weights should be approved, explainable, tested, and aligned with regulatory and business requirements.

## 6. Example decision

**Illustrative scenario:** Finding A has a very high CVSS score but affects a component that is not installed on the production asset. Finding B has a lower score but is confirmed in KEV and affects an internet-facing service.

Finding B may require faster action, even though its CVSS score is lower. The final decision should still validate product/version applicability, exposure, available mitigations, and the organisation's approved remediation policy.

## 7. Measure the process

Useful vulnerability-management measures include:

- Time from verified finding to owner assignment.
- Time to remediation by severity and exploitation status.
- Number of KEV findings past the organisation's target date.
- Recurrence of findings after remediation.
- Percentage of findings with verified asset ownership.
- Exceptions with an owner, rationale, expiry, and compensating controls.

Do not reward teams for closing findings without validating that the vulnerable condition is actually removed or mitigated.

## Key takeaways

Use CVSS to understand technical severity, KEV to identify known exploitation, EPSS to estimate near-term exploitation likelihood, and asset context to understand business impact. Document the decision and re-evaluate as threat information changes.

## References

- [FIRST — CVSS v4.0](https://www.first.org/cvss/v4-0/)
- [FIRST — EPSS FAQ](https://www.first.org/epss/faq)
- [CISA — Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NIST SP 800-40 Rev. 4 — Guide to Enterprise Patch Management Planning](https://csrc.nist.gov/pubs/sp/800/40/r4/final)

*The article describes a prioritisation approach, not a substitute for your organisation's approved patching policy or regulatory deadlines.*