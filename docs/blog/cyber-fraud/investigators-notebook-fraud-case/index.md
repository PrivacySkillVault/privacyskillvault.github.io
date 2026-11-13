# The Investigator's Notebook: Recording Cyber Fraud Evidence Clearly

<small>CYBER FRAUD · INVESTIGATION PRACTICE · 13 NOV 2026 · 8 MIN READ</small>

<p class="psv-article-breadcrumb"><a href="../">← Cyber Fraud</a><span> / </span><a href="../../">Cyber Journal</a></p>

A good investigation notebook makes it possible for another analyst to understand what was examined, what was found and how a conclusion was reached. It should be factual, chronological and clear about uncertainty.

## What to record

- Case reference and investigation scope.
- Date and time of each action, including time zone.
- Evidence source and the person or system that provided it.
- Search terms, filters and time ranges used.
- Original event identifiers and relevant correlation references.
- Observations, hypotheses and alternative explanations.
- Evidence gaps, technical limitations and follow-up requests.
- Decisions, approvals and escalation details.

## Separate facts from interpretation

**Fact:** The payment system recorded a transfer request at 14:03:21 UTC.

**Assessment:** The transfer may have been initiated through an existing authenticated session.

**Unknown:** The available records do not establish who physically operated the device.

This structure avoids turning a plausible theory into a statement of fact.

## Evidence handling

Preserve original records where policy allows. Record how evidence was collected, transferred, stored and accessed. Use approved integrity mechanisms such as hashes for exported files when appropriate. Do not copy passwords, OTPs, raw session tokens or unnecessary personal data into a notebook.

## Build a timeline

A useful timeline may include customer contact, authentication, session events, profile changes, beneficiary creation, transaction initiation, risk decisions and settlement. Keep original timestamps and time zones, and document any conversion to a common time base.

## Record negative findings carefully

"Not found in the queried log source for the specified time range" is more accurate than "the event did not occur." State which source was searched, its retention and known coverage.

## Suggested case-note template

| Field | Example |
|---|---|
| Time | 2026-11-13 14:03 UTC |
| Source | Payment audit service |
| Event | Transfer initiated |
| Reference | Protected internal transaction reference |
| Observation | Event recorded as submitted |
| Assessment | Requires correlation with authorisation logs |
| Gap | Customer interaction evidence not yet received |

## Key takeaways

Good notes are reproducible and defensible. Record sources, timestamps, methods, facts, hypotheses and gaps separately. Protect sensitive information and follow your organisation's evidence-handling requirements.

## References

- [NIST SP 800-61 Rev. 3 — Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
- [OWASP — Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

*Privacy Skill Vault publishes educational material. Examples are illustrative unless explicitly identified and sourced as real incidents. This article is general information, not advice for a specific case.*