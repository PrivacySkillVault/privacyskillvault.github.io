# Deconstructing a Phishing Message: A Step-by-Step Evidence Walkthrough

<small>CYBER FRAUD · INVESTIGATION WALKTHROUGH · 13 NOV 2026 · 9 MIN READ</small>

<p class="psv-article-breadcrumb"><a href="../">← Cyber Fraud</a><span> / </span><a href="../../">Cyber Journal</a></p>

A phishing message should be analysed as evidence, not judged only by how suspicious it looks. The aim is to determine what the message claims, where it came from, what action it requests and whether the recipient interacted with it.

The example below is fictional and uses placeholder details.

## Example message

**Subject:** Urgent: Account access will be suspended

**Message:** Your account requires verification today. Use the link below to confirm your details.

**Displayed link:** `https://bank.example/verify`

The displayed text may not match the actual destination. Do not open suspicious links on a normal workstation to inspect them.

## 1. Examine the sender

Review the full sender address, reply-to address and available message headers. Display names can be chosen by the sender. Authentication results such as SPF, DKIM and DMARC can help assess domain-level sending claims, but a passing result does not prove that the message is safe or that the request is legitimate.

## 2. Inspect the link safely

Extract the actual URL using approved tooling. Review the hostname, subdomains, path, redirects and certificate information. A valid TLS certificate means the connection is encrypted to that hostname; it does not mean the site is trustworthy.

## 3. Review attachments

Record file names, sizes and cryptographic hashes. Use approved sandbox or malware-analysis procedures. Do not execute unknown attachments on a production device.

## 4. Establish user interaction

Ask whether the recipient opened the link, entered credentials, downloaded a file, enabled macros, approved a prompt or shared an OTP. A delivered message is not the same as a successful compromise.

## 5. Correlate telemetry

Review mail gateway verdicts, click-protection logs, DNS and proxy records, endpoint process events, identity-provider sign-ins and account changes. Use timestamps carefully and preserve the source time zone.

## 6. Record the conclusion

Separate observed facts from assessment. For example, "The message contained a link to an unrelated domain" is an observation. "The sender was a named criminal group" requires separate attribution evidence.

## India-first examples

A fictional phishing message might claim that a bank KYC record needs urgent verification, that a UPI payment is pending, or that a courier fee must be paid. These are illustrative pretexts only. A legitimate UPI collect request is not automatically fraudulent; inspect the payee and purpose and do not approve a request you did not initiate or understand. In Saudi Arabia, similar analysis applies to messages imitating banks, delivery services or digital-government services.

## Key takeaways

- Analyse full headers and actual destinations, not only display names and link text.
- TLS and email authentication are useful signals, not guarantees of legitimacy.
- Determine whether the recipient interacted with the content.
- Correlate email, identity, endpoint and network evidence.

## References

- [CISA — Recognize and Report Phishing](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)
- [Google — Email Authentication](https://support.google.com/a/answer/81126)
- [OWASP — Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

*Privacy Skill Vault publishes educational material. Examples are illustrative unless explicitly identified and sourced as real incidents. This article is general information, not advice for a specific case.*