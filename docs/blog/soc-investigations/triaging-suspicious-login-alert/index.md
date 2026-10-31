# Triage a Suspicious Login Alert Without Jumping to Conclusions

<small>SOC INVESTIGATIONS · ALERT TRIAGE · 01 NOV 2026</small>

<p class="psv-article-breadcrumb"><a href="../">← SOC Investigations</a><span> / </span><a href="../../">Cyber Journal</a></p>

A login alert may be triggered by an unfamiliar IP address, impossible-travel logic, repeated failures, a new device, or an unusual sign-in time. These signals are useful, but each has legitimate explanations. The analyst's job is to determine whether the activity represents unauthorised access, not simply to confirm that something was unusual.

## 1. Identify what the alert actually represents

Before investigating, read the detection logic and source schema. Does the alert describe a failed attempt, successful authentication, MFA challenge, session issuance, or application request? These are different events.

A successful authentication record means the identity system accepted the configured authentication process. It does not prove the account owner personally performed the action.

## 2. Build a small evidence set

Collect, where available and authorised:

- User and account status, including privileged roles.
- Authentication success and failure records.
- MFA challenge and outcome details.
- Password reset and account recovery events.
- Device enrolment or trust changes.
- Session creation, refresh, use, and revocation.
- Source IP, ASN, geolocation estimate, VPN/proxy indicators.
- Application actions after sign-in.
- Customer or user confirmation through approved channels.

Keep raw source records and record the timezone.

## 3. Evaluate context

| Signal | Possible benign explanation | Follow-up |
|---|---|---|
| New country or city | Travel, VPN, mobile carrier routing | Compare device, session and customer context |
| New IP | ISP address rotation or shared NAT | Review ASN, reputation and history |
| Repeated failures | Mistyped password or stale client | Check account spread, timing and success after failures |
| New device | Phone replacement or app reinstall | Review enrolment and recovery events |
| MFA approval | Legitimate user or coerced/fatigued approval | Verify challenge details and user confirmation |
| Unusual hour | Shift work, travel, automation | Compare normal account and application patterns |

Geolocation is approximate. Do not use it as sole evidence of compromise.

## 4. Look beyond the login

The most important activity may occur after authentication. Review profile changes, recovery details, new API tokens, mailbox rules, beneficiary additions, payment attempts, data access, and privilege changes as relevant to the application.

An attacker may use valid credentials and legitimate tools. MITRE ATT&CK describes this as Valid Accounts (T1078), which can support several stages of an intrusion.

## 5. Make a proportionate decision

Use an evidence-based classification such as:

- Benign / expected.
- Suspicious but unconfirmed.
- Confirmed unauthorised access.
- Inconclusive due to missing telemetry.

Follow the organisation's approved escalation and containment process. Do not lock accounts, reset credentials, or contact customers outside authorised procedures.

## 6. What good case notes look like

Write a short conclusion with the time window, affected account, source events, observed anomaly, corroborating evidence, contradictory evidence, customer validation status, actions taken, and remaining gaps.

Avoid statements such as “hacker logged in” when the evidence only shows an unfamiliar successful sign-in.

## References

- [Microsoft Event 4624 — Successful Logon](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
- [MITRE ATT&CK — Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [NIST SP 800-61 Rev. 3 — Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

*Use this workflow only within approved monitoring and incident-response authority.*