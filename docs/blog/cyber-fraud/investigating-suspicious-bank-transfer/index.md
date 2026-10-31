# Investigating a Suspicious Bank Transfer: Build the Timeline Before the Theory

<small>CYBER FRAUD · CASE INVESTIGATION · 01 NOV 2026</small>

<p class="psv-article-breadcrumb"><a href="../">← Cyber Fraud</a><span> / </span><a href="../../">Cyber Journal</a></p>

A disputed bank transfer is an outcome that needs explaining. It does not, by itself, tell an investigator whether the cause was stolen credentials, social engineering, a compromised device, session misuse, an authorised push-payment scam, or a control failure.

The most reliable starting point is a neutral timeline. Establish what happened, which system recorded it, and what each event actually proves before deciding on an attack narrative.

## 1. Define the question

Separate the investigation into distinct questions:

- Was the customer account accessed by an unauthorised party?
- Was the session authenticated, recovered, or reused?
- Was a beneficiary added or modified?
- How was the payment initiated and authorised?
- Which controls were evaluated, challenged, bypassed, or unavailable?
- What did the customer report, and when?
- Did the payment settle, fail, reverse, or reach another institution?

These questions may have different answers. A customer may have been socially engineered into authorising a payment without the account being technically taken over.

## 2. Build a time-normalised event timeline

Collect records from systems that own each event. Keep the original timestamp and timezone, then add a normalised UTC value for comparison. Record ingestion time separately where available.

| Stage | Records to request | What to establish |
|---|---|---|
| Customer contact | Call, complaint, secure-message records | When the customer noticed and reported the activity |
| Authentication | Identity provider, MFA, password reset, recovery | How the identity check was completed |
| Device | Registration, app attestation, device-risk events | What device evidence was recorded and its provenance |
| Session | Session issue, refresh, validation, expiry, revocation | Whether requests belonged to one session or multiple sessions |
| Profile | Phone, email, password, security-setting changes | Whether account control changed before payment |
| Beneficiary | Create, edit, approval, cooling-off events | When the payee became usable |
| Transaction | Initiation, authorisation, risk decision, processing | Which payment action was requested and accepted |
| Downstream | Clearing, settlement, reversal, receiving-bank response | Where the funds went and what recovery actions occurred |

Do not assume the same event identifier exists across every platform. Map correlation identifiers carefully and document any joins based on approximate time or other indirect attributes.

## 3. Understand the authentication record

A successful login event usually means that a particular authentication system recorded a successful check. It does not necessarily prove the customer personally operated the device.

Review failed and successful attempts, factor challenges, reset flows, device enrolment, and changes to registered contact methods. Check whether a session was created after the authentication event and whether later API requests were tied to that session.

If a payment uses an existing session, there may be no new password event at payment time. That is why login logs alone are insufficient.

## 4. Reconstruct the transaction decision

For the payment, identify:

- The channel and operation requested.
- The beneficiary's creation and activation history.
- The authentication or step-up requirement applied.
- The fraud rules and risk signals evaluated at the time.
- The decision returned by each relevant control.
- Any manual override, timeout, retry, or fallback.
- The final payment state and downstream references.

Distinguish a rule being evaluated from a rule being enforced. A log saying a rule matched is not enough to establish that it blocked or challenged the transaction.

## 5. Test competing hypotheses

| Hypothesis | Evidence that may support it | Evidence that may weaken it |
|---|---|---|
| Credential compromise | Unusual login context, password reset, breached credential indicators | Strong independent evidence of customer-initiated access |
| Session misuse | Existing session used from an unexpected context; token lifecycle anomalies | Consistent device-bound session evidence and customer confirmation |
| Recovery abuse | Contact or factor changes before access | Recovery completed through independently verified customer process |
| Social engineering | Customer confirms being coached or deceived | No supporting customer or communication evidence |
| Application/control defect | Unexpected authorisation path, missing enforcement or inconsistent service logs | Reproducible control decision with complete audit trail |
| Customer-authorised payment | Customer knowingly initiated and confirmed payment | Evidence of coercion, deception, or unauthorised access |

A hypothesis is not a finding. Record supporting and contradictory evidence, confidence, and outstanding gaps.

## 6. When logs are missing

Missing telemetry is not proof that an event did not occur. Check retention, ingestion delay, filtering, sampling, service boundaries, clock drift, correlation logic, and whether the expected component was configured to emit the event.

Ask the application and platform teams for the event schema and lifecycle: which component creates the event, when it is emitted, what failures suppress it, and whether retries or asynchronous processing change its timing.

Preserve raw records before transformations. Avoid sharing sensitive identifiers outside approved channels.

## 7. Write a defensible case conclusion

A good case report separates:

- **Established facts:** directly supported by records or customer confirmation.
- **Assessment:** the most plausible explanation and why.
- **Alternative explanations:** credible possibilities not ruled out.
- **Control observations:** what worked, failed, or could not be verified.
- **Evidence gaps:** unavailable records or unresolved inconsistencies.
- **Actions:** containment, payment recovery, rule review, and telemetry improvement.

## Key takeaways

- Start with the disputed transaction and work backwards through the timeline.
- Authentication, session, authorisation, and payment processing are different events.
- A missing log does not establish a bypass.
- A device or IP match does not identify the person behind an action.
- Make findings proportional to the evidence.

## References

- [NIST SP 800-61 Rev. 3 — Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MITRE ATT&CK — Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)

*This is a generic investigation framework. It is not a description of a specific customer case, bank, or internal fraud platform.*