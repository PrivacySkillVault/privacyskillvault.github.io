# Account Takeover (ATO) Investigation Playbook

<badge color="warning">Operational reference — follow approved bank procedures</badge>

## Purpose

Provide a repeatable evidence-led investigation for suspected digital-channel account takeover, including disputed transactions. This playbook is a checklist and decision aid; it does not authorise account restrictions, transaction blocks, customer contact, or regulatory notifications.

## 1. Establish the case and preserve evidence

Record the case ID, alert/reference IDs, customer/account reference in the authorised case platform, detection source, time first observed, investigator, case owner, current status, and approved priority.

Preserve original records before enrichment or transformation. Record source system, native event ID, event timestamp and time zone, collection time, record/request/trace/session identifiers, collector, export method, integrity hash where supported, and access restrictions.

Do not paste customer identifiers, authentication secrets, full card data, OTPs, session tokens, or internal production logs into this public template or an unapproved service.

## 2. Build a single timeline

Normalise timestamps to UTC while retaining the original timestamp and offset. Use a timeline table:

| UTC time | Source | Event / action | Actor / account | Device / session | IP / channel | Transaction | Evidence reference |
|---|---|---|---|---|---|---|---|
| [time] | [IAM/app/fraud/core] | [login/profile change/payment] | [masked ID] | [ID] | [IP/channel] | [ID] | [record ID] |

Do not correlate solely on a timestamp. Prefer server-issued identifiers and independently observed keys: authentication request ID, session ID, API request/trace ID, transaction ID, payment reference, 3DS transaction identifiers, device attestation reference, and account/customer key. Record the reliability and origin of each identifier.

## 3. Evidence collection matrix

| Domain | Collect | Questions / caveats |
|---|---|---|
| Identity provider / IAM | Login attempts, success/failure, MFA challenge/result, password reset, recovery, authenticator enrolment/removal, lockout, token/session issue and revocation | Which component authenticated the user? Which factor was actually validated? |
| Mobile/web application | App version, device ID and fingerprint, device attestation result if implemented, session creation/refresh/revoke, API route, request/trace ID, server response | Was the identifier generated client-side or server-side? Could it be copied or replayed? |
| API gateway / WAF | Request ID, trace ID, route, method, source IP, TLS/client metadata available, status, upstream target and latency | Was the call received, rejected, retried, or routed elsewhere? |
| Fraud platform | Rule/model version, evaluated features, score, decision, reason codes, latency, override, bypass/disable event, operator and configuration history | What exact data was evaluated at decision time? Were rules disabled or thresholds changed? |
| Core banking / payment | Transaction ID, posting/authorisation state, amount, currency, beneficiary, rail, timestamps, reversals/returns, channel and authorisation references | Distinguish initiated, authorised, accepted, posted, settled, reversed and returned states. |
| Device / endpoint | EDR events, device registration, OS/app version, root/jailbreak/attestation signals, malware findings, integrity signals | A matching device ID is not proof of the same physical device or legitimate user. |
| Network / infrastructure | IP, port, ASN/geo enrichment, DNS, proxy, VPN indicators, firewall, load balancer, NAT and TLS metadata | IP and geolocation are contextual signals; consider carrier NAT, VPNs, proxies and shared egress. |
| Customer / channel | Contact history, verified callback result, dispute details, known travel/accessibility context where lawfully available | Use independently verified contact routes and approved customer-contact scripts. |
| 3-D Secure / card rails | Protocol version, message identifiers, result/status, challenge flow, ECI and other fields supplied by the provider | Interpret fields with the applicable EMVCo version and provider mapping. Authentication result is not a complete fraud verdict. |

## 4. Correlation logic

Use the following sequence and record each join:

1. Link the disputed transaction to the payment/core record using the authoritative transaction or payment reference.
2. Link the transaction to the fraud decision using the decision reference, rule execution ID or trace ID.
3. Link the fraud decision to the application/API request using a server-side request or trace ID.
4. Link the API request to the authenticated session using the session reference; establish whether the mapping is direct or inferred.
5. Link the session to the authentication event using the identity provider's authentication/request ID and user/account key.
6. Link the session/device to network and endpoint evidence using multiple attributes and timestamps, not a client-controlled device ID alone.
7. Independently compare the resulting chain with customer dispute evidence and known-good historical behaviour.

A join that relies only on approximate time, IP, user-agent or a client-generated device ID must be labelled a weak correlation—not a confirmed link.

## 5. When the session is missing from logs

Do not conclude that a session did not exist merely because it is absent from one log source. Investigate the logging path:

- Was the session created by a different component, region, API version, gateway, or authentication provider?
- Is the expected event generated at all, or only after a successful downstream step?
- Was the log sampled, filtered, dropped, delayed, overwritten, or outside retention?
- Are clocks out of sync or time zones misinterpreted?
- Did an asynchronous queue, retry, cache, or service-to-service call break trace propagation?
- Are request IDs and trace IDs regenerated at a proxy or gateway?
- Did the request fail before application logging, or did a downstream service accept a request without the expected upstream log?
- Was there a logging configuration change, service restart, audit disablement, or pipeline incident?
- Can the provider, API gateway, WAF, load balancer, mobile telemetry, or core system independently corroborate the request?

Document the exact sources searched, query/time range, retention status, and whether the source is expected to log that event. Use the conclusion **“not present in the available source records”** until the gap is explained.

## 6. Assess device-ID cloning or replay hypotheses

A cloned or reused device identifier is a hypothesis to test, not a conclusion based on duplicate values alone.

Compare:
- Client device ID against server-side device registration and attestation references.
- App instance ID, app version, OS build, device model and integrity signals.
- Concurrent or near-concurrent sessions using the same identifier from incompatible network contexts.
- Device ID history, reset/re-registration events and identifier lifecycle.
- TLS/client metadata and API request patterns where lawfully collected.
- Authentication factors, session tokens and token lifecycle; do not expose token values in the case report.
- Differences between mobile telemetry, API gateway records and fraud-platform feature inputs.

Possible explanations include identifier cloning/replay, legitimate app reinstall or migration, SDK changes, shared devices, account sharing, data mapping defects, stale cache, or a provider integration issue. Seek independent evidence before choosing among them.

## 7. Assess transaction and customer impact

Record each disputed transaction separately. Distinguish attempted, declined, authorised, posted, settled, reversed, returned and recovered amounts. Record currency, fee/FX impact, beneficiary, rail, transaction status, dispute status, and any related transactions.

Determine whether the same session/account/device/beneficiary or fraud pattern affects other customers. Use approved internal link-analysis and case-management controls.

## 8. Decision and escalation

Escalate according to approved policy when there is credible evidence of ongoing unauthorised access, attempted/confirmed financial loss, compromised credentials or sessions, multiple affected customers, suspected control bypass, or a material logging/control failure.

For any protective action, record:
- Decision-maker and authority
- Evidence and risk basis
- Exact scope (account/session/device/transaction)
- Execution time, operator and system result
- Customer/service impact
- Review and reversal criteria

Do not infer a mandatory action or deadline from this playbook. Use the institution's current policy, payment scheme rules, contracts, and applicable regulatory obligations.

## 9. Case conclusion

State one of: confirmed unauthorised activity; likely unauthorised activity; suspicious but inconclusive; legitimate/authorised activity; control/process failure without confirmed fraud; or unable to determine. Define the institution's approved case outcomes if they differ.

Include observed facts, correlated facts, analysis, alternative hypotheses, confidence, losses/attempts, customer impact, control gaps, actions and approvals, evidence gaps, root cause (if supported), corrective actions, owners and target dates.

## References

- [SAMA 2022 Counter-Fraud Framework — 5.2 Fraud Detection Systems](https://rulebook.sama.gov.sa/en/52-fraud-detection-systems)
- [SAMA 2022 Counter-Fraud Framework](https://rulebook.sama.gov.sa/en/counter-fraud-framework-0)
- [SAMA 2022 Counter-Fraud Framework — 6.3 Fraud Investigation](https://rulebook.sama.gov.sa/en/63-fraud-investigation)
- [EMVCo 3-D Secure](https://www.emvco.com/emv-technologies/3-d-secure/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
