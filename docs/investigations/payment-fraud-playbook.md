# Payment Fraud Investigation Playbook

<badge color="warning">Operational reference — not payment-scheme advice</badge>

## Purpose

Structure an investigation into suspected unauthorised card, account-to-account, bill-payment or other digital payment activity. Use the actual payment rail and provider documentation; do not assume every rail exposes the same lifecycle states, identifiers or reversal rights.

## 1. Preserve the transaction record

For each transaction, record the authorised case reference and the authoritative values available in the payment/core system:

- Transaction/payment reference and any parent/related reference
- Channel, product, payment rail and provider/acquirer
- Initiation, authorisation, acceptance, posting, settlement, reversal/return timestamps
- Amount, currency, fees and FX conversion (where applicable)
- Debtor/payer account reference and beneficiary/payee reference (masked in reports)
- Status, response/decline codes, reason codes and source system
- Fraud decision reference, rule/model version, score, decision and override
- Authentication method and result, including 3DS where applicable
- Customer dispute/contact record and source of the statement

Do not collapse “authorised”, “posted”, “settled”, “reversed” and “refunded” into a single “successful” state. Confirm the meaning of each status with the system or payment provider.

## 2. Reconstruct the payment flow

Map the real message and service path for the specific rail. A generic card-not-present flow may involve customer channel, merchant, 3DS Server, Directory Server, Access Control Server, acquirer, issuer authorisation host and payment network. A SADAD or other account/bill-payment flow has a different path and must be mapped from the bank/provider's own interface and operational documentation.

For every hop, record request/response IDs, timestamps, system name, status and the original event reference. Confirm which system is authoritative for each state.

## 3. Card-not-present and 3-D Secure evidence

When 3DS is involved, capture only fields actually present in the issuer/acquirer/provider records and interpret them using the applicable EMVCo specification version and integration documentation.

Potentially relevant fields include:
- Protocol version
- `threeDSServerTransID`, `dsTransID`, and `acsTransID` where supplied
- `messageType` and `messageVersion`
- `transStatus` and `transStatusReason`, where present
- `challengeCompletionInd` and challenge-flow evidence, where present
- ECI and authentication value/reference as represented by the network/provider
- Directory Server / ACS result, error and timeout information
- Provider mapping of authentication, authorisation and liability-related outcomes

Protect authentication values and sensitive payment data. Store the minimum necessary evidence in the authorised case system; do not publish full values in PSV.

**Do not assume:** a generic “3DS passed” label means the legitimate account holder initiated the transaction; a frictionless flow means the customer actively approved it; or a liability-shift indicator determines the bank's fraud verdict. Confirm the actual protocol version, result fields, scheme rules and provider semantics.

## 4. Account-to-account, bill-payment and SADAD-style flows

For a non-card payment, identify the rail-specific source of truth and collect:
- Payment initiation request and response references
- Payer authentication and authorisation records
- Beneficiary validation and any beneficiary creation/change event
- Payment provider/SADAD reference and status history, where applicable
- Core banking debit/credit posting and reconciliation records
- Limit checks, fraud decision and rule/model evaluation
- Cancellation, reversal, return, dispute or recovery state
- Customer channel and session linkage

Do not apply EMV 3DS fields to a rail that does not use EMV 3DS. Do not assume a payment can be reversed or blocked after a particular state without checking the applicable rail and operating procedure.

## 5. Fraud-control evaluation

For every relevant decision, reconstruct what the control knew at decision time:

| Question | Evidence |
|---|---|
| Which control evaluated the transaction? | Rule ID, model/version, policy version |
| What input features were available? | Feature snapshot or decision audit record |
| What was the output? | Score, reason code, approve/decline/step-up/review result |
| Was the control operating? | Health/availability, timeout, fallback and bypass logs |
| Was the decision changed? | Override actor, reason, approval and timestamp |
| Was the same pattern seen elsewhere? | Related cases, accounts, devices, beneficiaries and transaction references |
| Was the control calibrated? | Test results, false-positive/false-negative review, change history |

A missing fraud alert does not by itself prove a rule failed. First establish whether the event reached the engine, whether required features were present, whether the rule was enabled and in scope, and whether the decision was logged.

## 6. Cross-system correlation

Correlate payment reference → fraud decision reference → API request/trace ID → authenticated session → authentication event → device/network evidence. Use independent references wherever possible. Record the join key, source and confidence for every link.

If an application session is absent, use the dedicated [ATO playbook](account-takeover-playbook.md#5-when-the-session-is-missing-from-logs) to investigate logging and trace-propagation gaps. Do not fill missing records with assumed values.

## 7. Scope, loss and customer impact

- Identify related transactions and whether the pattern spans customers, channels, products, beneficiaries or institutions.
- Separate attempted, declined, authorised, posted, settled, reversed, returned and recovered amounts.
- Record gross and net loss using the institution's accounting definition; do not add amounts across statuses in a way that double-counts.
- Confirm customer impact and contact status using approved processes.
- Preserve evidence for dispute, scheme, provider, legal and regulatory processes as required.

## 8. Outcome and corrective action

The case conclusion should identify confirmed facts, inference, alternative explanations, confidence, loss status, customer impact, control performance, evidence gaps and unresolved questions.

Potential corrective-action categories include:
- Authentication or account-recovery control
- Device binding/attestation and session management
- API authentication, authorisation and trace propagation
- Fraud-rule/model feature quality, coverage and calibration
- Transaction limits, beneficiary controls and step-up decisions
- Logging, monitoring, evidence retention and case workflow
- Third-party/provider integration and reconciliation

Assign each action an accountable owner, approval, risk rationale, due date, validation evidence and closure criteria. Do not use a generic remediation deadline or severity threshold unless approved by the institution.

## References

- [SAMA Counter-Fraud Framework — 5.2 Fraud Detection Systems](https://rulebook.sama.gov.sa/en/52-fraud-detection-systems)
- [SAMA Counter-Fraud Framework — 6.3 Fraud Investigation](https://rulebook.sama.gov.sa/en/63-fraud-investigation)
- [SAMA Counter-Fraud Fundamental Requirements](https://rulebook.sama.gov.sa/en/counter-fraud-fundamental-requirements) — apply only where entity/activity is in scope.
- [EMVCo 3-D Secure](https://www.emvco.com/emv-technologies/3-d-secure/)
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
