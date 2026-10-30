# Investigations

Defensive investigation methods and worked examples covering security alerts, endpoint activity, network evidence, and cyber-fraud signals.

## Evidence standard

Every report must distinguish observed evidence from interpretation. Published material is classified as sanitised professional experience, lab investigation, simulated scenario, or research note. No customer records, internal banking details, production IP addresses, or employer-confidential information belong here.

## Worked example: suspicious PowerShell launched by a scheduled task

<badge>SIMULATED TRAINING SCENARIO</badge>

Hostnames, timestamps, commands, and indicators in this example are synthetic. It does not describe a real customer, employer, or production incident.

### Initial alert

A monitoring rule flags encoded PowerShell launched by a scheduled-task process outside an expected maintenance window.

### Investigation questions

1. What process created PowerShell, and what was its full command line?
2. Which account and integrity level were involved?
3. Is the scheduled task known, approved, and correctly owned?
4. Do script-block, process, DNS, proxy, and firewall records corroborate the activity?
5. Is there evidence of payload retrieval, persistence, lateral movement, or impact?

### Evidence to correlate

- Process creation telemetry, including parent process and command line
- PowerShell operational events where logging is enabled
- Scheduled-task registration and execution history
- DNS and network connection records
- File creation, hash, signature, and reputation context
- Change records and owner confirmation

### Example reasoning

An encoded command is a triage signal, not proof of malware. A scheduled task can be legitimate administration or unauthorised persistence. Validate the task definition, executable path, script contents, account, creation time, change history, and network destinations before assigning a verdict.

### Possible outcomes

- **Expected administration:** document the owner and maintenance purpose; tune narrowly with evidence.
- **Policy violation:** remediate the configuration even if malicious intent is not established.
- **Likely compromise:** follow incident-response procedures, preserve evidence, and consider containment under organisational policy.
- **Insufficient evidence:** state what telemetry is missing and what additional collection is required.

Avoid treating one event or one indicator as a complete story. Record confidence, alternative explanations, data gaps, and the basis for every conclusion.
