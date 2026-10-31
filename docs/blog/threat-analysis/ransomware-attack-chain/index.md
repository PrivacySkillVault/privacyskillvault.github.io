# A Ransomware Attack, Step by Step: What Happens Before Files Are Encrypted?

<small>THREAT ANALYSIS · ATTACK-LIFECYCLE EXPLAINER · 01 NOV 2026</small>

<p class="psv-article-breadcrumb"><a href="../">← Threat Analysis</a><span> / </span><a href="../../">Cyber Journal</a></p>

Ransomware is often described as malware that encrypts files and demands payment. That describes the visible impact, but it misses much of the intrusion. In many incidents, attackers first gain access, explore the environment, obtain higher privileges, disable or evade controls, locate valuable data, and only then deploy encryption or other destructive actions.

Not every ransomware incident follows the same sequence. Some attacks are fast and automated; others involve extended hands-on activity. The stages below are a useful defensive model, not a universal checklist.

## 1. Initial access

An attacker needs a way into the environment. Common routes include stolen credentials, exposed remote services, phishing, vulnerable internet-facing applications, and access through a compromised supplier.

**Defender focus:** monitor remote access, identity-provider events, exposed services, unusual authentication patterns, and vulnerability exposure. Prioritise MFA and secure configuration for remote administration.

## 2. Execution and foothold

After access, an attacker may execute commands or deploy tools. The first process or file is not always obviously malicious. Legitimate administrative utilities can be abused, which is why process lineage, command-line context, user identity, and host role matter.

**Defender focus:** collect endpoint process telemetry, application control events, script logs, and security-product alerts. Compare activity with the host's normal administrative baseline.

## 3. Discovery and privilege escalation

An intruder may enumerate users, groups, systems, network shares, security products, and backup infrastructure. They may attempt to obtain stronger privileges or reuse credentials found elsewhere.

**Defender focus:** look for unusual directory queries, administrative group changes, access to credential stores, remote service use, and unexpected account activity. Validate whether the activity matches approved administration.

## 4. Lateral movement

The attacker may move from the first compromised system to file servers, identity systems, management hosts, or other endpoints. A single infected workstation does not automatically mean the whole network is compromised—but shared credentials and broad administrative privileges can increase the blast radius.

**Defender focus:** correlate source and destination hosts, account logons, remote service creation, SMB/RDP/WinRM use, and unusual authentication paths. Review segmentation and privileged access.

## 5. Data collection and possible exfiltration

Some ransomware operations also steal data and threaten to publish it. Encryption and data theft are separate activities: evidence of one does not automatically prove the other.

**Defender focus:** examine unusual archive creation, large outbound transfers, cloud-storage access, DNS and proxy activity, and endpoint file-access patterns. Establish what data left the environment before making a disclosure claim.

## 6. Impact and recovery disruption

Attackers may encrypt systems, delete shadow copies, disrupt backup services, or interfere with security tooling. Some incidents involve data destruction rather than recoverable encryption.

**Defender focus:** alert on mass file modifications, unexpected service stops, backup configuration changes, recovery-point deletion, and security-control tampering. Ensure backups are isolated and restoration is tested.

## A simple detection timeline

| Stage | Useful telemetry | Investigation question |
|---|---|---|
| Initial access | Identity, VPN, email, web gateway | Which access path was used? |
| Execution | EDR, process creation, script logs | What ran, under which account, and from where? |
| Discovery | Endpoint and directory audit | What was enumerated and was it expected? |
| Lateral movement | Authentication, network, remote service logs | Which systems and accounts were involved? |
| Collection/exfiltration | File access, proxy, DNS, cloud audit | Was sensitive data accessed or transferred? |
| Impact | File activity, backup, service, EDR | What was changed, encrypted, or disabled? |

## What should a SOC do when ransomware is suspected?

1. Validate the alert and determine the affected host, user, and time window.
2. Follow the organisation's incident-response authority and escalation process.
3. Isolate affected systems using approved procedures, considering business and safety impact.
4. Preserve relevant endpoint, identity, network, and cloud evidence.
5. Identify potentially compromised credentials and privileged accounts.
6. Scope lateral movement and possible data access or exfiltration.
7. Protect backups and recovery infrastructure.
8. Coordinate containment, eradication, legal, privacy, communications, and recovery teams.

Do not rush to wipe or rebuild a system before evidence preservation and scope decisions are made, unless immediate containment requirements dictate otherwise.

## Important distinctions

- A ransomware note does not prove all files were encrypted.
- A file-encryption alert does not prove data was exfiltrated.
- A public proof-of-concept is not evidence that a particular organisation was exploited.
- A ransom demand is not proof that paying will restore systems or prevent disclosure.

## Key takeaways

Ransomware defence is about detecting and disrupting the intrusion before impact. Identity, endpoint, network, backup, and cloud telemetry must work together. Incident response should be rehearsed before an incident, not improvised during one.

## References

- [NIST IR 8374 Rev. 1 — Ransomware Risk Management (2026)](https://csrc.nist.gov/pubs/ir/8374/r1/final)
- [NIST SP 800-61 Rev. 3 — Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [CISA StopRansomware](https://www.cisa.gov/stopransomware)
- [MITRE ATT&CK](https://attack.mitre.org/)

*This article describes common defensive concepts. It is not a report of a specific ransomware campaign.*