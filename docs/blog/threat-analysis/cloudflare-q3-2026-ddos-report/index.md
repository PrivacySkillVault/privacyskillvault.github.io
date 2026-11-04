# Cloudflare's Q3 2026 DDoS Report: 18.2 Million Network-Layer Attacks in One Quarter

<small>THREAT ANALYSIS · NETWORK SECURITY · 04 NOV 2026 · 8 MIN READ</small>

<p class="psv-article-breadcrumb"><a href="../">← Threat Analysis</a><span> / </span><a href="../../">Cyber Journal</a></p>

Cloudflare's Q3 2026 DDoS Threat Report describes a threat landscape with a striking pattern: many more short, lower-bandwidth attacks, alongside a decline in the largest hyper-volumetric events. The company says it autonomously mitigated **18.2 million network-layer DDoS attacks** and **14.4 trillion HTTP DDoS requests** across its network during July, August and September 2026.

The 18.2 million figure equates to approximately 8,226 network-layer attacks per hour, or 197,400 per day. These are Cloudflare's observed and mitigated events across its own network—not a count of every DDoS attack worldwide.

## More frequent attacks, not only bigger attacks

Cloudflare reports 18.2 million network-layer attacks in Q3, compared with 13.2 million in Q2 (about 38% higher). Its report says short-burst attacks lasting under 10 minutes and below 1 Gbps surged by 208% year over year. Cloudflare also reports that 96% of network-layer attacks ended in under 10 minutes and 98% stayed below 1 Gbps.

That distinction matters for defenders. A DDoS campaign does not need to reach multi-terabit scale to disrupt a smaller application, saturate a limited circuit or exhaust a constrained service. Repeated short attacks can also complicate triage when teams focus only on the largest traffic spikes.

At the other end of the scale, Cloudflare recorded 251 network-layer attacks exceeding 1 Tbps in Q3, down from 805 in Q2. The report discusses law-enforcement disruption of several IoT botnets earlier in the year as a possible factor, while warning that botnet variants continue to emerge.

## Changes in attack techniques

Cloudflare highlights a sharp shift in reflection and amplification activity. It reports that CLDAP attacks fell by 99.5% quarter over quarter, while DNS amplification increased by 215% and general UDP floods rose by 122%. Cloudflare says DNS amplification accounted for 3.43% of network-layer attacks and other UDP floods reached 31.31%.

Reflection and amplification abuse exposed UDP services to spoofed requests that cause larger responses to be sent toward a victim. Defenders should therefore understand which internet-facing services can be abused as reflectors and whether their providers have controls to reduce spoofing and amplification.

The report also notes that the geography and industry mix of targets changed during the quarter. These trends are useful context, but they should not be treated as a prediction that a specific organisation will be targeted next.

## What network defenders should take from the report

| Defensive area | Practical action |
|---|---|
| Baseline traffic | Establish normal packet rates, protocols, ports and traffic patterns by service |
| Short attacks | Retain telemetry at sufficient granularity to investigate bursts lasting only minutes |
| UDP exposure | Review exposed UDP services and disable unnecessary listeners |
| Upstream protection | Confirm ISP, CDN and DDoS-provider escalation paths and mitigation capacity |
| Application resilience | Rate-limit expensive operations and test graceful degradation |
| Incident readiness | Document traffic diversion, scrubbing, communications and evidence-preservation steps |

For SOC analysts, distinguish a volumetric event from an application-layer availability incident. Network packet rates, connection states, load balancer metrics, application latency and error rates answer different questions. Correlate them before assigning a cause.

## Understand the limits of the numbers

Cloudflare's statistics reflect its own global network and mitigation systems. They are valuable at scale, but they are not a universal census of internet attacks. A reported increase in mitigated events may reflect changes in attacker activity, visibility, customer mix or detection and mitigation coverage.

The report's headline count also combines many attacks of different sizes and durations. It should not be read as 18.2 million successful service outages. Mitigated attacks may have been blocked without the protected service becoming unavailable.

## Key takeaway

DDoS readiness should not focus exclusively on record-breaking bandwidth. High-frequency, short-duration attacks can still consume resources and disrupt exposed services. Build granular baselines, reduce unnecessary UDP exposure, validate upstream mitigation and rehearse response procedures before the next traffic spike.

## References

- [Cloudflare — DDoS Threat Report 2026 Q3: More swarms, fewer giants](https://blog.cloudflare.com/ddos-threat-report-2026-q3) — primary report, October 29, 2026.
- [The Hacker News — Cloudflare Reports 18.2 Million Network-Layer DDoS Attacks in Q3, Up 38%](https://thehackernews.com/2026/10/cloudflare-reports-182-million-network.html) — secondary reporting, October 31, 2026.

*PSV analysis based on Cloudflare's Q3 report. Statistics are attributed to Cloudflare's network telemetry and should not be interpreted as a global count of all attacks.*
