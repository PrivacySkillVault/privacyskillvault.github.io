# Editorial and Source Standards

The Cyber Journal exists to explain cybersecurity, not to republish other publishers' work. Every article must provide original understanding, context, or defensive analysis.

## Source hierarchy

Use sources in this order where they are available and relevant:

1. **Primary technical sources** — vendor security advisories, CERT/CSIRT advisories, vulnerability records, standards, official incident statements, original research papers, and project documentation.
2. **Authoritative technical references** — OWASP, MITRE ATT&CK, NIST, CISA, FIRST, and maintained vendor documentation.
3. **Reputable reporting and independent research** — useful for discovery, chronology, interviews, and context. Verify material technical claims against primary evidence.
4. **Community discussion and aggregators** — Hacker News, forums, and social platforms are discovery signals, not proof. Follow the original links and verify independently.

A source being well known does not make every claim in it correct or current.

## Required checks before publication

- Confirm the publication date and distinguish it from the date an incident or vulnerability occurred.
- Check whether an advisory has been updated, superseded, or corrected.
- Confirm product names, versions, affected configurations, and stated impact from the original source.
- Do not infer exploitation, attribution, data theft, or customer impact unless a reliable source supports it.
- Distinguish a vulnerability's existence from evidence that it is being exploited in the wild.
- Distinguish a reported incident from a technically confirmed attack chain.
- Link to the original material and identify the source of important claims.
- Avoid unsupported statistics. If a number is used, explain its scope, date, and source.
- If reliable evidence is unavailable, state what is unknown rather than filling the gap with speculation.

## Article labels

Use these labels consistently:

- **Confirmed fact** — directly supported by a cited source or reproducible observation.
- **Analysis** — reasoned interpretation based on the stated evidence.
- **Illustrative scenario** — a hypothetical example used to explain a concept; not a report of a real incident.
- **Lab-tested** — actually tested in a controlled environment, with environment and limitations recorded.
- **Not independently verified** — a claim reported by a source but not corroborated independently.

## Originality and attribution

- Do not copy paragraphs, article structures, distinctive phrasing, or images from another publisher.
- Read the source material, take notes, close the source, and explain the concept in your own structure and language.
- Quote only when the exact wording matters; keep quotations short, use quotation marks, and link to the source.
- Attribute reporting and research clearly. A list of links does not replace attribution in the relevant paragraph.
- Create original diagrams and examples. Label simulated data and hypothetical workflows.
- Do not reproduce copyrighted screenshots, charts, or photographs without permission or an applicable licence.

## Cyber-fraud and banking confidentiality

Never publish customer identifiers, account details, payment references, internal IP addresses, internal hostnames, API endpoints, fraud rules, detection thresholds, proprietary device identifiers, session tokens, or non-public incident information.

Use fictional data for examples. Generalise workplace experience and obtain appropriate approval before publishing anything derived from professional work. Do not imply that a hypothetical sequence describes a specific bank or real case.

## Article structure

A typical explainer should answer:

1. What happened or what concept are we examining?
2. What is confirmed, and what remains unknown?
3. How does the technology or attack concept work?
4. What evidence could a defender reasonably expect to see?
5. How should a SOC or fraud team investigate?
6. What controls reduce risk, and what are their limitations?
7. What are the key lessons?
8. Which primary sources support the explanation?

Not every article needs every section. Do not invent detail merely to fill a template.

## Corrections and updates

Each article should show its original publication date. If a material correction is needed, add a short correction note describing what changed and why. Update technical guidance when source documentation changes; do not silently make a significant factual change.

## Discovery sources

Hacker News and security news outlets can be useful for discovering subjects. They are not the final authority for technical claims. For technical verification, consult sources such as:

- [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [The DFIR Report](https://thedfirreport.com/)
- [Cisco Talos Intelligence](https://talosintelligence.com/)
- [Google Project Zero](https://googleprojectzero.blogspot.com/)

This list is a starting point, not an endorsement of every claim or an exhaustive source list.
