# Security Investigation Workbench

A local-first analyst workspace for SOC triage, threat intelligence pivots, incident response, DFIR, detection engineering, vulnerability analysis and authorised security testing.

<div id="psv-workbench-root" aria-live="off">
  <p>Loading the security investigation workbench… Enable JavaScript and reload if it does not appear.</p>
</div>

## Investigation workflow

The workbench provides three additional local workflows:

- **Incident case workspace:** assemble a case summary, affected assets, detection source, actions, evidence references and UTC timeline; export a Markdown report. The browser does not persist cases or replace an approved case-management platform.
- **Evidence integrity checker:** calculate SHA-256 for a selected local file (up to 100 MB) and download a basic integrity record. Hashes support integrity comparisons; they do not establish provenance, authenticity or chain of custody.
- **Encrypted evidence sharing:** encrypt text or files up to 25 MB locally using AES-256-GCM with a PBKDF2-SHA-256-derived key (310,000 iterations), random salt and IV. The encrypted package is downloaded. The recipient decrypts it in this page using the separately shared passphrase. There is no password recovery or server-side storage.

**Secure-sharing warning:** this is a client-side encryption helper, not a managed secure file-transfer service or evidence vault. Use a unique strong passphrase, transmit it over a separate approved channel, and follow your organisation's classification, retention and transfer rules. Keep plaintext and passphrases out of email/chat alongside the package. Do not use this tool for regulated or highly sensitive evidence unless your organisation explicitly approves the workflow.

## Privacy and external services

Most parsers, extractors, formatters, report builders, hashing and encryption features process input locally in your browser. The Threat Intel Hub is different: it sends the single indicator you submit to public third-party services only after you select **Enrich Indicator**. IPv4 lookups use Shodan InternetDB and RDAP; domain lookups use RDAP and Cloudflare DNS. Optional VirusTotal, AbuseIPDB, URLScan and Shodan pivots send the selected indicator to the chosen provider when opened.

The Threat Intel Hub makes no requests while you type. Provider responses may be incomplete, unavailable or out of date; they are not a verdict that an indicator is malicious or benign. Public providers may process or retain submitted indicators under their own terms and policies.

**Never paste customer information, authentication data, internal logs, confidential indicators, regulated data or employer-sensitive material into this public page.** The page does not send your case workspace, evidence file or plaintext to PSV, but external threat-intelligence lookups disclose the indicator to the selected provider.

## Tool coverage

The interactive workbench includes:

- **SOC & detection:** Windows/Sysmon event reference, log regex extraction, Sigma source preview, JSON log formatting and flattening.
- **Threat intelligence:** IOC extraction and defanging, public IP/domain enrichment, CVE and hash extraction.
- **DFIR & incident response:** incident case builder, evidence SHA-256, encrypted package creation/decryption, safe PowerShell/Base64/Hex/URL decoding, incident report generation.
- **Network, email & vulnerability:** email-header text analysis and CVSS v3.1 scoring.
- **Incident utilities:** timestamp conversion and illustrative triage heuristic.

The page also provides a reference list of tools intended to run in your own lab or approved environment, including Elastic Security, Splunk, Wazuh, Sigma CLI, Wireshark, Zeek, Suricata, Velociraptor, KAPE, Autopsy, Volatility 3, Plaso, Hayabusa, MISP, OpenCTI, YARA, capa, Ghidra, REMnux, FLARE-VM, Nmap, Nuclei, Burp Suite, OWASP ZAP, Metasploit, sqlmap, ffuf and testssl.sh. These are not embedded in the browser workbench; they require separate installation, configuration and authorisation.

## Standards and compatibility

The CVSS calculator supports **CVSS v3.1 only**. Do not use it for v4.0 vectors. See [Industry Standards & Authoritative References](../standards/index.md#first-common-vulnerability-scoring-system-cvss-v40) for the version distinction. The Sigma utility is a source preview only, not a standards-compliant parser or converter.

## Operational limitations

- Tool output assists analysis; it is not a verdict, automated security decision, containment instruction or replacement for a qualified analyst.
- IOC extraction is pattern-based. IPv4 syntax validation is not reputation checking; domain-like strings are not proof of registration or DNS resolution.
- The Event Encyclopedia contains 16 curated Windows Security and Sysmon records, not a complete event catalogue. Confirm event IDs, fields and query syntax against your Windows/Sysmon version and SIEM schema.
- The timestamp converter preserves sub-millisecond input remainders for Unix microsecond/nanosecond and FILETIME formats, but JavaScript Date calendar display is limited to milliseconds.
- The YARA builder performs a textual reference check only; it is not a grammar parser or compiler. Validate rules using the YARA compiler or an approved engine.
- The email-header analyser parses supplied text. It does not cryptographically verify DKIM, SPF or DMARC, or establish the provenance of Authentication-Results or Received headers.
- The severity calculator is a keyword heuristic with illustrative bands, not an approved severity policy, SLA or containment decision.
- The Sigma utility displays source YAML only. It does not parse or validate YAML, evaluate Sigma conditions or generate Elastic, Splunk or Sentinel queries.
- CVSS v3.1 scoring validates supported metrics and calculates Base, Temporal and Environmental scores. Confirm vector assumptions before using the score for prioritisation.
- The evidence hash is calculated with Web Crypto and limited to files up to 100 MB in this browser tool. Use validated forensic acquisition tools for disk images, memory captures and large evidence.
- Secure sharing uses browser cryptography, but the browser/device remains part of the trusted computing base. No independent security audit or penetration test of this helper is claimed. Validate the encrypted package and transfer workflow before operational use.
- Detection examples are starting points. Test, tune, document false positives and review before production deployment.

Use only on systems and data you are authorised to examine.
