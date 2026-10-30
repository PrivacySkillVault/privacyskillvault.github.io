# Security Tools

A browser-based workbench for common SOC and defensive-security tasks.

<div id="psv-workbench-root" aria-live="off">
  <p>Loading the security workbench… If it does not appear, enable JavaScript and reload this page.</p>
</div>

## Privacy and external services

Most parsing, extraction, and transformation features process input locally in your browser. The Threat Intel Hub is different: it sends the single indicator you submit to public third-party services only after you select **Enrich Indicator**. IPv4 lookups use Shodan InternetDB and RDAP; domain lookups use RDAP and Cloudflare DNS. Optional links to VirusTotal, AbuseIPDB, URLScan, and Shodan also send the indicator to the selected provider when opened.

The Threat Intel Hub does not make requests while you type. Provider responses may be incomplete, unavailable, or out of date; they are not a verdict that an indicator is malicious or benign.

**Do not paste customer information, authentication data, internal logs, confidential indicators, or employer-sensitive material into this public page.** Public providers may process or retain submitted indicators under their own terms and policies. Review those policies before use.

## Standards and version compatibility

The CVSS calculator currently supports **CVSS v3.1 only**. FIRST publishes CVSS v4.0 as the current specification; do not use this calculator for v4.0 vectors or label its output as v4.0. See the [Industry Standards & Authoritative References](../standards/index.md#first-common-vulnerability-scoring-system-cvss-v40) page for the version distinction. The Sigma utility on this page is a source preview only, not a Sigma parser or converter.

## Operational limitations

- Tool output is an aid to analysis, not a verdict or automated security decision.
- The IOC extractor performs pattern-based extraction. IPv4 syntax is checked, but private/reserved classification and DNS validation are not performed; domain-like strings are not proof of registration or resolution.
- The Event Encyclopedia contains 16 curated records, not a complete Windows or Sysmon event catalogue. Query examples and field names must be checked against your event version and SIEM schema.
- The timestamp converter preserves sub-millisecond input remainders for Unix microsecond/nanosecond and FILETIME formats, but JavaScript Date calendar display is limited to milliseconds.
- The YARA builder performs only a textual reference check; it is not a grammar parser or compiler. Validate rules with the YARA compiler or an approved engine.
- The email header analyser parses supplied text. It does not cryptographically verify DKIM, SPF, or DMARC, nor establish the provenance of Authentication-Results or Received headers.
- The severity calculator is a keyword heuristic with illustrative bands, not an approved incident severity policy, SLA, or containment decision.
- The Sigma page currently displays source YAML only. It does not parse or validate YAML, evaluate Sigma conditions, or generate Elastic, Splunk, or Sentinel queries. Use maintained Sigma tooling for conversion, then validate the result against your SIEM schema and telemetry.
- CVSS scoring accepts CVSS v3.1 vectors, validates required Base metrics and supported metric values, and calculates Base, Temporal, and Environmental scores using the v3.1 equations. Confirm the vector and scoring assumptions before using the result in vulnerability prioritization.
- Detection templates are examples and must be tested and reviewed before operational deployment.
- Results can vary with browser support, input format, data quality, and external service availability.

Use only on data you are authorised to process.
