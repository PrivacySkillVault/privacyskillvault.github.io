# Security Tools

A browser-based workbench for common SOC and defensive-security tasks.

<div id="psv-workbench-root" aria-live="off">
  <p>Loading the security workbench… If it does not appear, enable JavaScript and reload this page.</p>
</div>

## Privacy and external services

Most parsing, extraction, and transformation features process input locally in your browser. The Threat Intel Hub is different: it sends the single indicator you submit to public third-party services only after you select **Enrich Indicator**. IPv4 lookups use Shodan InternetDB and RDAP; domain lookups use RDAP and Cloudflare DNS. Optional links to VirusTotal, AbuseIPDB, URLScan, and Shodan also send the indicator to the selected provider when opened.

The Threat Intel Hub does not make requests while you type. Provider responses may be incomplete, unavailable, or out of date; they are not a verdict that an indicator is malicious or benign.

**Do not paste customer information, authentication data, internal logs, confidential indicators, or employer-sensitive material into this public page.** Public providers may process or retain submitted indicators under their own terms and policies. Review those policies before use.

## Operational limitations

- Tool output is an aid to analysis, not a verdict or automated security decision.
- The Sigma page currently displays source YAML only. It does not parse or validate YAML, evaluate Sigma conditions, or generate Elastic, Splunk, or Sentinel queries. Use maintained Sigma tooling for conversion, then validate the result against your SIEM schema and telemetry.
- CVSS scoring accepts CVSS v3.1 vectors, validates required Base metrics and supported metric values, and calculates Base, Temporal, and Environmental scores using the v3.1 equations. Confirm the vector and scoring assumptions before using the result in vulnerability prioritization.
- Detection templates are examples and must be tested and reviewed before operational deployment.
- Results can vary with browser support, input format, data quality, and external service availability.

Use only on data you are authorised to process.
