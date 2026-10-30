# Security Tools

A browser-based workbench for common SOC and defensive-security tasks.

<div id="psv-workbench-root" aria-live="off">
  <p>Loading the security workbench… If it does not appear, enable JavaScript and reload this page.</p>
</div>

## Privacy and external services

Most parsing, extraction, and transformation features operate in your browser. Threat-intelligence enrichment makes requests to public services, including Shodan InternetDB, RDAP, and Cloudflare DNS. External pivot links may open services such as VirusTotal, AbuseIPDB, or URLScan.

**Do not paste customer information, authentication data, internal logs, confidential indicators, or employer-sensitive material into this public page.** When using enrichment, the queried indicator is sent to the selected third-party service. Review that provider's terms and privacy policy before use.

## Operational limitations

- Tool output is an aid to analysis, not a verdict or automated security decision.
- Sigma-to-query translation is best-effort. Validate field mappings, syntax, and results against your SIEM data before use.
- Detection templates are marked experimental and must be tested and reviewed before operational deployment.
- Results can vary with browser support, input format, data quality, and external service availability.

Use only on data you are authorised to process.
