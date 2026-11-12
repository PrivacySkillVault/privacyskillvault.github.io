/* Privacy Skill Vault — Production SOC Workbench (Capture-Phase Event Engine) */
(function () {
  "use strict";

  const CATEGORIES = [
    { id: "all", label: "All Tools" },
    { id: "soc", label: "SOC & Detection" },
    { id: "ti", label: "Threat Intelligence" },
    { id: "dfir", label: "DFIR & Forensics" },
    { id: "network", label: "Network & Email" },
    { id: "util", label: "Incident & Utilities" },
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
      desc: "Extract syntactically valid IPv4 values, domains, URLs, email addresses, CVEs, and MD5/SHA-1/SHA-256 hash candidates from text; optionally defang indicators.",
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
      desc: "Enrich public IPs, domains, file hashes and CVEs through server-side AbuseIPDB, AlienVault OTX, NVD, urlscan.io, VirusTotal and Hybrid Analysis lookups.",
      options: ["Sample IP (1.1.1.1)", "Sample IP (8.8.8.8)", "Sample Domain (cloudflare.com)"],
      actionLabel: "Enrich Indicator",
      sample: "1.1.1.1",
      whatItDoes: "Queries configured AbuseIPDB, AlienVault OTX, NVD and urlscan.io, plus read-only VirusTotal reports and Hybrid Analysis hash reports where supported. Provider responses are normalized for investigation review.",
      whyItMatters: "Combining selected public-provider responses can speed up initial indicator triage. Treat the results as supporting context and corroborate them with authoritative telemetry and additional sources.",
      howItWorks: "After you explicitly select Enrich Indicator, the browser sends one validated indicator to the PSV API. Provider credentials remain on the server; each configured provider is queried independently, and provider failures are isolated. No lookup runs while you type.",
      bestPractices: [
        "Check open ports and CVEs on external IPs before escalating perimeter scan alerts.",
        "RDAP output is limited to fields returned by the registry; this view does not calculate domain age or establish ownership.",
        "Correlate provider findings with bank-approved telemetry and internal SIEM/EDR evidence; do not treat reputation scores as proof of compromise."
      ],
      faqs: [
        { q: "Are provider API keys exposed to my browser?", a: "No. All provider credentials are held as server-side Vercel environment variables. The browser sends only the selected indicator to the PSV API." }
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
      whatItDoes: "Parses supplied header fields and Received lines, extracts sender-address differences, and displays SPF, DKIM, and DMARC results as reported in supplied Authentication-Results text.",
      whyItMatters: "Display names and From headers can be spoofed. Header clues must be checked against the trusted receiving gateway boundary and corroborated with mail-server and network telemetry; no single supplied header proves attribution.",
      howItWorks: "Parses supplied header text and displays Received lines in reverse order. It does not verify DKIM signatures, authenticate Authentication-Results provenance, or prove Received-line trustworthiness.",
      bestPractices: [
        "Treat Authentication-Results as untrusted until you validate the header added by your own receiving gateway; pasted text alone cannot establish provenance.",
        "Look for mismatches between the header From domain, the Return-Path (Envelope Sender), and the Reply-To address."
      ],
      faqs: [
        { q: "Does this tool verify DKIM or trust Authentication-Results?", a: "No. It parses text only; it does not verify DKIM signatures or establish which mail server added Authentication-Results." }
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
      whatItDoes: "Provides 16 curated Windows Security and Sysmon event records with selected event fields, LogonTypes where relevant, MITRE ATT&CK references, and example Elastic KQL hunting queries. It is not a complete event catalogue.",
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
      title: "Forensic Timestamp Converter (UTC & Local)",
      desc: "Convert Unix Epoch seconds, milliseconds, microseconds and nanoseconds, 18-digit Windows FILETIME values, and parseable date strings. Calendar display is millisecond-precision.",
      options: ["Sample Epoch (Seconds)", "Sample Windows AD FileTime (18-Digit)", "Use Current Live UTC Time"],
      actionLabel: "Convert Timestamp",
      sample: "1760713462",
      whatItDoes: "Converts 10-digit Unix seconds, 13-digit milliseconds, 16-digit microseconds, 19-digit nanoseconds, 18-digit Windows FILETIME values, and parseable date strings.",
      whyItMatters: "During incident timeline reconstruction, firewall logs may be in UTC Epoch, Active Directory attributes (lastLogonTimestamp) in 18-digit FileTime, and endpoint logs in local time.",
      howItWorks: "Recognises 10-digit seconds, 13-digit milliseconds, 16-digit microseconds, 19-digit nanoseconds, 18-digit Windows FILETIME ticks, and browser-parseable date strings. BigInt preserves sub-millisecond remainders; JavaScript Date display remains millisecond precision.",
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
      shortTitle: "Triage Heuristic",
      title: "Incident Triage Heuristic (Illustrative)",
      desc: "Apply a keyword-based triage heuristic to produce an illustrative score and example priority bands. It is not an approved severity policy, SLA, or containment decision.",
      options: ["Scenario: P1 Domain Controller Intrusion", "Scenario: P4 Isolated Workstation Alert"],
      actionLabel: "Estimate Triage Priority",
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
    },
    {
      id: "case",
      cat: "dfir",
      badge: "CASE",
      shortTitle: "Incident Case Workspace",
      title: "SOC Incident Case Workspace",
      desc: "Create a structured incident record, track scope and response actions, build a UTC timeline, and export a Markdown case report locally.",
      options: [],
      actionLabel: "Build Incident Case",
      sample: "",
      whatItDoes: "Creates a local working incident record with case metadata, affected assets, evidence references, timeline and response actions.",
      whyItMatters: "Consistent case notes improve handovers, auditability and incident coordination.",
      howItWorks: "The workspace formats your entries in the browser and exports a Markdown file. It does not save cases to a PSV server or replace an approved case-management system.",
      bestPractices: ["Use UTC for all event times and retain original source timestamps.", "Record evidence provenance, collector, acquisition time and cryptographic hashes.", "Keep personal data and regulated evidence in approved enterprise systems."],
      faqs: [{q:"Is this a case-management backend?",a:"No. It is a local report builder. Download the report and store it in your approved case repository."}],
      related: ["report","timestamp","ioc"]
    },
    {
      id: "share",
      cat: "dfir",
      badge: "LOCK",
      shortTitle: "Secure Evidence Share",
      title: "Encrypted Evidence Sharing",
      desc: "Encrypt text or small evidence files in your browser using AES-256-GCM with a PBKDF2-derived key. Download an encrypted package to share separately.",
      options: [],
      actionLabel: "Encrypt Package",
      sample: "",
      whatItDoes: "Encrypts supplied text or a file locally with AES-256-GCM and a passphrase-derived key. Decryption is performed in the browser using the passphrase.",
      whyItMatters: "Evidence and incident details should not be sent as plain text or uploaded to public file-sharing services.",
      howItWorks: "Uses Web Crypto PBKDF2-SHA-256 (310,000 iterations) to derive an AES-256-GCM key, a random 16-byte salt and 12-byte IV. The encrypted package is downloaded; PSV does not receive the content.",
      bestPractices: ["Use a unique passphrase of at least 14 characters and share it through a separate approved channel.", "Do not send the passphrase in the same email or message as the encrypted package.", "Follow organisational evidence retention, classification and approved transfer policies; this browser tool is not a substitute for managed secure transfer."],
      faqs: [{q:"Does PSV store or transmit the evidence?",a:"No upload endpoint is used by this feature. Encryption and decryption run in your browser; the encrypted package is downloaded to your device."},{q:"Can I recover a lost passphrase?",a:"No. There is no password reset or recovery mechanism. A lost passphrase means the package cannot be decrypted."}],
      related: ["case","report"]
    },
    {
      id: "secure-transfer",
      cat: "dfir",
      badge: "P2P",
      shortTitle: "Secure Share (Live Transfer)",
      title: "Secure Share — Direct Browser Transfer",
      desc: "Transfer an encrypted note or evidence file directly between two browsers using a one-time, sender-approved WebRTC session.",
      options: [],
      actionLabel: "Open Secure Share",
      sample: "",
      whatItDoes: "Opens a separate browser-to-browser transfer tool. The sender creates a one-time link, approves the recipient, and sends an AES-256-GCM encrypted payload over a WebRTC data channel.",
      whyItMatters: "Provides a controlled way to transfer small evidence files without uploading the plaintext file to PSV storage. It is distinct from the existing passphrase-based Secure Evidence Share utility.",
      howItWorks: "A random AES-256-GCM key is generated in the sender's browser. The encrypted payload travels over a WebRTC data channel; PeerJS is used only for connection signalling. The sender must remain online and approve the recipient. Network restrictions may prevent a direct peer connection.",
      bestPractices: ["Share the one-time link only with the intended recipient; it contains the decryption key in its URL fragment.", "Verify the recipient out of band before approving the connection.", "Do not use this prototype for regulated or high-sensitivity evidence until your organisation approves the transfer path and browser-to-browser tests pass.", "Keep an independent original and record SHA-256 hashes before and after transfer."],
      faqs: [{q:"Is this the same as Secure Evidence Share?",a:"No. Secure Evidence Share encrypts/decrypts a package using a passphrase. This is a separate live browser-to-browser transfer feature."},{q:"Does it work when the sender is offline?",a:"No. The sender must keep the page open until the recipient completes the transfer."}],
      related: ["share","evidence","case"]
    },
    {
      id: "evidence",
      cat: "dfir",
      badge: "SHA",
      shortTitle: "Evidence Integrity",
      title: "Evidence SHA-256 Integrity Checker",
      desc: "Calculate a SHA-256 digest for a selected local file and export a simple integrity record without uploading the file.",
      options: [],
      actionLabel: "Calculate SHA-256",
      sample: "",
      whatItDoes: "Calculates a SHA-256 digest of a file selected from your device and creates a basic evidence integrity record.",
      whyItMatters: "Cryptographic hashes help demonstrate that a collected file has not changed between documented checkpoints.",
      howItWorks: "Reads the selected file in browser memory and uses the Web Crypto SHA-256 digest API. The file is not uploaded.",
      bestPractices: ["Hash the original evidence as early as practical and record acquisition method, time, collector and source.", "A matching hash supports integrity comparison but does not prove authenticity, lawful acquisition or chain of custody.", "For large forensic images, use validated forensic tooling and write blockers rather than a browser page."],
      faqs: [{q:"Does a hash prove evidence is genuine?",a:"No. A hash detects changes relative to a known digest; it does not establish provenance or authenticity."}],
      related: ["case","share","timestamp"]
    }
    ,{
      id: "spl",
      cat: "soc",
      badge: "SPL",
      shortTitle: "Splunk SPL Builder",
      title: "Splunk SPL Query Builder",
      desc: "Generate editable SPL from a structured, analyst-controlled query specification. Validate field names and index/sourcetype against your environment before running.",
      options: ["Failed logons by source IP", "Successful logons after failures", "Process execution search", "Network connection search"],
      actionLabel: "Generate SPL Query",
      sample: "index=wineventlog sourcetype=WinEventLog:Security EventCode=4625",
      whatItDoes: "Builds common Splunk Search Processing Language (SPL) hunting queries from selected use cases and editable environment fields.",
      whyItMatters: "Reusable query patterns reduce repetitive query authoring during triage. Generated SPL is a starting point and must be adapted to the local CIM, indexes, sourcetypes and field extractions.",
      howItWorks: "Uses local templates and escaped field/value inputs. It does not connect to Splunk, execute searches, or validate the query against your deployment.",
      bestPractices: ["Confirm index and sourcetype names in your Splunk environment.", "Use the narrowest practical time range and add exclusions only after validating expected behaviour.", "Test query performance and results on representative data before operational use."],
      faqs: [{q:"Does this execute searches in Splunk?",a:"No. It generates query text locally. Copy it into an authorised Splunk search environment and validate the results."}],
      related: ["events","regex","ioc"]
    },
    {
      id: "parser",
      cat: "soc",
      badge: "LOG",
      shortTitle: "Log Parser & Normaliser",
      title: "SOC Log Parser & Normaliser",
      desc: "Parse JSON, CSV and common key=value log lines locally, inspect extracted fields and normalise records for investigation.",
      options: ["JSON", "CSV", "Key = Value"],
      actionLabel: "Parse Log Data",
      sample: "{\"timestamp\":\"2026-11-01T10:15:00Z\",\"src_ip\":\"203.0.113.10\",\"event_id\":4625,\"user\":\"analyst\"}",
      whatItDoes: "Parses JSON arrays/objects, CSV with a header row, and simple key=value records in the browser.",
      whyItMatters: "Analysts often receive logs in inconsistent formats. Quick field extraction helps identify useful pivots before building SIEM searches.",
      howItWorks: "Uses the browser JSON parser, a quoted CSV state machine, or key=value tokenisation. Parsing is local and does not upload data.",
      bestPractices: ["Preserve the original evidence and work on a copy.", "Check delimiters, quoted values, multiline fields and timezone assumptions.", "This is a convenience parser, not a replacement for production ingestion pipelines or schema validation."],
      faqs: [{q:"Does it support every vendor log format?",a:"No. It supports JSON, basic header-based CSV and simple key=value lines. Use a dedicated parser for CEF, LEEF, W3C, XML or vendor-specific formats."}],
      related: ["regex","json","timestamp","ioc"]
    }
    ,{
      id: "device",
      cat: "soc",
      badge: "DEVICE",
      shortTitle: "Device Intelligence",
      title: "Device Intelligence & Fingerprinting Workbench",
      desc: "Collect consent-based browser characteristics, parse User-Agent and Client Hints, inspect supplied session telemetry, and compare device profiles locally.",
      options: ["Live browser collection", "User-Agent / JSON analysis", "Compare two profiles"],
      actionLabel: "Analyze Device Evidence",
      sample: "",
      whatItDoes: "Collects browser-exposed characteristics and analyses analyst-supplied User-Agent, Client Hints and session records. Supports local profile comparison.",
      whyItMatters: "Device-ID reuse, session takeover and inconsistent client telemetry can be important fraud-investigation pivots.",
      howItWorks: "Uses browser APIs and local parsing only. It does not claim hardware identity or upload collected telemetry.",
      bestPractices: ["Treat browser values as untrusted, client-reported evidence.", "Correlate with server-side device registration, authentication, IP, TLS and native-app attestation records.", "Do not treat a profile mismatch as proof of device cloning."],
      faqs: [{q:"Can this read IMEI, MAC address or serial number?",a:"No. Ordinary web pages cannot reliably access those hardware identifiers."}],
      related: ["parser","headers","case"]
    }  ];

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
  const userInputs = {};
  let lastHashRecord = null;

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
    // Never replace MkDocs' entire article as a fallback. The dedicated mount
    // point is the only safe place for this application to render.
    return document.getElementById("psv-workbench-root");
  }

  function injectStyles() {
    if (document.getElementById("psv-hiderox-royal-css")) return;
    const style = document.createElement("style");
    style.id = "psv-hiderox-royal-css";
    style.textContent = `
      /* Centered analyst workspace with a persistent right-side navigator. */
      #psv-app .psv-vault-layout{display:grid;grid-template-columns:minmax(0,1fr) 270px;gap:1.5rem;align-items:start}
      #psv-app .psv-vault-main{grid-column:1;grid-row:1;min-width:0}
      #psv-app .psv-vault-sidebar{grid-column:2;grid-row:1;position:sticky;top:1.25rem;max-height:calc(100vh - 2.5rem);overflow:auto;padding:.8rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:9px;background:var(--md-code-bg-color)}
      #psv-app .psv-vault-category{padding:.58rem .5rem}
      #psv-app .psv-vault-category small{display:none}
      #psv-app .psv-tool-workspace-layout{display:grid;grid-template-columns:minmax(0,1fr) 245px;gap:1.5rem;align-items:start}
      #psv-app .psv-tool-workspace-main{min-width:0;grid-column:1;grid-row:1}
      #psv-app .psv-tool-sidebar{position:sticky;top:1.25rem;grid-column:2;grid-row:1;max-height:calc(100vh - 2.5rem);overflow:auto;padding:.8rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:9px;background:var(--md-code-bg-color)}
      #psv-app .psv-sidebar-back{width:100%;margin-top:.8rem;padding:.6rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:6px;background:transparent;color:var(--md-default-fg-color);text-align:left;cursor:pointer}
      #psv-app .psv-tool-page{min-width:0}
      #psv-app .psv-tool-directory{display:flex;flex-direction:column;border-top:1px solid var(--md-default-fg-color--lightest)}
      #psv-app .psv-directory-row{display:flex;align-items:center;gap:.9rem;padding:.9rem .65rem;border-bottom:1px solid var(--md-default-fg-color--lightest);color:var(--md-default-fg-color);text-decoration:none;transition:background .15s ease}
      #psv-app .psv-directory-row:hover{background:var(--md-code-bg-color)}
      #psv-app .psv-directory-badge{display:grid;place-items:center;flex:0 0 42px;height:38px;border:1px solid var(--md-default-fg-color--lightest);border-radius:6px;font:700 .68rem "Roboto Mono",monospace;color:var(--md-accent-fg-color)}
      #psv-app .psv-directory-copy{display:flex;flex:1;min-width:0;flex-direction:column;gap:.2rem}
      #psv-app .psv-directory-copy strong{font-size:.84rem}
      #psv-app .psv-directory-copy small{color:var(--md-default-fg-color--light);font-size:.72rem;line-height:1.45}
      #psv-app .psv-directory-open{white-space:nowrap;color:var(--md-accent-fg-color);font-size:.72rem;font-weight:650}
      @media(max-width:600px){#psv-app .psv-directory-row{align-items:flex-start;gap:.55rem;padding:.8rem .25rem}#psv-app .psv-directory-open{font-size:0;align-self:center}#psv-app .psv-directory-open span{font-size:1rem}#psv-app .psv-directory-copy small{font-size:.68rem}}
      /* Vault-style directory layout, aligned with the shared PSV Material theme. */
      #psv-app .psv-tools-intro{margin:0 0 1.6rem;padding:0 0 1.2rem;border-bottom:1px solid var(--md-default-fg-color--lightest)}
      #psv-app .psv-tools-intro h1{margin:.25rem 0 .6rem;font-size:2rem;font-weight:700;letter-spacing:-.02em;color:var(--md-default-fg-color)}
      #psv-app .psv-tools-intro>p{max-width:900px;color:var(--md-default-fg-color--light);font-size:.92rem;line-height:1.7}
      #psv-app .psv-tools-trust{display:flex;flex-wrap:wrap;gap:.5rem 1.2rem;margin:.9rem 0;color:var(--md-default-fg-color--light);font-size:.76rem;font-weight:600}
      #psv-app .psv-tools-trust span:first-child{color:var(--md-default-fg-color)}
      #psv-app .psv-tools-note{margin:.8rem 0 0;padding:.75rem .9rem;border-left:3px solid var(--md-accent-fg-color);background:var(--md-code-bg-color);font-size:.78rem}
      #psv-app .psv-vault-layout{display:grid;grid-template-columns:minmax(0,1fr) 245px;gap:1.5rem;align-items:start}
      #psv-app .psv-vault-sidebar,#psv-app .psv-tool-sidebar{position:sticky;top:1.25rem;max-height:calc(100vh - 2.5rem);overflow:auto;padding:.9rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:10px;background:var(--md-code-bg-color)}
      #psv-app .psv-vault-category{display:flex;align-items:center;justify-content:space-between;gap:.5rem;width:100%;padding:.65rem .55rem;border:0;border-radius:7px;background:transparent;color:var(--md-default-fg-color);text-align:left;cursor:pointer}
      #psv-app .psv-vault-category:hover{background:var(--md-default-bg-color)}
      #psv-app .psv-vault-category.active{background:var(--md-default-bg-color);box-shadow:inset 3px 0 var(--md-accent-fg-color)}
      #psv-app .psv-vault-category strong,#psv-app .psv-vault-category small{display:block}
      #psv-app .psv-vault-category strong{font-size:.8rem;font-weight:650}
      #psv-app .psv-vault-category small{margin-top:.12rem;color:var(--md-default-fg-color--light);font-size:.67rem;line-height:1.4}
      #psv-app .psv-vault-sidebar-note{margin-top:.8rem;padding:.75rem;border-top:1px solid var(--md-default-fg-color--lightest);font-size:.74rem}
      #psv-app .psv-vault-sidebar-note p{margin:.35rem 0 0;color:var(--md-default-fg-color--light);line-height:1.55}
      #psv-app .psv-vault-main{min-width:0}
      #psv-app .psv-vault-main-head{display:flex;justify-content:space-between;align-items:end;margin:.1rem 0 .7rem}
      #psv-app .psv-vault-main-head h2{margin:.15rem 0;font-size:1.35rem;border:0;padding:0}
      #psv-app .psv-vault-main-head p{margin:0;color:var(--md-default-fg-color--light);font-size:.76rem}
      #psv-app .psv-vault-search-label{display:block;margin:.7rem 0 .35rem;font-size:.75rem;font-weight:650}
      #psv-app .psv-vault-search-wrap{position:relative}
      #psv-app .psv-vault-search-wrap>span{position:absolute;left:.85rem;top:.48rem;color:var(--md-default-fg-color--light);font-size:1.2rem}
      #psv-app .psv-vault-search-wrap .psv-search-bar{margin:0 0 1rem;padding:.72rem .9rem .72rem 2.25rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:8px;background:var(--md-default-bg-color);color:var(--md-default-fg-color);font:inherit}
      #psv-app .psv-cards-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem}
      #psv-app .psv-tool-card-v2{min-height:180px;padding:1rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:9px;background:var(--md-code-bg-color);text-decoration:none;color:var(--md-default-fg-color);transition:border-color .15s ease,transform .15s ease}
      #psv-app .psv-tool-card-v2:hover{border-color:var(--md-accent-fg-color);transform:translateY(-2px)}
      #psv-app .psv-tool-card-v2:focus-visible{outline:3px solid var(--md-accent-fg-color);outline-offset:3px}
      #psv-app .psv-tool-card-v2 .psv-card-title{font-size:.95rem;line-height:1.4}
      #psv-app .psv-tool-card-v2 .psv-card-desc{font:inherit}
      #psv-app .psv-tool-card-v2 .psv-card-cat-lbl{font-size:.62rem}
      #psv-app .psv-tool-card-v2 .psv-card-foot{display:flex;align-items:center;justify-content:space-between;gap:.5rem;margin-top:auto}
      #psv-app .psv-tool-card-v2 .psv-client-tag{font-size:.65rem}
      #psv-app .psv-tool-card-v2 .psv-open-link{font-size:.74rem;font-weight:700;white-space:nowrap}
      #psv-app .psv-operator-reference{margin-top:2.4rem}
      @media(max-width:900px){#psv-app .psv-vault-layout,#psv-app .psv-tool-workspace-layout{grid-template-columns:minmax(0,1fr)}#psv-app .psv-vault-sidebar,#psv-app .psv-tool-sidebar{position:static;grid-column:1;grid-row:2;display:flex;flex-wrap:wrap;gap:.35rem;max-height:none;padding:.65rem}body.psv-tools-three-column .psv-tool-sidebar .psv-vault-sidebar-title{width:100%;padding:.15rem .3rem .3rem}#psv-app .psv-vault-category{width:auto;flex:1 1 180px;border:1px solid var(--md-default-fg-color--lightest)}#psv-app .psv-vault-sidebar-note{display:none}}
      @media(max-width:620px){#psv-app .psv-cards-grid{grid-template-columns:1fr}#psv-app .psv-tools-intro h1{font-size:1.7rem}#psv-app .psv-vault-category{flex-basis:100%}}
      /* Keep the shared MkDocs header, sidebars, article width and page canvas intact. */
      #psv-workbench-root {
        width: 100%;
        max-width: 100%;
        margin: 0;
        padding: 0;
      }
      #psv-app {
        --psv-tool-bg: var(--md-default-bg-color);
        --psv-tool-surface: var(--md-code-bg-color);
        --psv-tool-border: var(--md-default-fg-color--lightest);
        --psv-tool-text: var(--md-default-fg-color);
        --psv-tool-muted: var(--md-default-fg-color--light);
        --psv-tool-accent: var(--md-accent-fg-color);
        width: 100%;
        max-width: 100%;
        box-sizing: border-box;
        font-family: Roboto, "Helvetica Neue", Arial, sans-serif;
        color: var(--psv-tool-text);
        padding: 1.25rem 0 3rem 0;
      }
      #psv-app *, #psv-app *::before, #psv-app *::after { box-sizing: border-box; }
      #psv-app button, #psv-app a, #psv-app input, #psv-app select, #psv-app textarea {
        pointer-events: auto;
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
        font: inherit;
        color: #94a3b8;
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

      /* Keep the Tools page visually consistent with the shared PSV article layout. */
      #psv-app.psv-workbench-v2{max-width:100%;margin:0;padding:0 0 2.5rem;color:var(--md-default-fg-color)}
      #psv-app .psv-tools-intro{margin:0 0 2rem;padding:0 0 1.25rem;border-bottom:1px solid var(--md-default-fg-color--lightest)}
      #psv-app .psv-tools-intro h1{margin:.25rem 0 .65rem;font-size:2rem;font-weight:700;letter-spacing:-.02em;color:var(--md-default-fg-color)}
      #psv-app .psv-tools-intro>p{max-width:850px;color:var(--md-default-fg-color--light);font-size:.95rem;line-height:1.7}
      #psv-app .psv-tools-intro .psv-tools-note{margin:.9rem 0 0;padding:.7rem .9rem;border-left:3px solid var(--md-accent-fg-color);background:var(--md-code-bg-color);font-size:.8rem}
      #psv-app .psv-tool-directory{margin:1.5rem 0 2.4rem}
      #psv-app .psv-trust-line{display:flex;flex-wrap:wrap;gap:.7rem 1.2rem;color:#93c5fd;font:700 .7rem "Roboto Mono",monospace;margin:1.2rem 0}
      #psv-app .psv-command-stats{display:flex;flex-wrap:wrap;gap:2rem;border-top:1px solid rgba(148,163,184,.2);padding-top:1rem}
      #psv-app .psv-command-stats div{display:grid;gap:.15rem}
      #psv-app .psv-command-stats strong{font-size:1.5rem;color:#60a5fa}
      #psv-app .psv-command-stats span{font-size:.78rem;color:#cbd5e1}
      #psv-app .psv-workflow-section,#psv-app .psv-tool-directory,#psv-app .psv-operator-reference{margin:2.4rem 0}
      #psv-app .psv-section-head{display:flex;align-items:end;justify-content:space-between;gap:1rem;margin-bottom:1rem}
      #psv-app .psv-section-head h2{margin:.15rem 0;font-size:1.45rem}
      #psv-app .psv-section-head>p{max-width:440px;color:var(--md-default-fg-color--light);font-size:.85rem;margin:0}
      #psv-app .psv-workflow-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem}
      #psv-app .psv-workflow-card{display:flex;flex-direction:column;align-items:flex-start;gap:.65rem;min-height:180px;padding:1.2rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:13px;background:var(--md-code-bg-color);color:var(--md-default-fg-color);text-align:left;cursor:pointer}
      #psv-app .psv-workflow-card:hover{border-color:#3b82f6;transform:translateY(-2px)}
      #psv-app .psv-workflow-card strong{font-size:1.05rem}
      #psv-app .psv-workflow-card small{color:var(--md-default-fg-color--light);line-height:1.5}
      #psv-app .psv-workflow-card b{color:#3b82f6;margin-top:auto;font-size:.82rem}
      #psv-app .psv-workflow-icon{font:700 .68rem "Roboto Mono",monospace;color:#60a5fa}
      #psv-app .psv-workflow-secure{border-color:rgba(16,185,129,.4)}
      #psv-app .psv-tool-card-v2{width:100%;min-height:190px;color:var(--md-default-fg-color);font:inherit}
      #psv-app .psv-tool-card-v2 .psv-card-title{color:var(--md-default-fg-color);font-size:1rem}
      #psv-app .psv-tool-card-v2 .psv-card-desc{font:inherit;color:var(--md-default-fg-color--light)}
      #psv-app .psv-tool-card-v2 .psv-card-head{width:100%}
      #psv-app .psv-tool-card-v2 .psv-card-foot{width:100%;margin-top:auto}
      #psv-app .psv-reference-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.8rem}
      #psv-app .psv-reference-grid article{padding:1rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:10px;background:var(--md-code-bg-color)}
      #psv-app .psv-reference-grid article strong{font-size:.9rem}
      #psv-app .psv-reference-grid article p{font-size:.8rem;line-height:1.55;color:var(--md-default-fg-color--light);margin:.45rem 0 0}
      #psv-app .psv-workbench-disclaimer{padding:1rem;border-left:3px solid #d97706;background:var(--md-code-bg-color);font-size:.82rem;line-height:1.6}
      #psv-app .psv-empty-state{padding:1.5rem;color:var(--md-default-fg-color--light)}
      #psv-app .psv-advanced-panel{max-width:1050px;margin:1.2rem auto;padding:clamp(1rem,3vw,2rem);border:1px solid var(--md-default-fg-color--lightest);border-radius:15px;background:var(--md-code-bg-color)}
      #psv-app .psv-advanced-panel h1{font-size:clamp(1.6rem,3vw,2.3rem);margin:.5rem 0}
      #psv-app .psv-advanced-panel>p{color:var(--md-default-fg-color--light)}
      #psv-app .psv-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem;margin:1.2rem 0}
      #psv-app .psv-form-grid label,#psv-app .psv-share-label{display:flex;flex-direction:column;gap:.4rem;font-size:.82rem;font-weight:650}
      #psv-app .psv-form-grid input,#psv-app .psv-form-grid textarea,#psv-app .psv-form-grid select,#psv-app .psv-share-label input,#psv-app .psv-share-label textarea{width:100%;padding:.7rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:7px;background:var(--md-default-bg-color);color:var(--md-default-fg-color);font:400 .85rem Arial,sans-serif}
      #psv-app .psv-form-grid textarea{min-height:100px}
      #psv-app .psv-form-wide{grid-column:1/-1}
      #psv-app .psv-file-label{display:block;margin:1.2rem 0;padding:1rem;border:1px dashed #64748b;border-radius:9px;font-weight:650}
      #psv-app .psv-file-label input{display:block;margin-top:.6rem;max-width:100%}
      #psv-app .psv-share-label{margin:1rem 0}
      #psv-app .psv-mode-tabs{display:flex;gap:.5rem;margin:1rem 0}
      #psv-app .psv-output-container{white-space:pre-wrap;overflow-wrap:anywhere;padding:1rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:9px;background:var(--md-default-bg-color);font: .82rem/1.6 "Roboto Mono",monospace}
      #psv-app .psv-tool-note{margin:1rem 0;padding:.8rem;background:var(--md-default-bg-color);border-radius:8px;font-size:.78rem;line-height:1.55;color:var(--md-default-fg-color--light)}
      #psv-app .psv-advanced-head{display:flex;align-items:center;justify-content:space-between;gap:1rem;max-width:1050px;margin:0 auto}
      @media(max-width:900px){#psv-app .psv-workflow-grid{grid-template-columns:1fr}#psv-app .psv-reference-grid{grid-template-columns:repeat(2,minmax(0,1fr))}#psv-app .psv-section-head{align-items:flex-start;flex-direction:column}}
      @media(max-width:620px){#psv-app .psv-form-grid,#psv-app .psv-reference-grid{grid-template-columns:1fr}#psv-app .psv-form-wide{grid-column:auto}#psv-app .psv-command-stats{gap:1rem}#psv-app .psv-advanced-head{align-items:flex-start;flex-direction:column}}
      /* Match the PSV site-wide Material theme rather than a separate dark microsite. */
      #psv-app.psv-workbench-v2{max-width:100%;margin:0;padding:0 0 2.5rem;color:var(--psv-tool-text)}
      #psv-app .psv-command-hero{background:var(--md-code-bg-color);border:1px solid var(--psv-tool-border);box-shadow:none;border-radius:10px;padding:clamp(1.25rem,2.5vw,2rem)}
      #psv-app .psv-command-hero .psv-hero-h1{color:var(--md-default-fg-color);font-size:clamp(2rem,3.5vw,2.8rem);letter-spacing:-.035em}
      #psv-app .psv-command-hero .psv-hero-desc{color:var(--md-default-fg-color--light)}
      #psv-app .psv-trust-line{color:var(--md-accent-fg-color)}
      #psv-app .psv-command-stats{border-top-color:var(--psv-tool-border)}
      #psv-app .psv-command-stats strong{color:var(--md-accent-fg-color)}
      #psv-app .psv-command-stats span{color:var(--md-default-fg-color--light)}
      #psv-app .psv-workflow-card,#psv-app .psv-tool-card-v2,#psv-app .psv-reference-grid article{background:var(--md-code-bg-color);border:1px solid var(--psv-tool-border);border-radius:9px;box-shadow:none;color:var(--md-default-fg-color)}
      #psv-app .psv-workflow-card:hover,#psv-app .psv-tool-card-v2:hover{border-color:var(--md-accent-fg-color);transform:translateY(-1px)}
      #psv-app .psv-workflow-card small,#psv-app .psv-tool-card-v2 .psv-card-desc,#psv-app .psv-reference-grid article p{color:var(--md-default-fg-color--light)}
      #psv-app .psv-workflow-card b,#psv-app .psv-workflow-icon{color:var(--md-accent-fg-color)}
      #psv-app .psv-search-bar{background:var(--md-default-bg-color);border:1px solid var(--psv-tool-border);color:var(--md-default-fg-color)}
      #psv-app .psv-pill{border:1px solid var(--psv-tool-border);background:var(--md-code-bg-color);color:var(--md-default-fg-color)}
      #psv-app .psv-pill.active{background:var(--md-accent-fg-color);border-color:var(--md-accent-fg-color);color:var(--md-default-bg-color)}
      #psv-app .psv-advanced-panel{background:var(--md-code-bg-color);border-color:var(--psv-tool-border);border-radius:10px;box-shadow:none}
      #psv-app .psv-advanced-panel h1,#psv-app .psv-advanced-panel h2,#psv-app .psv-advanced-panel h3{color:var(--md-default-fg-color)}
      #psv-app .psv-privacy-strip,#psv-app .psv-tool-note,#psv-app .psv-workbench-disclaimer{background:var(--md-default-bg-color);color:var(--md-default-fg-color--light);border-color:var(--psv-tool-border);border-radius:8px}
      #psv-app .psv-output-container{background:var(--md-default-bg-color);border-color:var(--psv-tool-border);color:var(--md-default-fg-color)}
      #psv-app .psv-form-grid input,#psv-app .psv-form-grid textarea,#psv-app .psv-form-grid select,#psv-app .psv-share-label input,#psv-app .psv-share-label textarea{background:var(--md-default-bg-color);border-color:var(--psv-tool-border);color:var(--md-default-fg-color);font:inherit}
      #psv-app .psv-form-grid input:focus,#psv-app .psv-form-grid textarea:focus,#psv-app .psv-form-grid select:focus,#psv-app .psv-share-label input:focus,#psv-app .psv-share-label textarea:focus{outline:2px solid var(--md-accent-fg-color);outline-offset:1px}
      #psv-app .psv-btn-run{background:var(--md-primary-fg-color);border:1px solid var(--md-primary-fg-color);color:var(--md-primary-bg-color)}
      #psv-app .psv-btn-util,#psv-app .psv-back-btn{background:var(--md-code-bg-color);border:1px solid var(--psv-tool-border);color:var(--md-default-fg-color)}
      #psv-app [data-psv-action]{cursor:pointer}
      #psv-app a.psv-workflow-card,#psv-app a.psv-tool-card-v2,#psv-app a.psv-related-card{display:flex;text-decoration:none!important;color:var(--md-default-fg-color)!important}
      #psv-app a.psv-workflow-card:hover,#psv-app a.psv-tool-card-v2:hover,#psv-app a.psv-related-card:hover{text-decoration:none!important}
      #psv-app a.psv-tool-card-v2 .psv-card-title,#psv-app a.psv-related-card .psv-card-title{color:var(--md-default-fg-color)}

      #psv-app .psv-section-head h2{color:var(--md-default-fg-color);border:0}
      #psv-app .psv-section-head>p{color:var(--md-default-fg-color--light)}
      #psv-app .psv-workflow-grid{grid-template-columns:repeat(3,minmax(0,1fr))}
      #psv-app .psv-cards-grid{grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem}
      #psv-app .psv-tool-card-v2{min-width:0;min-height:190px;display:flex;flex-direction:column;align-items:flex-start;text-align:left;padding:1rem;gap:.65rem;cursor:pointer}
      #psv-app .psv-tool-card-v2 .psv-card-title{color:var(--md-default-fg-color)}
      #psv-app .psv-tool-card-v2 .psv-card-foot{margin-top:auto}

      #psv-app .psv-advanced-panel{margin:1.25rem 0;padding:clamp(1rem,2vw,1.5rem);border:1px solid var(--md-default-fg-color--lightest);border-radius:10px;background:var(--md-code-bg-color)}
      #psv-app .psv-advanced-panel h2{margin-top:0;color:var(--md-default-fg-color);font-size:1.2rem}
      #psv-app .psv-advanced-panel>p{color:var(--md-default-fg-color--light);font-size:.85rem;line-height:1.65}
      #psv-app .psv-advanced-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem;margin:1rem 0}
      #psv-app .psv-advanced-panel label{display:flex;flex-direction:column;gap:.35rem;min-width:0;font-size:.78rem;font-weight:650}
      #psv-app .psv-advanced-panel input,#psv-app .psv-advanced-panel textarea,#psv-app .psv-advanced-panel select{width:100%;max-width:100%;box-sizing:border-box;padding:.65rem .75rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:6px;background:var(--md-default-bg-color);color:var(--md-default-fg-color);font:inherit;font-size:.85rem}
      #psv-app .psv-advanced-panel input[type=file]{padding:.5rem}
      #psv-app .psv-advanced-actions{display:flex;flex-wrap:wrap;gap:.6rem;margin:1rem 0}
      #psv-app .psv-advanced-actions button{padding:.6rem .9rem;border:1px solid var(--md-accent-fg-color);border-radius:6px;background:var(--md-accent-fg-color);color:var(--md-primary-bg-color);font:inherit;font-size:.8rem;font-weight:650;cursor:pointer}
      #psv-app .psv-advanced-actions button[data-psv-action="share-mode"]{background:var(--md-default-bg-color);color:var(--md-default-fg-color);border-color:var(--md-default-fg-color--lightest)}
      #psv-app .psv-advanced-actions button.active{border-color:var(--md-accent-fg-color);box-shadow:inset 0 -2px var(--md-accent-fg-color)}
      #psv-app .psv-advanced-output{overflow:auto;max-height:420px;padding:1rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:7px;background:var(--md-default-bg-color);color:var(--md-default-fg-color);white-space:pre-wrap;overflow-wrap:anywhere;font-size:.78rem;line-height:1.6}
      #psv-app .psv-advanced-muted{color:var(--md-default-fg-color--light);font-size:.75rem}
      #psv-app .psv-device-panel .psv-advanced-output{max-height:none;overflow:visible;white-space:normal;overflow-wrap:anywhere}
      #psv-app .psv-device-report-head{padding:.9rem 1rem;margin:0 0 1rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:7px;background:var(--md-code-bg-color)}
      #psv-app .psv-device-report-head strong{font-size:.95rem;letter-spacing:.02em}
      #psv-app .psv-device-report-head p{margin:.45rem 0 0;white-space:normal}
      #psv-app .psv-device-comparison{display:grid;gap:.55rem}
      #psv-app .psv-device-diff{display:grid;grid-template-columns:minmax(120px,1fr) auto;gap:.3rem .8rem;padding:.65rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:6px}
      #psv-app .psv-device-diff small{grid-column:1/-1;overflow-wrap:anywhere;color:var(--md-default-fg-color--light)}
      #psv-app .psv-device-raw{margin-top:1rem}
      #psv-app .psv-device-raw pre{max-height:520px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;padding:.8rem;border-radius:5px;background:var(--md-code-bg-color)}
      @media(max-width:600px){#psv-app .psv-device-diff{grid-template-columns:1fr}}
      #psv-app .psv-init-error-detail{white-space:pre-wrap;overflow-wrap:anywhere}
      @media(max-width:650px){#psv-app .psv-advanced-grid{grid-template-columns:1fr}}
      #psv-app .psv-advanced-head{max-width:100%}
      @media(max-width:1100px){#psv-app .psv-cards-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
      @media(max-width:900px){#psv-app .psv-workflow-grid{grid-template-columns:1fr}#psv-app .psv-reference-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
      @media(max-width:620px){#psv-app .psv-cards-grid,#psv-app .psv-reference-grid,#psv-app .psv-form-grid{grid-template-columns:1fr}#psv-app .psv-form-wide{grid-column:auto}#psv-app .psv-command-stats{gap:1rem}}

      /* Final PSV page-alignment overrides: one page title, one content heading. */
      body:has(#psv-workbench-root) .md-content__inner > h1:first-child{display:none!important}
      #psv-app,#psv-app button,#psv-app input,#psv-app select,#psv-app textarea{font-family:Roboto,"Helvetica Neue",Arial,sans-serif}
      #psv-app .psv-vault-layout{display:grid;grid-template-columns:minmax(0,1fr) 245px;gap:1.5rem;align-items:start}
      #psv-app .psv-vault-main{grid-column:1;grid-row:1;min-width:0}
      #psv-app .psv-vault-sidebar{grid-column:2;grid-row:1;align-self:start;position:sticky;top:1.25rem;margin:0}
      #psv-app .psv-tool-workspace-layout{display:grid;grid-template-columns:minmax(0,1fr) 245px;gap:1.5rem;align-items:start}
      #psv-app .psv-tool-workspace-main{grid-column:1;grid-row:1;min-width:0}
      #psv-app .psv-tool-sidebar{grid-column:2;grid-row:1;align-self:start;position:sticky;top:1.25rem;margin:0}
      #psv-app .psv-vault-category strong{font-family:inherit;font-size:.82rem;font-weight:600}
      #psv-app .psv-vault-category small{font-family:inherit;font-size:.72rem}
      #psv-app .psv-tools-intro{margin:0 0 1rem;padding:0;border:0}
      #psv-app .psv-tools-intro h1{margin:0 0 .75rem;font-family:inherit;font-size:1.8rem;font-weight:700;letter-spacing:-.02em;line-height:1.3;color:var(--md-default-fg-color)}
      #psv-app .psv-vault-search-label{margin:0 0 .35rem;font-family:inherit;font-size:.82rem;font-weight:600}
      #psv-app .psv-vault-search-wrap .psv-search-bar{width:100%;font-family:inherit;font-size:.9rem}
      #psv-app .psv-directory-row{font-family:inherit}
      #psv-app .psv-directory-copy strong{font-family:inherit;font-size:.9rem;font-weight:600}
      #psv-app .psv-directory-copy small{font-family:inherit;font-size:.8rem;line-height:1.55}
      #psv-app .psv-directory-open{font-family:inherit;font-size:.78rem;font-weight:600}
      #psv-app .psv-tool-page-head h1,#psv-app .psv-tool-hero h1{font-family:inherit;font-weight:700}
       /* Keep MkDocs Material in control of the page columns. */
      #psv-app .psv-category-group{margin:0;border-bottom:1px solid var(--md-default-fg-color--lightest)}
      #psv-app .psv-category-group>summary{display:flex;align-items:center;justify-content:space-between;gap:.5rem;padding:.2rem .6rem;cursor:pointer;font:inherit;line-height:inherit;list-style:none}
      #psv-app .psv-category-group>summary::-webkit-details-marker{display:none}
      #psv-app .psv-category-tools{padding:.1rem 0 .45rem .45rem}
      #psv-app .psv-category-group .psv-sidebar-tool{display:block;width:100%;padding:.38rem .35rem;border:0;border-radius:4px;background:transparent;color:var(--md-default-fg-color--light);font:inherit;text-align:left;cursor:pointer}
      #psv-app .psv-category-group .psv-sidebar-tool:hover,#psv-app .psv-category-group .psv-sidebar-tool.active{background:var(--md-default-bg-color);color:var(--md-accent-fg-color)}
      #psv-app .psv-category-group .psv-sidebar-tool.active{font-weight:650}
      /* Native Material sidebar: preserve its standard width and scroll behaviour. */
      .md-sidebar--secondary .psv-tool-sidebar{padding:0!important;border:0!important;background:transparent!important}
      .md-sidebar--secondary .psv-tool-sidebar>.psv-category-accordion{margin-top:.85rem!important}
      .md-sidebar--secondary .psv-tool-sidebar .psv-category-group{margin:0}
      .md-sidebar--secondary .psv-tool-sidebar .psv-category-group>summary.md-nav__link{display:flex;align-items:center;justify-content:space-between;cursor:pointer;list-style:none}
      .md-sidebar--secondary .psv-tool-sidebar .psv-category-group>summary.md-nav__link::-webkit-details-marker{display:none}
      .md-sidebar--secondary .psv-tool-sidebar .psv-category-tools{display:block;margin:0 0 0 .55rem;padding:0 0 0 .55rem;border-left:1px solid var(--md-default-fg-color--lightest)}
      .md-sidebar--secondary .psv-tool-sidebar .psv-sidebar-tool.md-nav__link{display:block;width:100%;min-width:0;margin:0;border:0;padding:.2rem .35rem;background:transparent;font:inherit;text-align:left;text-indent:0;white-space:normal;overflow-wrap:anywhere;cursor:pointer}
      .md-sidebar--secondary .psv-tool-sidebar .psv-vault-count{margin-left:auto;padding-left:.5rem;font:inherit;font-size:.85em}
      /* Match Tools page typography to standard MkDocs content pages. */
       #psv-app .psv-tools-intro h1,
       #psv-app .psv-tool-page-head h1{font-size:1.25rem!important;font-weight:700!important;line-height:1.4!important;letter-spacing:normal!important;color:var(--md-typeset-color)!important}
       #psv-app .psv-tools-intro>p,
       #psv-app .psv-tool-page-head>p{max-width:unset!important;margin:.35rem 0 0!important;font-size:.8rem!important;line-height:1.6!important;color:var(--md-default-fg-color--light)!important}
       #psv-app .psv-section-head h2{font-size:1rem!important;font-weight:700!important;line-height:1.4!important;letter-spacing:normal!important;color:var(--md-typeset-color)!important}
       #psv-app .psv-section-head>p{font-size:.8rem!important;line-height:1.6!important;color:var(--md-default-fg-color--light)!important}
       /* Apply the Investigation-page type scale to every standard tool view,
          not only the advanced Incident Case Workspace header. */
       #psv-app .psv-tool-page .psv-tool-hero h1,
       #psv-app .psv-tool-page .psv-tool-page-head h1{margin:0 0 .55rem!important;font-family:inherit!important;font-size:1.8rem!important;font-weight:700!important;line-height:1.3!important;letter-spacing:-.02em!important;color:var(--md-typeset-color)!important}
       #psv-app .psv-tool-page .psv-tool-hero>p,
       #psv-app .psv-tool-page .psv-tool-page-head>p{max-width:unset!important;margin:0 auto .9rem!important;font-family:inherit!important;font-size:.9rem!important;font-weight:400!important;line-height:1.72!important;color:var(--md-default-fg-color--light)!important}
       #psv-app .psv-tool-page .psv-doc-section h3{margin:1.1rem 0 .45rem!important;font-family:inherit!important;font-size:1.15rem!important;font-weight:700!important;line-height:1.4!important;letter-spacing:-.01em!important;color:var(--md-typeset-color)!important}
       #psv-app .psv-tool-page .psv-doc-section>p,
       #psv-app .psv-tool-page .psv-doc-section li,
       #psv-app .psv-tool-page .psv-faq-item>p{font-family:inherit!important;font-size:.9rem!important;font-weight:400!important;line-height:1.72!important;color:var(--md-typeset-color)!important}
       #psv-app .psv-tool-page .psv-advanced-panel h2{font-family:inherit!important;font-size:1.25rem!important;font-weight:700!important;line-height:1.4!important;letter-spacing:-.02em!important;color:var(--md-typeset-color)!important}
       #psv-app .psv-tool-page .psv-advanced-panel>p{font-family:inherit!important;font-size:.9rem!important;line-height:1.72!important;color:var(--md-default-fg-color--light)!important}
       /* Match the native .md-typeset hierarchy used by Investigations. */
       #psv-app .psv-tool-page{width:100%!important;max-width:none!important;margin:0!important;text-align:left!important}
       #psv-app .psv-tool-hero{margin:0 0 1.6rem!important;text-align:left!important}
       #psv-app .psv-tool-hero h1,
       #psv-app .psv-tool-page-head h1{margin:0 0 .8em!important;font-family:inherit!important;font-size:1.5625em!important;font-weight:700!important;line-height:1.4!important;letter-spacing:normal!important;text-align:left!important;color:var(--psv-text)!important}
       #psv-app .psv-tool-hero>p,
       #psv-app .psv-tool-page-head>p{max-width:850px!important;margin:1.2em 0!important;font-family:inherit!important;font-size:1em!important;font-weight:400!important;line-height:1.72!important;text-align:left!important;color:var(--psv-muted)!important}
       #psv-app .psv-hero-badges{justify-content:flex-start!important}
       #psv-app .psv-doc-section{margin:1.6em 0!important;text-align:left!important}
       #psv-app .psv-doc-section h3,
       #psv-app .psv-advanced-panel h2{margin:1.6em 0 .8em!important;padding:0 0 .35em!important;border:0!important;border-bottom:1px solid var(--psv-border)!important;font-family:inherit!important;font-size:1.25em!important;font-weight:700!important;line-height:1.4!important;letter-spacing:normal!important;text-align:left!important;color:var(--psv-text)!important}
       #psv-app .psv-doc-section p,
       #psv-app .psv-doc-section li,
       #psv-app .psv-faq-item>p,
       #psv-app .psv-advanced-panel>p{margin:1.2em 0!important;font-family:inherit!important;font-size:1em!important;font-weight:400!important;line-height:1.72!important;text-align:left!important;color:var(--psv-text)!important}
       #psv-app .psv-advanced-panel{text-align:left!important}

/* Final Threat Intel Hub polish: match PSV page typography and responsive results. */
#psv-app .psv-tool-page .psv-tool-hero h1,
#psv-app .psv-tool-page .psv-tool-page-head h1{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:clamp(1.65rem,2.2vw,2rem)!important;
  font-weight:700!important;
  line-height:1.25!important;
  letter-spacing:-.025em!important;
  margin:0 0 .65rem!important;
}
#psv-app .psv-tool-page .psv-tool-hero>p,
#psv-app .psv-tool-page .psv-tool-page-head>p{
  max-width:820px!important;
  margin:0 0 1rem!important;
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.95rem!important;
  line-height:1.7!important;
  font-weight:400!important;
  color:var(--psv-muted)!important;
}
#psv-app .psv-tool-page .psv-hero-badges{gap:.5rem!important}
#psv-app .psv-tool-page .psv-pill-badge{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.74rem!important;
  font-weight:600!important;
  letter-spacing:0!important;
}
#psv-app .psv-tool-page .psv-field-label{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.75rem!important;
  font-weight:700!important;
  letter-spacing:.055em!important;
  line-height:1.45!important;
}
#psv-app .psv-tool-page .psv-privacy-strip{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.84rem!important;
  line-height:1.65!important;
}
#psv-app .psv-tool-page .psv-editor{
  font-family:"Roboto Mono",SFMono-Regular,Consolas,monospace!important;
  font-size:.84rem!important;
  line-height:1.65!important;
}
#psv-app .psv-tool-page .psv-btn-run,
#psv-app .psv-tool-page .psv-btn-util,
#psv-app .psv-tool-page .psv-opt-pill{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.82rem!important;
  font-weight:600!important;
}
#psv-app .psv-tool-page .psv-output-container{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.9rem!important;
  line-height:1.7!important;
  letter-spacing:normal!important;
}
#psv-app .psv-tool-page .psv-output-container [role="status"],
#psv-app .psv-tool-page .psv-output-container .psv-ti-data-note{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.88rem!important;
  line-height:1.7!important;
  letter-spacing:normal!important;
}
#psv-app .psv-tool-page .psv-out-table{
  width:100%!important;
  min-width:760px!important;
  table-layout:fixed!important;
  border-collapse:collapse!important;
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.86rem!important;
  line-height:1.65!important;
  letter-spacing:normal!important;
}
#psv-app .psv-tool-page .psv-out-table th,
#psv-app .psv-tool-page .psv-out-table td{
  padding:.8rem .9rem!important;
  vertical-align:top!important;
  overflow-wrap:anywhere!important;
  white-space:normal!important;
}
#psv-app .psv-tool-page .psv-out-table th:nth-child(1),
#psv-app .psv-tool-page .psv-out-table td:nth-child(1){width:180px!important}
#psv-app .psv-tool-page .psv-out-table th:nth-child(2),
#psv-app .psv-tool-page .psv-out-table td:nth-child(2){width:165px!important}
#psv-app .psv-tool-page .psv-out-table th{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.82rem!important;
  font-weight:700!important;
}
#psv-app .psv-tool-page .psv-out-table td{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.86rem!important;
  font-weight:400!important;
}
#psv-app .psv-tool-page .psv-out-table code,
#psv-app .psv-tool-page .psv-out-table .mono{
  font-family:"Roboto Mono",SFMono-Regular,Consolas,monospace!important;
}
#psv-app .psv-ti-provider-card__head strong{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.9rem!important;
  font-weight:700!important;
}
#psv-app .psv-ti-provider-card__head span{
  max-width:55%!important;
  font-size:.78rem!important;
  line-height:1.5!important;
}
#psv-app .psv-ti-provider-card__findings{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.88rem!important;
  line-height:1.7!important;
}
#psv-app .psv-ti-provider-card__findings a{font-weight:600!important}
#psv-app .psv-tool-page .psv-doc-section h3{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:1.15rem!important;
  font-weight:700!important;
}
#psv-app .psv-tool-page .psv-doc-section p,
#psv-app .psv-tool-page .psv-doc-section li,
#psv-app .psv-tool-page .psv-faq-item>p{
  font-family:Roboto,"Helvetica Neue",Arial,sans-serif!important;
  font-size:.92rem!important;
  line-height:1.72!important;
}
@media(max-width:800px){
  #psv-app .psv-ti-results-table{display:none!important}
  #psv-app .psv-ti-provider-cards{display:block!important}
  #psv-app .psv-tool-page .psv-tool-hero h1{font-size:1.65rem!important}
  #psv-app .psv-tool-page .psv-tool-hero>p{font-size:.9rem!important}
}
#psv-app .psv-back-bar{display:none!important}
      #psv-app .psv-doc-section{max-width:100%;margin:1.25rem 0}
      /* Native Material breakpoints control both navigation rails. */
@media(max-width:620px){
        #psv-app .psv-tool-hero h1{font-size:1.55rem!important}
        #psv-app .psv-term-body{padding:.75rem!important}
        #psv-app .psv-action-bar{gap:.75rem!important}
        #psv-app .psv-btn-group{display:flex;flex-wrap:wrap;gap:.4rem}
      }

      /* Hybrid Analysis: readable, report-style evidence layout. */
      #psv-app .psv-ha-report{margin:1rem 0;padding:1rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:12px;background:var(--md-code-bg-color)}
      #psv-app .psv-ha-report__top{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:1rem}
      #psv-app .psv-ha-report__top span{font-weight:800;text-transform:uppercase;color:#ef4444}
      #psv-app .psv-ha-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.65rem;margin:1rem 0}
      #psv-app .psv-ha-metrics>div{padding:.8rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:9px}
      #psv-app .psv-ha-metrics small,#psv-app .psv-ha-file span{display:block;color:var(--md-default-fg-color--light);font-size:.76rem}
      #psv-app .psv-ha-metrics strong{display:block;margin-top:.25rem;font-size:1.12rem;overflow-wrap:anywhere}
      #psv-app .psv-ha-file{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.75rem;margin:1rem 0}
      #psv-app .psv-ha-file>div{min-width:0;padding:.65rem 0;border-bottom:1px solid var(--md-default-fg-color--lightest)}
      #psv-app .psv-ha-file strong,#psv-app .psv-ha-file code{display:block;margin-top:.25rem;overflow-wrap:anywhere}
      #psv-app .psv-ha-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.4rem}
      #psv-app .psv-ha-field{display:flex;flex-direction:column;gap:.15rem;min-width:0;padding:.55rem;border-radius:6px;background:var(--md-default-bg-color)}
      #psv-app .psv-ha-field span{font-size:.75rem;color:var(--md-default-fg-color--light)}
      #psv-app .psv-ha-field strong{font-size:.84rem;overflow-wrap:anywhere}
      #psv-app .psv-ha-report details{margin:.7rem 0}
      #psv-app .psv-ha-technical pre{max-height:28rem;overflow:auto}
      @media(max-width:620px){#psv-app .psv-ha-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}#psv-app .psv-ha-file,#psv-app .psv-ha-fields{grid-template-columns:1fr}}
      /* Secure sharing for completed Threat Intelligence lookups. */
      #psv-app .psv-ti-secure-share{margin:1rem 0;padding:1rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:10px;background:var(--md-code-bg-color)}
      #psv-app .psv-ti-secure-share h3{margin-top:0}
      #psv-app .psv-ti-secure-share p{font-size:.88rem;line-height:1.6}
      #psv-app .psv-ti-secure-share__fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.75rem;margin:.75rem 0}
      #psv-app .psv-ti-secure-share__fields label{display:flex;flex-direction:column;gap:.35rem;font-size:.85rem;font-weight:600}
      #psv-app .psv-ti-secure-share__fields input{width:100%;min-width:0;box-sizing:border-box;padding:.65rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:7px;background:var(--md-default-bg-color);color:var(--md-default-fg-color)}
      #psv-app #psv-ti-secure-share-create{padding:.65rem 1rem;border:0;border-radius:7px;background:var(--md-primary-fg-color);color:white;font-weight:700;cursor:pointer}
      #psv-app #psv-ti-share-status{margin-bottom:0;padding:.65rem;border-radius:7px;background:var(--md-default-bg-color)}
      @media(max-width:620px){#psv-app .psv-ti-secure-share__fields{grid-template-columns:1fr}}
      /* Threat-intelligence report readability and progressive disclosure. */
      #psv-app .psv-ti-provider-card{min-width:0;width:100%;box-sizing:border-box;margin:1rem 0;padding:1rem!important}
      #psv-app .psv-ti-provider-card__findings{font-size:.94rem!important;line-height:1.7!important;overflow-wrap:anywhere}
      #psv-app .psv-ti-provider-card__findings details{margin:.8rem 0;padding:.55rem .7rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:8px;background:var(--md-default-bg-color)}
      #psv-app .psv-ti-provider-card__findings details>summary{cursor:pointer;font-weight:650;line-height:1.5}
      #psv-app .psv-ti-provider-card__findings details[open]>summary{margin-bottom:.65rem}
      #psv-app .psv-ti-provider-card__findings li{margin:.35rem 0;line-height:1.6;overflow-wrap:anywhere}
      #psv-app .psv-ha-report{font-size:.94rem;line-height:1.65}
      #psv-app .psv-ha-report__top{flex-wrap:wrap}
      #psv-app .psv-ha-report__top>strong{font-size:1.05rem}
      #psv-app .psv-ha-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}
      #psv-app .psv-ha-metrics>div{min-width:0;background:var(--md-default-bg-color)}
      #psv-app .psv-ha-metrics small{font-size:.78rem;line-height:1.35}
      #psv-app .psv-ha-metrics strong{font-size:1.15rem;line-height:1.3}
      #psv-app .psv-ha-file{grid-template-columns:repeat(2,minmax(0,1fr))}
      #psv-app .psv-ha-file>div{min-width:0}
      #psv-app .psv-ha-file strong,#psv-app .psv-ha-file code{font-size:.88rem;line-height:1.5}
      #psv-app .psv-ha-fields{grid-template-columns:repeat(2,minmax(0,1fr))}
      #psv-app .psv-ha-field{min-width:0}
      #psv-app .psv-ha-technical pre{font-size:.78rem;line-height:1.5;white-space:pre;overflow:auto}
      @media(max-width:800px){
        #psv-app .psv-ti-provider-card{padding:.8rem!important}
        #psv-app .psv-ha-file,#psv-app .psv-ha-fields{grid-template-columns:1fr}
      }
      /* Threat-intel results: readable wrapping and responsive provider cards. */
      #psv-app .psv-ti-results-table{width:100%;max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
      #psv-app .psv-ti-results-table .psv-out-table{width:100%!important;min-width:900px!important;table-layout:fixed!important}
      #psv-app .psv-ti-results-table .psv-out-table th:nth-child(1),#psv-app .psv-ti-results-table .psv-out-table td:nth-child(1){width:180px!important}
      #psv-app .psv-ti-results-table .psv-out-table th:nth-child(2),#psv-app .psv-ti-results-table .psv-out-table td:nth-child(2){width:250px!important}
      #psv-app .psv-ti-results-table .psv-out-table th:nth-child(3),#psv-app .psv-ti-results-table .psv-out-table td:nth-child(3){width:auto!important}
      #psv-app .psv-ti-results-table .psv-out-table th,#psv-app .psv-ti-results-table .psv-out-table td{white-space:normal!important;overflow-wrap:break-word!important;word-break:normal!important;vertical-align:top!important}
      #psv-app .psv-ti-indicator{display:block;max-width:100%;overflow-x:auto;white-space:nowrap;word-break:normal;overflow-wrap:normal;font-family:"Roboto Mono",SFMono-Regular,Consolas,monospace;font-size:.78rem;line-height:1.6}
      #psv-app .psv-ti-provider-cards{display:none}
      #psv-app .psv-ti-error{color:#b91c1c;font-weight:600}
      #psv-app .psv-ti-not-found{color:var(--md-default-fg-color--light);font-weight:500}
      #psv-app .psv-ti-data-note{margin-top:1rem;font-size:.78rem;line-height:1.6;color:var(--md-default-fg-color--light)}
      @media(max-width:800px){
        #psv-app .psv-ti-results-table{display:none!important}
        #psv-app .psv-ti-provider-cards{display:grid!important;grid-template-columns:minmax(0,1fr);gap:.75rem}
        #psv-app .psv-ti-provider-card{min-width:0;padding:1rem;border:1px solid var(--psv-tool-border);border-radius:9px;background:var(--md-code-bg-color);overflow-wrap:anywhere}
        #psv-app .psv-ti-provider-card__head{display:flex;justify-content:space-between;align-items:flex-start;gap:.75rem;flex-wrap:wrap;margin-bottom:.65rem}
        #psv-app .psv-ti-provider-card__head .psv-ti-indicator{max-width:100%;flex:1 1 100%;overflow-x:auto}
        #psv-app .psv-ti-provider-card__findings{min-width:0;overflow-wrap:anywhere;word-break:break-word}
      }

      /* Canonical Tools typography: one hierarchy for overview and individual tools. */
      #psv-app .psv-tool-page .psv-tool-hero h1,
      #psv-app .psv-tool-page .psv-tool-page-head h1{
        margin:0 0 .65rem!important;font-family:inherit!important;
        font-size:clamp(1.65rem,2.2vw,2rem)!important;font-weight:700!important;
        line-height:1.25!important;letter-spacing:-.025em!important;
        color:var(--md-typeset-color)!important;text-align:left!important
      }
      #psv-app .psv-tool-page .psv-tool-hero>p,
      #psv-app .psv-tool-page .psv-tool-page-head>p{
        max-width:820px!important;margin:1.2em 0!important;
        font:inherit!important;font-weight:400!important;
        line-height:inherit!important;
        color:var(--md-typeset-color)!important;text-align:left!important
      }
      #psv-app .psv-tool-page .psv-doc-section h3,
      #psv-app .psv-tool-page .psv-advanced-panel h2{
        margin:1.6rem 0 .65rem!important;padding:0 0 .4rem!important;
        border:0!important;border-bottom:1px solid var(--md-default-fg-color--lightest)!important;
        font-family:inherit!important;font-size:1.2rem!important;font-weight:700!important;
        line-height:1.4!important;letter-spacing:-.015em!important;color:var(--md-typeset-color)!important
      }
      #psv-app .psv-tool-page .psv-doc-section>p,
      #psv-app .psv-tool-page .psv-doc-section li,
      #psv-app .psv-tool-page .psv-advanced-panel>p,
      #psv-app .psv-tool-page .psv-faq-item>p{
        font-family:inherit!important;font-size:.92rem!important;font-weight:400!important;
        line-height:1.75!important;color:var(--md-typeset-color)!important
      }
      #psv-app .psv-tool-page .psv-secure-transfer-open{
        display:inline-flex;align-items:center;gap:.55rem;padding:.7rem 1rem;
        border:1px solid var(--md-accent-fg-color);border-radius:6px;
        background:var(--md-accent-fg-color);color:var(--md-primary-bg-color)!important;
        font-family:inherit;font-size:.85rem;font-weight:600;line-height:1.3;
        text-decoration:none!important
      }
      #psv-app .psv-tool-page .psv-secure-transfer-open:hover{filter:brightness(1.08)}
      /* Final page-wide descriptive text scale: mirror native .md-typeset paragraphs.
         Scoped to the Tools app so Investigations and other site pages remain untouched. */
      #psv-app .psv-tools-intro>p,
      #psv-app .psv-section-head>p,
      #psv-app .psv-tool-card-v2 .psv-card-desc,
      #psv-app .psv-workflow-card small,
      #psv-app .psv-reference-grid article p,
      #psv-app .psv-tool-page .psv-tool-hero>p,
      #psv-app .psv-tool-page .psv-tool-page-head>p,
      #psv-app .psv-tool-page .psv-doc-section p,
      #psv-app .psv-tool-page .psv-doc-section li,
      #psv-app .psv-tool-page .psv-faq-item>p,
      #psv-app .psv-tool-page .psv-advanced-panel>p{
        font-family:inherit!important;
        font-size:.8rem!important;
        font-weight:400!important;
        line-height:1.72!important;
        color:var(--md-typeset-color)!important;
      }
      #psv-app .psv-tools-intro>p,
      #psv-app .psv-section-head>p,
      #psv-app .psv-tool-page .psv-tool-hero>p,
      #psv-app .psv-tool-page .psv-tool-page-head>p{
        max-width:none!important;
        text-align:left!important;
      }

      @media(max-width:700px){
        #psv-app .psv-tool-page .psv-tool-hero h1,
        #psv-app .psv-tool-page .psv-tool-page-head h1{font-size:1.55rem!important}
        #psv-app .psv-tool-page .psv-tool-hero>p,
        #psv-app .psv-tool-page .psv-tool-page-head>p{font-size:.9rem!important}
      }


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
  let lastThreatIntelReport = null;

  async function encryptThreatIntelReport() {
    const status = document.getElementById("psv-ti-share-status");
    const pass = document.getElementById("psv-ti-share-pass");
    const confirm = document.getElementById("psv-ti-share-confirm");
    if (!status || !pass || !confirm) return;
    const passphrase = String(pass.value || "");
    if (!lastThreatIntelReport) { status.textContent = "Run a provider lookup before creating a secure report package."; return; }
    if (!window.isSecureContext || !window.crypto || !crypto.subtle) { status.textContent = "Secure encryption requires HTTPS and a browser with Web Crypto support."; return; }
    if (passphrase.length < 16) { status.textContent = "Use a passphrase of at least 16 characters."; return; }
    if (passphrase !== String(confirm.value || "")) { status.textContent = "The passphrases do not match."; return; }
    try {
      const encoder = new TextEncoder();
      const plaintext = encoder.encode(JSON.stringify(lastThreatIntelReport, null, 2));
      if (plaintext.byteLength > 10 * 1024 * 1024) { status.textContent = "This report exceeds the 10 MB browser encryption limit. Use your organisation's approved secure evidence-transfer process."; return; }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
      const key = await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt"]);
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv},key,plaintext));
      const toB64 = bytes => { let binary=""; for(let i=0;i<bytes.length;i+=0x8000) binary+=String.fromCharCode(...bytes.subarray(i,i+0x8000)); return btoa(binary); };
      const pkg = {
        format:"PSV-ENCRYPTED-PACKAGE",version:1,algorithm:"AES-256-GCM",
        kdf:"PBKDF2-SHA-256",iterations:310000,salt:toB64(salt),iv:toB64(iv),
        filename:"psv-threat-intelligence-report.json",
        content_type:"application/json;charset=utf-8",payload:toB64(ciphertext)
      };
      downloadText("psv-threat-intel-encrypted-report.json",JSON.stringify(pkg,null,2),"application/json;charset=utf-8");
      status.textContent = "Encrypted report package downloaded. Share this file and its passphrase through separate approved channels. No report content or passphrase was sent to PSV servers.";
      pass.value = ""; confirm.value = "";
    } catch (error) {
      console.error("[PSV Threat Intel] Secure report encryption failed:",error);
      status.textContent = "Encryption failed. No package was created. Try again or use an approved secure transfer method.";
    }
  }

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
    if (/^CVE-\d{4}-\d{4,}$/i.test(value)) return { value: value.toUpperCase(), isIp: false, isCve: true };
    if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value)) return { value, isIp: false, isHash: true };
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
      outputElement.innerHTML = '<div role="alert" class="psv-ti-error">Enter one public IPv4/IPv6 address, domain, file hash, or CVE ID. Private and reserved IP ranges are not queried.</div>';
      return;
    }
    const requestId = ++tiLookupSequence;
    const indicator = parsed.value;
    outputElement.innerHTML = '<div role="status">Querying configured threat-intelligence providers through the PSV API…</div>';
    try {
      const response = await fetch("https://api.privacyskillvault.com/api/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ indicator })
      });
      let payload = {};
      try { payload = await response.json(); } catch (_) {}
      if (!response.ok) throw new Error(payload.error || ("PSV API returned HTTP " + response.status));
      if (requestId !== tiLookupSequence || document.getElementById("psv-tool-result-box") !== outputElement || activeToolId !== "ti" || currentView !== "tool") return;

      lastThreatIntelReport = {
        schema:"PSV-THREAT-INTELLIGENCE-REPORT",
        schemaVersion:1,
        generatedAt:new Date().toISOString(),
        indicator:{value:indicator,type:payload.indicator && payload.indicator.type || "unknown"},
        completenessNote:"Provider responses are independent. Missing fields or reports are not clean verdicts. Validate provider timestamps, coverage and evidence before making incident decisions.",
        results:payload.results || {}
      };
      const providers = [
        ["AbuseIPDB", "abuseipdb"],
        ["AlienVault OTX", "otx"],
        ["NVD", "nvd"],
        ["urlscan.io", "urlscan"],
        ["VirusTotal", "virustotal"],
        ["Hybrid Analysis", "hybridAnalysis"]
      ];
      const escValue = value => esc(value === undefined || value === null || value === "" ? "Not supplied" : String(value));
      const formatLocalDateTime = value => {
        if (value === undefined || value === null || value === "") return "Not supplied";
        const numeric = Number(value);
        const isNumeric = typeof value === "number" || /^\\d{9,13}$/.test(String(value));
        const date = isNumeric ? new Date(numeric < 100000000000 ? numeric * 1000 : numeric) : new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        try {
          const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "Asia/Riyadh";
          return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium", timeZone: zone, timeZoneName: "short" }).format(date);
        } catch (_) {
          return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "medium", timeZone: "Asia/Riyadh" }).format(date) + " (Saudi Arabia time)";
        }
      };
      const renderProvider = key => {
        const item = payload.results && payload.results[key];
        if (!item) return "No response returned by provider.";
        if (item.status === "not_applicable") return "Not supported for this indicator type.";
        if (item.status === "not_configured" || item.status === "not_applicable_or_not_configured") return "Provider API is not configured on the server.";
        if (item.status === "not_found") return '<span class="psv-ti-not-found">No matching report is currently indexed for this indicator.</span>';
        if (item.status === "error") return '<span class="psv-ti-error"><strong>Provider error:</strong> ' + escValue(item.message) + '</span>';
        const d = item.data || {};
        if (key === "abuseipdb") return [
          "Abuse confidence: " + escValue(d.abuseConfidenceScore) + "%",
          "Total reports: " + escValue(d.totalReports),
          "Country: " + escValue(d.countryCode),
          "ISP: " + escValue(d.isp),
          "Usage: " + escValue(d.usageType),
          "Tor: " + escValue(d.isTor),
          "Last reported: " + escValue(formatLocalDateTime(d.lastReportedAt))
        ].join("<br>");
        if (key === "otx") {
          const pulses = (d.pulses || []).map(p => {
            const tags = Array.isArray(p.tags) && p.tags.length ? "<br><small>Tags: " + escValue(p.tags.join(", ")) + "</small>" : "";
            const created = p.created ? " · Created: " + escValue(formatLocalDateTime(p.created)) : "";
            const description = p.description && p.description.trim() && !/^not supplied$/i.test(p.description.trim())
              ? "<br>" + escValue(p.description.trim().slice(0, 240)) : "";
            const link = p.id ? '<br><a href="https://otx.alienvault.com/pulse/' + encodeURIComponent(p.id) + '" target="_blank" rel="noopener noreferrer">Open pulse on OTX</a>' : "";
            return "<li><strong>" + escValue(p.name || "Unnamed pulse") + "</strong>" + created + description + tags + link + "</li>";
          }).join("");
          return "<strong>OTX pulse associations</strong><br>" + escValue(d.pulseCount) + " pulses reported by OTX; " +
            escValue(d.pulseSummariesReturned || 0) + " summaries returned below. This is not a malware-detection count or a verdict." +
            (pulses ? "<ul>" + pulses + "</ul>" : "<br>No pulse summaries returned.");
        }
        if (key === "nvd") {
          if (!d.vulnerabilities || !d.vulnerabilities.length) return "No CVE record returned.";
          return d.vulnerabilities.map(v => "<strong>" + escValue(v.id) + "</strong> — " + escValue(v.baseSeverity) + " / " + escValue(v.baseScore) + "<br>" + escValue(v.description) + "<br><small>Status: " + escValue(v.vulnStatus) + " · Published: " + escValue(v.published) + "</small>").join("<hr>");
        }
        if (key === "virustotal") {
          const stats = d.lastAnalysisStats || {};
          const statOrder = ["malicious", "suspicious", "harmless", "undetected", "timeout", "confirmed-timeout", "failure", "type-unsupported"];
          const total = statOrder.reduce((sum, name) => sum + (Number.isFinite(stats[name]) ? stats[name] : 0), 0);
          const flagged = Number(stats.malicious || 0) + Number(stats.suspicious || 0);
          const statLabels = { malicious: "Malicious", suspicious: "Suspicious", harmless: "Harmless", undetected: "Undetected", timeout: "Timeout", "confirmed-timeout": "Confirmed timeout", failure: "Failure", "type-unsupported": "Type unsupported" };
          const statHtml = statOrder.filter(name => stats[name] !== undefined).map(name => "<li>" + escValue(statLabels[name]) + ": <strong>" + escValue(stats[name]) + "</strong></li>").join("");
          const file = d.file || {};
          const hashes = [["SHA-256", file.sha256], ["SHA-1", file.sha1], ["MD5", file.md5]].filter(pair => pair[1]);
          const fileHtml = hashes.length || file.meaningfulName || file.size !== undefined
            ? "<hr><strong>File details</strong><br>" + (file.meaningfulName ? "Name: " + escValue(file.meaningfulName) + "<br>" : "") +
              (file.size !== undefined ? "Size: " + escValue(Number(file.size).toLocaleString()) + " bytes<br>" : "") +
              hashes.map(pair => "<div class='psv-ti-hash'><span>" + pair[0] + "</span><code>" + escValue(pair[1]) + "</code></div>").join("") : "";
          const engines = (d.engineResults || []).map(engine => "<li><strong>" + escValue(engine.engine) + "</strong>: " + escValue(engine.category) + (engine.result ? " — " + escValue(engine.result) : "") + "</li>").join("");
          const sandboxes = (d.sandboxVerdicts || []).map(v => "<li><strong>" + escValue(v.sandbox) + "</strong>: " + escValue(v.category) + (v.malwareClassification ? " — " + escValue(v.malwareClassification) : "") + "</li>").join("");
          const link = d.id ? "<a href='https://www.virustotal.com/gui/file/" + encodeURIComponent(d.id) + "' target='_blank' rel='noopener noreferrer'>Open VirusTotal report</a>" : "";
          return "<strong>" + (total ? flagged + " / " + total + " engines; " + flagged + " marked malicious or suspicious" : "No engine statistics returned") + "</strong><br>Reputation score: " + escValue(d.reputation) +
            (statHtml ? "<ul class='psv-ti-stats'>" + statHtml + "</ul>" : "") +
            "<br>Last analysis: " + escValue(formatLocalDateTime(d.lastAnalysisDate)) +
            (d.popularThreatClassification && d.popularThreatClassification.suggestedThreatLabel ? "<br>Threat label: " + escValue(d.popularThreatClassification.suggestedThreatLabel) : "") +
            fileHtml + (engines ? "<details><summary>All engine-level results</summary><ul>" + engines + "</ul></details>" : "") +
            (sandboxes ? "<details><summary>Sandbox verdicts (" + escValue((d.sandboxVerdicts || []).length) + ")</summary><ul>" + sandboxes + "</ul></details>" : "") +
             (d.rawAttributes ? "<details><summary>Complete VirusTotal API attributes (raw JSON)</summary><pre class=psv-ti-raw-json>" + escValue(JSON.stringify(d.rawAttributes, null, 2)) + "</pre></details>" : "") +
            (link ? "<br>" + link : "");
        }
        if (key === "hybridAnalysis") {
          const reports = d.reports || [];
          if (!reports.length) return "Hybrid Analysis API did not return a report from its overview or hash-search endpoints." + (d.searchError ? "<br>Hash search: " + escValue(d.searchError) : "") + (d.overviewError ? "<br>Overview lookup: " + escValue(d.overviewError) : "") + (d.lookupStatus === "lookup_incomplete" ? "<br><strong>Lookup incomplete:</strong> this is not evidence that the report does not exist." : "");
          const humanLabel = key => String(key).replace(/_/g," ").replace(/([a-z])([A-Z])/g,"$1 $2").replace(/\b\w/g,c=>c.toUpperCase());
          const humanValue = value => {
            if (value === null || value === undefined || value === "") return "Not supplied";
            if (typeof value === "boolean") return value ? "Yes" : "No";
            if (typeof value === "object") return "";
            return String(value);
          };
          const fieldRows = (value, depth=0, prefix="") => {
            if (!value || typeof value !== "object" || depth > 2) return "";
            const entries = Array.isArray(value) ? value.map((v,i)=>[String(i+1),v]) : Object.entries(value);
            return entries.map(([key,val]) => {
              const label = prefix ? prefix + " · " + humanLabel(key) : humanLabel(key);
              if (val && typeof val === "object") {
                if (Array.isArray(val) && val.every(x=>typeof x!=="object"||x===null)) return "<div class='psv-ha-field'><span>"+escValue(label)+"</span><strong>"+escValue(val.join(", ")||"None")+"</strong></div>";
                return fieldRows(val,depth+1,label);
              }
              return "<div class='psv-ha-field'><span>"+escValue(label)+"</span><strong>"+escValue(humanValue(val))+"</strong></div>";
            }).join("");
          };
          return reports.map(r => {
            const detail = r.detail || {};
            const overview = detail.overview || {};
            const summary = detail.overviewSummary || {};
            const report = detail.summary || r.searchResult || {};
            const full = detail.fullReport || {};
            const pick = (...values) => values.find(v=>v!==undefined&&v!==null&&v!=="");
            const verdict = pick(report.verdict,summary.verdict,overview.verdict);
            const threat = pick(report.threat_score,summary.threat_score,overview.threat_score);
            const av = pick(report.av_detect,summary.av_detect,overview.av_detect);
            const filename = pick(report.file_name,report.filename,report.last_file_name,summary.file_name,summary.last_file_name,overview.file_name,overview.last_file_name);
            const size = pick(report.size,summary.size,overview.size);
            const indicators = pick(report.total_indicators,report.indicators_count,summary.total_indicators,summary.indicators_count,summary.indicators,overview.total_indicators,overview.indicators);
            const firstSeen = pick(report.submitted_at,summary.submitted_at,overview.submitted_at);
            const analyzed = pick(report.analysis_start_time,summary.analysis_start_time,overview.analysis_start_time);
            const reportIds = d.reportIdsFound || reports.length;
            const link = r.reportUrl ? "<a href='"+escValue(r.reportUrl)+"' target='_blank' rel='noopener noreferrer'>Open official Hybrid Analysis sample report</a>" : "";
            const sandboxList = (d.reports || []).map((item,i)=>"<li>"+escValue(item.searchResult && (item.searchResult.environment_description||item.searchResult.environment)||("Sandbox report "+(i+1)))+" · "+escValue(item.searchResult && item.searchResult.verdict)+"</li>").join("");
            const summaryFields = fieldRows(report);
            const fullFields = fieldRows(full);
            const rawBlock = value => value===undefined ? "" : "<details class='psv-ha-technical'><summary>Technical evidence (raw JSON)</summary><pre class='psv-ti-raw-json'>"+escValue(JSON.stringify(value,null,2))+"</pre></details>";
            const errors = Object.entries(r.detailErrors||{}).map(([name,message])=>"<li>"+escValue(humanLabel(name))+": "+escValue(message)+"</li>").join("");
            return "<section class='psv-ha-report'><div class='psv-ha-report__top'><strong>Hybrid Analysis report</strong><span>"+escValue(verdict||"Verdict not supplied")+"</span></div>"+
              "<div class='psv-ha-metrics'><div><small>Threat score</small><strong>"+escValue(threat!==undefined?threat+"/100":"Not supplied")+"</strong></div><div><small>Antivirus detections</small><strong>"+escValue(av||"Not supplied")+"</strong></div><div><small>Indicators</small><strong>"+escValue(indicators!==undefined?indicators:"Not supplied")+"</strong></div><div><small>Sandbox reports</small><strong>"+escValue(reportIds)+"</strong></div></div>"+
              "<div class='psv-ha-file'><div><span>File name</span><strong>"+escValue(filename)+"</strong></div><div><span>File size</span><strong>"+escValue(size!==undefined?size+" bytes":"Not supplied")+"</strong></div><div><span>SHA-256</span><code>"+escValue(pick(report.sha256,summary.sha256,overview.sha256))+"</code></div><div><span>First submitted</span><strong>"+escValue(formatLocalDateTime(firstSeen))+"</strong></div><div><span>Analysis started</span><strong>"+escValue(formatLocalDateTime(analyzed))+"</strong></div><div><span>Report ID</span><code>"+escValue(r.reportId||"Not supplied")+"</code></div></div>"+
              (link?"<p>"+link+"</p>":"")+
              (sandboxList?"<details open><summary>Sandbox analysis environments</summary><ul>"+sandboxList+"</ul></details>":"")+
              (summaryFields?"<details open><summary>Readable report details</summary><div class='psv-ha-fields'>"+summaryFields+"</div></details>":"")+
              (fullFields?"<details><summary>Detailed analysis findings</summary><div class='psv-ha-fields'>"+fullFields+"</div></details>":"")+
              rawBlock(detail.summary)+rawBlock(detail.overview)+rawBlock(detail.overviewSummary)+rawBlock(detail.fullReport)+
              (errors?"<details><summary>Some report details unavailable</summary><ul>"+errors+"</ul></details>":"")+"</section>";
          }).join("<hr>");
        }
        const rows = d.results || [];
        if (!rows.length) return "No matching scan results returned.";
        return rows.map(r => {
          const task = r.task || {}, page = r.page || {};
          const link = task.uuid ? '<a href="https://urlscan.io/result/' + encodeURIComponent(task.uuid) + '/" target="_blank" rel="noopener noreferrer">Open scan result</a>' : "";
          return "<strong>" + escValue(page.domain || task.url) + "</strong> · " + escValue(formatLocalDateTime(task.time)) + "<br>IP: " + escValue(page.ip) + " · Country: " + escValue(page.country) + "<br>" + link;
        }).join("<hr>");
      };
      const providerRows = providers.map(([name,key]) => ({
        name,
        key,
        findings: renderProvider(key)
      }));
      const providerCards = '<div class="psv-ti-provider-cards">' + providerRows.map(row =>
        '<section class="psv-ti-provider-card" aria-labelledby="psv-ti-' + row.key + '">' +
          '<div class="psv-ti-provider-card__head"><strong id="psv-ti-' + row.key + '">' + row.name + '</strong><span class="psv-ti-provider-card__type">' + esc(payload.indicator && payload.indicator.type || "Indicator") + '</span></div>' +
          '<div class="psv-ti-provider-card__indicator"><code class="psv-ti-indicator">' + esc(indicator) + '</code><button type="button" class="psv-ti-copy" data-copy-indicator="' + esc(indicator) + '">Copy</button></div>' +
          '<div class="psv-ti-provider-card__findings">' + row.findings + '</div></section>'
      ).join("") + '</div>';
      outputElement.innerHTML = '<div role="status"><strong>Lookup completed.</strong> Each provider is independent. Detection totals and timestamps are provider-specific; a missing report is not a clean verdict. Results are supporting intelligence, not proof of compromise.</div>' +
        providerCards +
        '<section class="psv-ti-secure-share" aria-labelledby="psv-ti-secure-share-title"><h3 id="psv-ti-secure-share-title">Securely share this investigation</h3><p>Create a locally encrypted copy of the provider responses, including available technical evidence. Encryption uses AES-256-GCM and PBKDF2-SHA-256. PSV does not upload or store the report or passphrase.</p><div class="psv-ti-secure-share__fields"><label for="psv-ti-share-pass">Passphrase (minimum 16 characters)<input id="psv-ti-share-pass" type="password" autocomplete="new-password" minlength="16" placeholder="Create a strong, unique passphrase"></label><label for="psv-ti-share-confirm">Confirm passphrase<input id="psv-ti-share-confirm" type="password" autocomplete="new-password" minlength="16" placeholder="Re-enter the passphrase"></label></div><button type="button" id="psv-ti-secure-share-create">Encrypt &amp; download report</button><p id="psv-ti-share-status" role="status" aria-live="polite">The encrypted package can be opened using the Secure Share tool. Send the passphrase separately using an approved channel.</p></section>' +
        '<p class="psv-ti-data-note">Only the indicator entered above is sent to the configured providers. Do not submit employer-confidential indicators unless your organisation permits external sharing.</p>';
      const secureShareButton = outputElement.querySelector("#psv-ti-secure-share-create");
      if (secureShareButton) secureShareButton.addEventListener("click", encryptThreatIntelReport);
      outputElement.querySelectorAll("[data-copy-indicator]").forEach(button => {
        button.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(button.getAttribute("data-copy-indicator") || "");
            button.textContent = "Copied";
          } catch (_) {
            button.textContent = "Copy unavailable";
          }
        });
      });
    } catch (error) {
      if (requestId !== tiLookupSequence) return;
      outputElement.innerHTML = '<div role="alert" class="psv-ti-error">Threat-intelligence lookup failed: ' + esc(error && error.message ? error.message : "Network error") + '</div>';
    }
  }

  function computeDynamicOutput(tool, rawInput) {
    const input = (rawInput || "").trim();
    if (!input) {
      return `<div style="color:#94a3b8;padding:0.5rem;">Input is empty. Click <strong>Load Sample</strong> above or paste your own telemetry.</div>`;
    }

    if (tool.id === "spl") {
      const presets = [
        `index=wineventlog sourcetype=WinEventLog:Security EventCode=4625 | stats count as failures dc(user) as distinct_users values(user) as users by IpAddress | where failures >= 5 | sort - failures`,
        `index=wineventlog sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624) | eval outcome=if(EventCode=4625,"failure","success") | stats count(eval(outcome="failure")) as failures count(eval(outcome="success")) as successes earliest(_time) as first_seen latest(_time) as last_seen by user, IpAddress | where failures >= 5 AND successes > 0 | convert ctime(first_seen) ctime(last_seen)`,
        `index=* (EventCode=4688 OR event_id=4688) | table _time host user New_Process_Name Process_Command_Line Parent_Process_Name | sort - _time`,
        `index=* (dest_ip=* OR DestinationIp=*) | stats count values(dest_port) as ports values(action) as actions by src_ip dest_ip | sort - count`
      ];
      const query = presets[Math.min(selectedOptionIdx,3)];
      return '<div class="psv-tool-note"><strong>Generated template — review before execution.</strong> Replace example indexes, sourcetypes and field names with those present in your deployment. This builder does not connect to Splunk or validate field availability.</div><pre class="psv-query-output" style="white-space:pre-wrap;overflow-wrap:anywhere;">'+esc(query)+'</pre><p>Selected use case: '+esc(tool.options[selectedOptionIdx]||tool.options[0])+'</p>';
    }

    if (tool.id === "parser") {
      try {
        if (selectedOptionIdx === 0) {
          const parsed=JSON.parse(input);
          const rows=Array.isArray(parsed)?parsed:[parsed];
          if(!rows.length)return '<p>No records found.</p>';
          const keys=Array.from(new Set(rows.flatMap(x=>x&&typeof x==="object"?Object.keys(x):[])));
          return '<p>Parsed '+rows.length+' JSON record(s).</p><table class="psv-out-table"><thead><tr>'+keys.map(k=>'<th>'+esc(k)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(row=>'<tr>'+keys.map(k=>'<td>'+esc(row&&row[k]!==undefined?(typeof row[k]==="object"?JSON.stringify(row[k]):String(row[k])):"")+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
        }
        if (selectedOptionIdx === 1) {
          const lines=input.split(/\r?\n/).filter(Boolean);
          if(lines.length<2)throw new Error("CSV needs a header row and at least one data row.");
          const parseLine=line=>{const out=[];let v="",quoted=false;for(let i=0;i<line.length;i++){const c=line[i];if(c==='"'&&quoted&&line[i+1]==='"'){v+='"';i++;}else if(c==='"'){quoted=!quoted;}else if(c===','&&!quoted){out.push(v);v="";}else{v+=c;}}if(quoted)throw new Error("Unclosed quoted CSV field.");out.push(v);return out;};
          const headers=parseLine(lines[0]),records=lines.slice(1).map(line=>parseLine(line));
          return '<p>Parsed '+records.length+' CSV record(s).</p><table class="psv-out-table"><thead><tr>'+headers.map(h=>'<th>'+esc(h)+'</th>').join('')+'</tr></thead><tbody>'+records.map(row=>'<tr>'+headers.map((_,i)=>'<td>'+esc(row[i]||"")+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
        }
        const records=input.split(/\r?\n/).filter(Boolean).map(line=>{const obj={};const rx=/([A-Za-z_][\w.-]*)=(?:"([^"]*)"|'([^']*)'|(\S+))/g;let m;while((m=rx.exec(line))!==null)obj[m[1]]=m[2]??m[3]??m[4];return obj;});
        return '<p>Parsed '+records.length+' key=value record(s).</p><pre style="white-space:pre-wrap;overflow-wrap:anywhere;">'+esc(JSON.stringify(records,null,2))+'</pre>';
      } catch(err) { return '<div role="alert">Parse error: '+esc(err.message)+'</div>'; }
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
        rows.map((r,i)=>'<tr><td>'+(i+1)+'</td><td>'+esc(r[0])+'</td><td>'+esc(r[1])+'</td><td>'+esc(r[2])+'</td><td>'+(r[3]&&normalizeThreatIndicator(r[1])?'<button type="button" class="psv-btn-util" data-psv-action="pivot-ti" data-indicator="'+esc(r[1])+'">Enrich →</button>':'—')+'</td></tr>').join("")+
        '</tbody></table><p class="psv-tool-note">Domain extraction includes URL hostnames, email domains, and domain-like text. It is pattern-based, not DNS validation. IPv4 extraction is syntax-checked only and does not classify address ranges; the Enrich action is shown only when the Threat Intel Hub accepts the indicator.</p>';
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
      `;
    }

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
    activeToolId = TOOLS.some(t => t.id === activeToolId) ? activeToolId : "ioc";
    currentView = "tool";
    renderSingleToolView(root);
  }
  function downloadText(filename, content, mime) {
    const blob = new Blob([content], { type: mime || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename || "download.txt";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function fieldValue(id) {
    const el = document.getElementById(id);
    return el ? String(el.value || "").trim() : "";
  }

  function caseReport() {
    const fields = [
      ["Case ID","case-id"],["Incident title","case-title"],["Severity / priority","case-severity"],
      ["Status","case-status"],["Detection source","case-source"],["Affected assets / accounts","case-assets"],
      ["UTC timeline","case-timeline"],["Indicators of compromise","case-iocs"],
      ["Investigation notes","case-notes"],["Containment / response actions","case-actions"],
      ["Evidence references","case-evidence"]
    ];
    const lines = ["# SOC Incident Case Report","","Generated (UTC): " + new Date().toISOString(),""];
    fields.forEach(pair => { const value=fieldValue(pair[1]); if(value) lines.push("## "+pair[0],"",value,""); });
    lines.push("> Generated locally in the browser. Verify facts, timestamps and evidence references before storing in an approved case-management system.");
    return lines.join("\n");
  }

  function renderAdvancedTool(root, tool) {
    const back = '<div class="psv-back-bar"><button type="button" class="psv-back-btn" data-psv-action="back-catalog">← Back to All Tools ('+TOOLS.length+')</button></div>';
    const header = '<header class="psv-tool-page-head"><h1>'+esc(tool.title)+'</h1><p>'+esc(tool.desc)+'</p></header>';
    let body = "";
    if (tool.id === "secure-transfer") {
      body = '<section class="psv-advanced-panel psv-secure-transfer-launch"><h2>Live browser-to-browser transfer</h2><p>Open the separate Secure Share workspace to create a one-time, sender-approved transfer. The payload is encrypted in the sender browser and sent over a WebRTC data channel.</p><p class="psv-advanced-muted">This is separate from Secure Evidence Share, which encrypts a package using a passphrase. Keep the complete recipient link private: it contains the decryption key.</p><div class="psv-advanced-actions"><a class="psv-secure-transfer-open" href="/secure-share/">Open Secure Share workspace <span aria-hidden="true">→</span></a></div></section>';
    } else if (tool.id === "case") {
      body = '<section class="psv-advanced-panel"><h2>Incident details</h2><p>Build a local incident record. Export the report and store it only in your approved case repository.</p><div class="psv-advanced-grid">'+
        '<label>Case ID<input id="case-id" type="text" placeholder="INC-2026-001"></label>'+
        '<label>Incident title<input id="case-title" type="text" placeholder="Suspicious account activity"></label>'+
        '<label>Severity / priority<select id="case-severity"><option>P1 - Critical</option><option>P2 - High</option><option selected>P3 - Medium</option><option>P4 - Low</option><option>Under assessment</option></select></label>'+
        '<label>Status<select id="case-status"><option>Open</option><option>Investigating</option><option>Contained</option><option>Resolved</option><option>Closed</option></select></label>'+
        '<label>Detection source<input id="case-source" type="text" placeholder="SIEM, EDR, fraud alert…"></label>'+
        '<label>Affected assets / accounts<textarea id="case-assets" rows="3" placeholder="Hostnames, user IDs, applications…"></textarea></label>'+
        '<label>Timeline (UTC)<textarea id="case-timeline" rows="5" placeholder="2026-10-31 10:15 UTC — Alert generated…"></textarea></label>'+
        '<label>Indicators of compromise<textarea id="case-iocs" rows="4" placeholder="IP addresses, domains, hashes, URLs…"></textarea></label>'+
        '<label>Investigation notes<textarea id="case-notes" rows="5" placeholder="Observations, validation, correlation and findings…"></textarea></label>'+
        '<label>Containment / response actions<textarea id="case-actions" rows="4" placeholder="Actions taken, owner and time…"></textarea></label>'+
        '<label>Evidence references<textarea id="case-evidence" rows="3" placeholder="Evidence IDs, file names, SHA-256…"></textarea></label></div>'+
        '<div class="psv-advanced-actions"><button type="button" data-psv-action="copy-case">Copy Markdown report</button><button type="button" data-psv-action="export-case">Download Markdown report</button></div>'+
        '<pre id="case-output" class="psv-advanced-output" aria-live="polite">Complete the fields and export your incident report.</pre></section>';
    } else if (tool.id === "evidence") {
      body = '<section class="psv-advanced-panel"><h2>Calculate file integrity digest</h2><p>Select a local file. It is read in browser memory and is not uploaded. SHA-256 supports integrity comparison but does not prove provenance or authenticity.</p>'+
        '<label class="psv-file-label" for="evidence-file">Evidence file</label><input id="evidence-file" type="file"><p id="evidence-file-meta" class="psv-advanced-muted">No file selected.</p>'+
        '<div class="psv-advanced-actions"><button type="button" data-psv-action="hash-file">Calculate SHA-256</button><button type="button" data-psv-action="export-hash">Export integrity record (JSON)</button></div>'+
        '<pre id="evidence-output" class="psv-advanced-output" aria-live="polite">Select a file to begin.</pre><p class="psv-advanced-muted">For large forensic images, use validated forensic tooling and documented acquisition procedures.</p></section>';
    } else if (tool.id === "device") {
      body = '<section class="psv-advanced-panel psv-device-panel"><h2>Device evidence collection</h2><p>Browser collection is consent-based and local to this page. No hardware serials, IMEI, MAC addresses or covert fingerprint hashes are collected.</p>'+
        '<div class="psv-advanced-actions"><button type="button" data-psv-action="device-collect">Collect this browser profile</button><button type="button" data-psv-action="device-sample">Load sample profiles</button></div>'+
        '<label for="device-evidence">Evidence input — User-Agent, HTTP headers, browser profile, or Android/iOS app telemetry JSON</label><textarea id="device-evidence" rows="12" spellcheck="false" placeholder="Paste a User-Agent / HTTP headers, one structured profile, or a JSON array containing two profiles. Native evidence fields may include verified Play Integrity, App Attest / DeviceCheck, app version, installation ID, device-binding events and server session metadata."></textarea><p class="psv-advanced-muted">Native Android/iOS evidence is imported for analysis; this browser page cannot independently generate or validate Play Integrity, App Attest, DeviceCheck, MDM or server-side attestation verdicts.</p>'+
        '<div class="psv-advanced-actions"><button type="button" data-psv-action="device-analyze">Analyze evidence</button><button type="button" data-psv-action="device-clear">Clear</button><button type="button" data-psv-action="device-export">Download JSON report</button></div>'+
        '<div class="psv-device-disclosure"><strong>Evidence limitations:</strong> User-Agent and browser APIs are spoofable and may be reduced. Device model, CPU, memory and platform details may be unavailable. Network ASN, source IP, TLS fingerprints, registered device IDs and native-app attestation must be supplied by trusted server-side systems.</div>'+
        '<div id="device-output" class="psv-advanced-output" aria-live="polite">Collect a profile or paste evidence, then select Analyze evidence.</div></section>';
    } else if (tool.id === "share") {
      body = '<section class="psv-advanced-panel"><h2>Encrypt or decrypt an evidence package</h2><p>Encryption and decryption run locally using Web Crypto (AES-256-GCM with PBKDF2-SHA-256). The encrypted package is downloaded; PSV does not receive the content.</p>'+
        '<div class="psv-advanced-actions psv-share-modes"><button type="button" class="active" data-psv-action="share-mode" data-mode="encrypt">Encrypt package</button><button type="button" data-psv-action="share-mode" data-mode="decrypt">Decrypt package</button></div>'+
        '<label for="share-text">Text to encrypt (optional)</label><textarea id="share-text" rows="5" placeholder="Paste text for local encryption…"></textarea>'+
        '<label for="share-file">Or select a file to encrypt</label><input id="share-file" type="file">'+
        '<label for="share-package">Encrypted package (for decryption)</label><textarea id="share-package" rows="5" placeholder="Paste encrypted package JSON…"></textarea>'+
        '<label for="share-pass">Passphrase</label><input id="share-pass" type="password" autocomplete="new-password" placeholder="Use a unique, strong passphrase">'+
        '<div class="psv-advanced-actions"><button type="button" data-psv-action="share-run">Encrypt &amp; download package</button><button type="button" data-psv-action="share-clear">Clear fields</button></div>'+
        '<pre id="share-output" class="psv-advanced-output" aria-live="polite">Choose encrypt or decrypt, provide the required content and passphrase, then run the operation.</pre>'+
        '<p class="psv-advanced-muted">Share the passphrase through a separate approved channel. Lost passphrases cannot be recovered. Follow organisational evidence-transfer policies.</p></section>';
    }
    root.innerHTML = '<div id="psv-app" class="psv-workbench-v2"><div class="psv-tool-page">'+back+header+body+'</div></div>';
    attachToolSidebar(root, tool);
  }

  function psvDeviceParseUA(ua) {
    const value=String(ua||"");
    const pick=re=>{const m=value.match(re);return m?m[1]:null;};
    let os="Unknown",osVersion=null,deviceModel=null,deviceType="Unknown";
    if(/Android/i.test(value)){
      os="Android";osVersion=pick(/Android[\s/]([0-9.]+)/i);
      deviceModel=pick(/Android[^;]*;\s*([^;)]+?)(?:\s+Build|\)|;)/i);
      deviceType=/Mobile/i.test(value)?"Mobile":/Tablet/i.test(value)?"Tablet":"Unknown";
    } else if(/iPhone|iPad|iPod/i.test(value)){
      os="iOS/iPadOS";deviceModel=/iPad/i.test(value)?"iPad":/iPod/i.test(value)?"iPod":"iPhone";
      osVersion=pick(/OS ([0-9_]+)/i);if(osVersion)osVersion=osVersion.replace(/_/g,".");
      deviceType=deviceModel==="iPad"?"Tablet":"Mobile";
    } else if(/Windows NT/i.test(value)){
      os="Windows";const v=pick(/Windows NT ([0-9.]+)/i);
      osVersion=({"10.0":"Windows 10 or 11 (UA does not distinguish)","6.3":"8.1","6.2":"8","6.1":"7"}[v]||v);
      deviceType="Desktop";
    } else if(/Mac OS X/i.test(value)){
      os="macOS";osVersion=pick(/Mac OS X ([0-9_]+)/i);if(osVersion)osVersion=osVersion.replace(/_/g,".");deviceType="Desktop";
    } else if(/Linux/i.test(value)){os="Linux";deviceType=/Mobile/i.test(value)?"Mobile":"Desktop";}
    const candidates=[["Microsoft Edge",/(?:Edg|EdgA|EdgiOS)\/([0-9.]+)/],["Opera",/OPR\/([0-9.]+)/],["Samsung Internet",/SamsungBrowser\/([0-9.]+)/],["Firefox",/(?:Firefox|FxiOS)\/([0-9.]+)/],["Chrome",/(?:Chrome|CriOS)\/([0-9.]+)/],["Safari",/Version\/([0-9.]+).*Safari/]];
    let browser="Unknown",browserVersion=null;
    for(const [name,re] of candidates){const m=value.match(re);if(m){browser=name;browserVersion=m[1];break;}}
    const webviewTokens=["; wv)","Version/4.0","WebView","WKWebView"];
    const embeddedAppTokens=["FBAN","FBAV","Instagram","Line/","GSA/","TikTok"];
    const engineToken=/AppleWebKit\//.test(value)?"AppleWebKit token (does not distinguish WebKit from Blink)":/Gecko\//.test(value)?"Gecko token":null;
    return {raw:value,browser,browserVersion,os,osVersion,deviceModel,deviceType,engineToken,
      webViewLikely:webviewTokens.some(t=>value.toLowerCase().includes(t.toLowerCase())),
      embeddedAppTokens:embeddedAppTokens.filter(t=>value.toLowerCase().includes(t.toLowerCase())),
      architectureHint:/Win64|x86_64|amd64/i.test(value)?"64-bit hint":/i[3-6]86/i.test(value)?"32-bit hint":null,
      userAgentReductionCaveat:"UA strings may be reduced, generic, overridden or spoofed; model and OS-version inference is not authoritative."};
  }

  function psvDeviceCollect() {
    const n=navigator,sc=window.screen||{};
    const p={schema:"psv-device-profile",schemaVersion:2,collectedAt:new Date().toISOString(),evidenceOrigin:"browser-api-self-report",
      userAgent:n.userAgent||null,
      browser:{language:n.language||null,languages:Array.from(n.languages||[]),platform:n.platform||null,vendor:n.vendor||null,cookieEnabled:!!n.cookieEnabled,onLine:!!n.onLine},
      hardware:{logicalCpuCores:Number.isFinite(n.hardwareConcurrency)?n.hardwareConcurrency:null,approxDeviceMemoryGB:Number.isFinite(n.deviceMemory)?n.deviceMemory:null,maxTouchPoints:Number.isFinite(n.maxTouchPoints)?n.maxTouchPoints:null},
      display:{width:sc.width||null,height:sc.height||null,availableWidth:sc.availWidth||null,availableHeight:sc.availHeight||null,colorDepth:sc.colorDepth||null,pixelRatio:window.devicePixelRatio||null,orientation:sc.orientation&&sc.orientation.type||null},
      regional:{timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||null,utcOffsetMinutes:new Date().getTimezoneOffset()},
      capabilities:{webAssembly:typeof WebAssembly!=="undefined",webGL:(()=>{try{const c=document.createElement("canvas");return !!(c.getContext("webgl")||c.getContext("experimental-webgl"));}catch(_){return false;}})(),indexedDB:!!n.indexedDB,localStorage:(()=>{try{const k="__psv_probe";localStorage.setItem(k,"1");localStorage.removeItem(k);return true;}catch(_){return false;}})(),sessionStorage:(()=>{try{const k="__psv_probe";sessionStorage.setItem(k,"1");sessionStorage.removeItem(k);return true;}catch(_){return false;}})(),webdriver:n.webdriver===true},
      network:{connectionType:n.connection&&n.connection.effectiveType||null,downlinkMbps:n.connection&&n.connection.downlink||null,rttMs:n.connection&&n.connection.rtt||null,saveData:n.connection&&typeof n.connection.saveData==="boolean"?n.connection.saveData:null}};
    return p;
  }
  async function psvDeviceAddHints(profile) {
    const d=navigator.userAgentData;
    if(!d){profile.clientHints={available:false,reason:"User-Agent Client Hints API is not exposed by this browser."};return profile;}
    profile.clientHints={available:true,mobile:!!d.mobile,platform:d.platform||null,brands:Array.from(d.brands||[])};
    if(typeof d.getHighEntropyValues==="function"){try{profile.clientHints.highEntropy=await d.getHighEntropyValues(["architecture","bitness","model","platformVersion","fullVersionList","wow64"]);}catch(_){profile.clientHints.highEntropyStatus="Not permitted or unavailable";}}
    return profile;
  }
  function psvDeviceStable(value) {
    if(value===undefined)return "__PSV_UNDEFINED__";
    if(value===null||typeof value!=="object")return JSON.stringify(value);
    if(Array.isArray(value))return "["+value.map(psvDeviceStable).join(",")+"]";
    return "{"+Object.keys(value).sort().map(k=>JSON.stringify(k)+":"+psvDeviceStable(value[k])).join(",")+"}";
  }
  function psvDeviceFlatten(value,prefix,out) {
    out=out||{};prefix=prefix||"";
    if(value&&typeof value==="object"&&!Array.isArray(value)){
      Object.keys(value).forEach(k=>psvDeviceFlatten(value[k],prefix?prefix+"."+k:k,out));
    } else if(value!==undefined) out[prefix]=value;
    return out;
  }
  function psvDeviceRender(data) {
    const out=document.getElementById("device-output");if(!out)return;
    const status=data.verdict||"EVIDENCE REVIEW";
    const summary=data.summary||data.important||"Review the source and trust level of each supplied field.";
    const json=JSON.stringify(data,null,2);
    out.innerHTML='<section class="psv-device-report-head"><strong>'+esc(status)+'</strong><p>'+esc(summary)+'</p></section>'+
      (data.comparison?'<h3>Profile comparison</h3><div class="psv-device-comparison">'+data.comparison.map(x=>'<div class="psv-device-diff"><b>'+esc(x.field)+'</b><span>'+esc(x.status)+'</span><small>Profile A: '+esc(JSON.stringify(x.profileA))+'<br>Profile B: '+esc(JSON.stringify(x.profileB))+'</small></div>').join("")+'</div>':'')+
      '<details class="psv-device-raw"><summary>View complete JSON report</summary><pre>'+esc(json)+'</pre></details>'+
      '<p class="psv-advanced-muted">This is an evidence-triage aid, not a device-authentication or clone-detection system. Confirm findings using trusted server, MDM, app-attestation and bank telemetry.</p>';
    window.__psvLastDeviceReport=data;
  }
  function psvDeviceAnalyze(raw) {
    const input=String(raw||"").trim();if(!input)throw new Error("Paste evidence or collect a browser profile first.");
    let parsed;try{parsed=JSON.parse(input);}catch(_){parsed=null;}
    if(Array.isArray(parsed)){
      if(parsed.length<2)throw new Error("Provide at least two profile objects in a JSON array to compare.");
      const [a,b]=parsed;
      if(!a||typeof a!=="object"||!b||typeof b!=="object")throw new Error("Each comparison entry must be a JSON object.");
      const fa=psvDeviceFlatten(a),fb=psvDeviceFlatten(b);
      const fields=Array.from(new Set(Object.keys(fa).concat(Object.keys(fb)))).sort();
      const comparison=fields.map(field=>{
        const hasA=Object.prototype.hasOwnProperty.call(fa,field),hasB=Object.prototype.hasOwnProperty.call(fb,field);
        const status=!hasA||!hasB?"not comparable":psvDeviceStable(fa[field])===psvDeviceStable(fb[field])?"match":"different";
        return {field,profileA:hasA?fa[field]:null,profileB:hasB?fb[field]:null,status};
      });
      const compared=comparison.filter(x=>x.status!=="not comparable"),different=compared.filter(x=>x.status==="different").length;
      const verdict=compared.length===0?"INSUFFICIENT EVIDENCE":different?"INCONSISTENT PROFILES":"CONSISTENT ON SUPPLIED FIELDS";
      return {reportType:"device-evidence-comparison",generatedAt:new Date().toISOString(),verdict,
        summary:different?different+" comparable field(s) differ. These differences require contextual review; they do not establish cloning.":compared.length?"No differences were found among the comparable supplied fields. This does not authenticate the device.":"The profiles have no overlapping populated fields to compare.",
        profilesCompared:2,comparison,limitations:["Only the first two array entries are compared; submit pairs separately for larger sets.","Missing fields are not treated as matches.","Object key order is normalised before comparing values.","Browser/app supplied values can be spoofed or legitimately change after OS, app, browser, display or network updates.","A shared device identifier is not proof that the same physical device generated both sessions."],
        requiredCorroboration:["Server-side device registration and binding history","Native-app attestation verdict and integrity signals (where supported)","App installation identifier lifecycle and reset/reinstall history","Trusted edge IP, ASN, TLS/client fingerprint and session telemetry","Authentication, MFA, account recovery and transaction timeline","Device-management/MDM inventory where available"]};
    }
    if(parsed&&typeof parsed==="object"){
      const ua=parsed.userAgent||parsed.headers&& (parsed.headers["user-agent"]||parsed.headers["User-Agent"])||"";
      const flat=psvDeviceFlatten(parsed);
      const nativeKeys=Object.keys(flat).filter(k=>/(attest|integrity|playintegrity|devicecheck|appattest|installation|appversion|sdkversion|jailbreak|root|emulator|signing|certificate|deviceid|sessionid)/i.test(k));
      return {reportType:"structured-evidence-review",generatedAt:new Date().toISOString(),verdict:"INSUFFICIENT EVIDENCE",
        summary:"Structured evidence parsed. Review provenance: imported app/device fields are claims unless their source and integrity are independently verified.",
        parsedUserAgent:ua?psvDeviceParseUA(ua):null,profile:parsed,
        nativeAppEvidenceFieldsDetected:nativeKeys,
        evidenceTrustGuidance:{browserAndClientFields:"Client-reported; spoofable and not authoritative.",serverLogs:"Trusted only when collected from controlled systems with integrity and time synchronisation.",android:"Import backend-verified Play Integrity/API verdicts and app/device binding events; do not treat a client-posted JSON claim as a verified verdict.",ios:"Import backend-verified App Attest/DeviceCheck validation results and key lifecycle records; a client-posted assertion alone is not verified."},
        limitations:["JSON structure does not prove provenance or authenticity.","Do not paste secrets, access tokens, private keys, full payment-card data or unnecessary personal data."]};
    }
    if(/^Mozilla\//i.test(input)||/Android|Windows NT|iPhone|Macintosh|Linux/i.test(input)){
      return {reportType:"user-agent-review",generatedAt:new Date().toISOString(),verdict:"INSUFFICIENT EVIDENCE",summary:"A User-Agent string provides compatibility hints only; it cannot identify or authenticate a physical device.",parsedUserAgent:psvDeviceParseUA(input),
        limitations:["User-Agent is client-controlled and may be spoofed, overridden, reduced or generic.","Android model tokens are inconsistent and may be omitted.","iPhone/iPad UA strings generally do not disclose a precise hardware model.","Windows NT 10.0 does not distinguish Windows 10 from Windows 11.","An AppleWebKit token does not by itself establish whether the browser engine is WebKit or Blink."]};
    }
    const headers={};input.split(/\r?\n/).forEach(line=>{const i=line.indexOf(":");if(i>0)headers[line.slice(0,i).trim().toLowerCase()]=line.slice(i+1).trim();});
    const ua=headers["user-agent"]||"";
    return {reportType:"http-header-review",generatedAt:new Date().toISOString(),verdict:"INSUFFICIENT EVIDENCE",summary:"Parsed supplied request headers. Pasted headers are not independently authenticated.",
      parsedUserAgent:ua?psvDeviceParseUA(ua):null,
      selectedHeaders:Object.fromEntries(["accept-language","accept","accept-encoding","sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform","sec-ch-ua-model","sec-ch-ua-platform-version","sec-ch-ua-full-version-list"].filter(k=>headers[k]).map(k=>[k,headers[k]])),
      limitations:["Header values may be modified by clients, proxies or intermediaries.","IP/ASN, TLS fingerprints and authoritative session metadata should be taken from trusted edge/server logs."]};
  }

  async function runShare() {
    const output=document.getElementById("share-output");
    const app=document.getElementById("psv-app");
    const mode=app && app.dataset.shareMode==="decrypt" ? "decrypt" : "encrypt";
    const passphrase=fieldValue("share-pass");
    if(!output) return;
    if(!window.isSecureContext || !window.crypto || !crypto.subtle){output.textContent="Web Crypto is unavailable. Open this page over HTTPS in a supported browser.";return;}
    if(passphrase.length<14){output.textContent="Use a passphrase of at least 14 characters.";return;}
    const enc=new TextEncoder();
    const toB64=bytes=>{let binary="";const a=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);for(let i=0;i<a.length;i+=0x8000)binary+=String.fromCharCode(...a.subarray(i,i+0x8000));return btoa(binary);};
    const fromB64=value=>Uint8Array.from(atob(value),c=>c.charCodeAt(0));
    const deriveKey=async(salt,usages)=>{const material=await crypto.subtle.importKey("raw",enc.encode(passphrase),"PBKDF2",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:salt,iterations:310000,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,usages);};
    try {
      if(mode==="encrypt"){
        const fileInput=document.getElementById("share-file"),file=fileInput&&fileInput.files&&fileInput.files[0],txt=fieldValue("share-text");
        if(!file&&!txt){output.textContent="Enter text or select a file to encrypt.";return;}
        if(file&&file.size>10*1024*1024){output.textContent="This browser utility is limited to files up to 10 MB. Use approved managed transfer for larger evidence.";return;}
        const plaintext=file?new Uint8Array(await file.arrayBuffer()):enc.encode(txt);
        const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),key=await deriveKey(salt,["encrypt"]);
        const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv},key,plaintext));
        const pkg={format:"PSV-ENCRYPTED-PACKAGE",version:1,algorithm:"AES-256-GCM",kdf:"PBKDF2-SHA-256",iterations:310000,salt:toB64(salt),iv:toB64(iv),filename:file?file.name:"encrypted-text.txt",content_type:file?(file.type||"application/octet-stream"):"text/plain;charset=utf-8",payload:toB64(ciphertext)};
        downloadText("psv-encrypted-package.json",JSON.stringify(pkg,null,2),"application/json;charset=utf-8");
        output.textContent="Encryption successful. The encrypted package has been downloaded. Share the package and passphrase separately. No plaintext or key was sent to a server.";
      } else {
        const raw=fieldValue("share-package");
        if(!raw){output.textContent="Paste the encrypted package JSON first.";return;}
        const pkg=JSON.parse(raw);
        if(pkg.format!=="PSV-ENCRYPTED-PACKAGE"||pkg.version!==1||pkg.algorithm!=="AES-256-GCM"||pkg.kdf!=="PBKDF2-SHA-256"||pkg.iterations!==310000)throw new Error("Unsupported or invalid package format.");
        const salt=fromB64(pkg.salt),iv=fromB64(pkg.iv),ciphertext=fromB64(pkg.payload);
        if(salt.length!==16||iv.length!==12||ciphertext.length<16)throw new Error("Invalid package fields.");
        const key=await deriveKey(salt,["decrypt"]);
        const plaintext=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:iv},key,ciphertext));
        const filename=(pkg.filename||"decrypted-evidence.bin").replace(/[\\/:*?"<>|]/g,"_");
        downloadText(filename,plaintext,pkg.content_type||"application/octet-stream");
        output.textContent="Decryption successful. The decrypted file has been downloaded. Keep the passphrase and decrypted evidence protected.";
      }
    } catch(error) {
      console.error("[PSV Tools] Secure-share operation failed:",error);
      output.textContent=mode==="decrypt"?"Decryption failed. The package may be damaged, unsupported, or the passphrase may be incorrect.":"Encryption failed: "+(error&&error.message?error.message:String(error));
    }
  }

  function renderSingleToolView(root) {
    const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
    if (["case","share","evidence","device"].includes(tool.id)) { renderAdvancedTool(root,tool); return; }
    const currentInput = userInputs[tool.id] !== undefined ? userInputs[tool.id] : tool.sample;

    root.innerHTML = `
      <div id="psv-app">
        <div class="psv-tool-page">
          <div class="psv-back-bar">
            <button type="button" class="psv-back-btn" data-psv-action="back-catalog">← Back to All Tools (${TOOLS.length})</button>
          </div>

          <div class="psv-tool-hero">
            <h1>${esc(tool.title)}</h1>
            <p>${esc(tool.desc)}</p>
            <div class="psv-hero-badges">
              <span class="psv-pill-badge">${tool.id === "ti" ? "Server-side API lookup" : "Browser-based processing"}</span>
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
              <textarea id="psv-tool-editor" class="psv-editor" aria-label="Security tool input" spellcheck="false">${esc(currentInput)}</textarea>

              <div class="psv-action-bar">
                <div class="psv-opt-group">
                  ${(tool.options || []).map((opt, idx) => `
                    <button type="button" class="psv-opt-pill ${selectedOptionIdx === idx ? "active" : ""}" data-psv-action="set-opt" data-opt="${idx}">${esc(opt)}</button>
                  `).join("")}
                </div>

                <div class="psv-btn-group">
                  <button type="button" class="psv-btn-run" data-psv-action="run-tool">⚡ ${esc(tool.actionLabel)}</button>
                  <button type="button" class="psv-btn-util" data-psv-action="load-sample">Reset Sample</button>
                  <button type="button" class="psv-btn-util" data-psv-action="copy-output">Copy Output</button>
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

        </div>
      </div>
    `;
    attachToolSidebar(root, tool);
  }

  function getOrCreateSecondarySidebar() {
    let secondary = document.querySelector('.md-sidebar--secondary[data-md-type="toc"]') ||
      document.querySelector(".md-sidebar--secondary");
    if (secondary) return secondary;

    const main = document.querySelector(".md-main__inner");
    if (!main) return null;
    secondary = document.createElement("div");
    secondary.className = "md-sidebar md-sidebar--secondary";
    secondary.setAttribute("data-md-component", "sidebar");
    secondary.setAttribute("data-md-type", "toc");
    const scroll = document.createElement("div");
    scroll.className = "md-sidebar__scrollwrap";
    const inner = document.createElement("div");
    inner.className = "md-sidebar__inner";
    scroll.appendChild(inner);
    secondary.appendChild(scroll);
    main.appendChild(secondary);
    return secondary;
  }

  // One renderer owns category markup, ordering, counts, and active-state styling
  // for both Tools and Secure Share. The page mode only changes the navigation
  // control (in-app buttons versus real route links).
  function renderCategorySidebar({ selectedTool = null, secureSharePage = false } = {}) {
    const secondary = getOrCreateSecondarySidebar();
    if (!secondary) return;

    let inner = secondary.querySelector(".md-sidebar__inner");
    if (!inner) {
      const scroll = document.createElement("div");
      scroll.className = "md-sidebar__scrollwrap";
      inner = document.createElement("div");
      inner.className = "md-sidebar__inner";
      scroll.appendChild(inner);
      secondary.appendChild(scroll);
    }

    const groups = [
      { id: "soc", label: "SOC & Detection" },
      { id: "ti", label: "Threat Intelligence" },
      { id: "dfir", label: "DFIR & Forensics" },
      { id: "network", label: "Network & Email" },
      { id: "util", label: "Incident Utilities" }
    ];
    const activeId = secureSharePage ? "secure-transfer" : selectedTool && selectedTool.id;
    const activeCategory = secureSharePage ? "dfir" : selectedTool && selectedTool.cat;
    const nav = document.createElement("nav");
    nav.className = "md-nav md-nav--primary psv-tool-sidebar";
    nav.setAttribute("aria-label", "Tool categories");
    nav.innerHTML = `<label class="md-nav__title">Tool categories</label><div class="md-nav__list psv-category-accordion">
      ${groups.map(group => {
        const items = TOOLS.filter(tool => tool.cat === group.id);
        return `<details class="md-nav__item psv-category-group" ${group.id === activeCategory ? "open" : ""}>
          <summary class="md-nav__link"><span>${group.label}</span><span class="psv-vault-count">${items.length}</span></summary>
          <div class="md-nav psv-category-tools">${items.map(tool => {
            const isActive = tool.id === activeId;
            const label = esc(tool.shortTitle || tool.title);
            if (secureSharePage) {
              const href = isActive ? "/secure-share/" : `/tools/#tool/${encodeURIComponent(tool.id)}`;
              return `<a class="md-nav__link psv-sidebar-tool${isActive ? " active" : ""}" href="${href}" ${isActive ? 'aria-current="page"' : ""}>${label}</a>`;
            }
            return `<button type="button" class="md-nav__link psv-sidebar-tool ${isActive ? "active" : ""}" data-psv-action="open-tool" data-tool="${esc(tool.id)}" ${isActive ? 'aria-current="page"' : ""}>${label}</button>`;
          }).join("")}</div>
        </details>`;
      }).join("")}
      </div>`;
    inner.replaceChildren(nav);
    secondary.setAttribute("aria-label", "Tools categories");
  }

  function attachToolSidebar(root, selectedTool) {
    const app = root.querySelector("#psv-app");
    const page = app && app.querySelector(".psv-tool-page");
    if (!app || !page) return;
    renderCategorySidebar({ selectedTool });
    app.classList.remove("psv-tool-workspace-layout");
    page.classList.remove("psv-tool-workspace-main");
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

    window.addEventListener("click", async function (e) {
      const eventElement = e.target instanceof Element ? e.target : (e.target && e.target.parentElement);
      const target = eventElement && eventElement.closest ? eventElement.closest("#psv-app [data-psv-action], .psv-tool-sidebar [data-psv-action]") : null;
      if (!target) return;

      const action = target.getAttribute("data-psv-action");

      e.preventDefault();
      e.stopPropagation();

      if (action === "open-tool") {
        const tid = target.getAttribute("data-tool");
        if (tid === "secure-transfer") {
          window.location.assign("/secure-share/");
          return;
        }
        if (tid && TOOLS.some(t => t.id === tid)) {
          tiLookupSequence++;
          activeToolId = tid;
          selectedOptionIdx = 0;
          currentView = "tool";
          const nextHash = "#tool/" + encodeURIComponent(tid);
          try {
            if (window.location.hash !== nextHash) history.pushState({ tool: tid }, "", nextHash);
          } catch (err) {}
          render();
          window.scrollTo({ top: 0, behavior: "smooth" });
        }
      } else if (action === "back-catalog") {
        currentView = "tool"; activeToolId = "ioc";
        try { history.pushState({}, "", window.location.pathname); } catch (err) {}
        render(); window.scrollTo({ top: 0, behavior: "smooth" });
      } else if (action === "set-cat") {
        const first = TOOLS.find(t => t.cat === target.getAttribute("data-cat"));
        if (first) { activeToolId = first.id; currentView = "tool"; render(); }
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
      } else if (action === "export-case" || action === "copy-case") {
        const report=caseReport();
        const out=document.getElementById("case-output");
        if(out) out.textContent=report;
        if(action==="export-case") downloadText((document.getElementById("case-id").value||"incident-case").replace(/[^a-z0-9_-]/gi,"_")+".md",report,"text/markdown;charset=utf-8");
        else if(navigator.clipboard?.writeText) navigator.clipboard.writeText(report).then(()=>{if(out)out.textContent="Case report copied.\n\n"+report;}).catch(()=>{if(out)out.textContent="Clipboard unavailable. Use Download Markdown case report.";});
      } else if (action === "device-collect") {
        const field=document.getElementById("device-evidence"),out=document.getElementById("device-output");
        if(field&&out){out.textContent="Collecting browser-exposed characteristics…";try{const profile=await psvDeviceAddHints(psvDeviceCollect());field.value=JSON.stringify(profile,null,2);psvDeviceRender({analysisType:"live-browser-collection",profile,parsedUserAgent:psvDeviceParseUA(profile.userAgent),notice:"Collected locally. Review consent and data minimisation before using in an investigation."});}catch(err){out.textContent="Collection failed: "+err.message;}}
      } else if (action === "device-sample") {
        window.__psvLastDeviceReport=null;
        const field=document.getElementById("device-evidence");if(field)field.value=JSON.stringify([{evidenceOrigin:"synthetic-demo-only",sessionId:"DEMO-SESSION-A",deviceId:"DEMO-DEVICE-ID",userAgent:"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/131.0.0.0 Mobile Safari/537.36",browser:"Chrome",hardware:{logicalCpuCores:8},display:{width:412,height:915}},{evidenceOrigin:"synthetic-demo-only",sessionId:"DEMO-SESSION-B",deviceId:"DEMO-DEVICE-ID",userAgent:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",browser:"Chrome",hardware:{logicalCpuCores:12},display:{width:1920,height:1080}}],null,2);
      } else if (action === "device-analyze") {
        try{const field=document.getElementById("device-evidence");psvDeviceRender(psvDeviceAnalyze(field&&field.value));}catch(err){const out=document.getElementById("device-output");if(out)out.textContent=err.message;}
      } else if (action === "device-clear") {
        window.__psvLastDeviceReport=null;
        const field=document.getElementById("device-evidence"),out=document.getElementById("device-output");if(field)field.value="";if(out)out.textContent="Workspace cleared.";
      } else if (action === "device-export") {
        if(!window.__psvLastDeviceReport){const out=document.getElementById("device-output");if(out)out.textContent="Analyze or collect evidence before exporting.";return;}
        downloadText("psv-device-investigation.json",JSON.stringify(window.__psvLastDeviceReport,null,2),"application/json;charset=utf-8");
      } else if (action === "hash-file") {
        const file=document.getElementById("evidence-file")?.files[0],out=document.getElementById("evidence-output");
        if(!file||!out){if(out)out.textContent="Select a file first.";return;}
        if(file.size>100*1024*1024){out.textContent="File exceeds 100 MB. Use validated forensic tooling for large evidence files.";return;}
        out.textContent="Calculating SHA-256 locally…";
        try {
          const digest=await crypto.subtle.digest("SHA-256",await file.arrayBuffer());
          const hex=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("");
          lastHashRecord={filename:file.name,size_bytes:file.size,last_modified:new Date(file.lastModified).toISOString(),sha256:hex,calculated_at_utc:new Date().toISOString()};
          out.textContent="SHA-256: "+hex+"\nFile: "+file.name+"\nSize: "+file.size+" bytes\nCalculated (UTC): "+lastHashRecord.calculated_at_utc+"\n\nA digest supports integrity comparison; it does not prove provenance or authenticity.";
        } catch(e){out.textContent="Hash calculation failed: "+e.message;}
      } else if (action === "export-hash") {
        const out=document.getElementById("evidence-output");
        if(!lastHashRecord){if(out)out.textContent="Calculate a hash before exporting the record.";return;}
        downloadText("evidence-integrity-record.json",JSON.stringify(lastHashRecord,null,2),"application/json");
      } else if (action === "share-mode") {
        const app=document.getElementById("psv-app"); if(app) app.dataset.shareMode=target.getAttribute("data-mode")==="decrypt"?"decrypt":"encrypt";
        document.querySelectorAll("[data-psv-action='share-mode']").forEach(el=>el.classList.toggle("active",el===target));
        const run=document.querySelector("[data-psv-action='share-run']"); if(run)run.textContent=app?.dataset.shareMode==="decrypt"?"Decrypt package":"Encrypt & download package";
      } else if (action === "share-run") {
        await runShare();
      } else if (action === "share-clear") {
        ["share-file","share-text","share-pass","share-package"].forEach(id=>{const el=document.getElementById(id);if(el)el.value="";});
        const out=document.getElementById("share-output");if(out)out.textContent="Fields cleared.";
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
      } else if (e.target && e.target.id === "device-evidence") {
        window.__psvLastDeviceReport=null;
        const out=document.getElementById("device-output");if(out)out.textContent="Evidence changed. Analyze it again before exporting a report.";
      } else if (e.target && e.target.id === "evidence-file") {
        const file=e.target.files[0],meta=document.getElementById("evidence-file-meta");
        lastHashRecord=null;
        if(meta)meta.textContent=file?file.name+" · "+file.size+" bytes · last modified "+new Date(file.lastModified).toISOString():"No file selected.";
        const out=document.getElementById("evidence-output");if(out)out.textContent="File selected. Select Calculate SHA-256.";
      } else if (e.target && e.target.id === "psv-tool-editor") {
        const tool = TOOLS.find(t => t.id === activeToolId) || TOOLS[0];
        userInputs[tool.id] = e.target.value;
        if (tool.id === "ti") tiLookupSequence++;
        const out = document.getElementById("psv-tool-result-box");
        if (out) out.innerHTML = computeDynamicOutput(tool, e.target.value);
      }
    }, true);

    function syncToolRouteFromLocation() {
      const h = window.location.hash || "";
      if (h.startsWith("#tool/")) {
        const id = h.slice("#tool/".length).trim();
        if (TOOLS.some(t => t.id === id)) {
          activeToolId = id;
          currentView = "tool";
          render();
          return;
        }
      }
      currentView = "catalog";
      render();
    }
    // Support browser Back/Forward and direct/shared #tool/<id> links.
    window.addEventListener("popstate", syncToolRouteFromLocation);
    window.addEventListener("hashchange", syncToolRouteFromLocation);
  }

  function isSecureShareRoute() {
    const path = window.location.pathname.replace(/\/+$/, "");
    return path.endsWith("/secure-share");
  }

  function restoreNativeSecondaryToc() {
    const secondary = document.querySelector(".md-sidebar--secondary");
    const inner = secondary && secondary.querySelector(".md-sidebar__inner");
    const content = document.querySelector(".md-content__inner");
    if (!inner || !content || !inner.querySelector(".psv-tool-sidebar")) return;

    const headings = Array.from(content.querySelectorAll("h2[id],h3[id],h4[id],h5[id],h6[id]"))
      .filter((heading) => !heading.closest("[hidden]") && heading.getClientRects().length);
    const nav = document.createElement("nav");
    nav.className = "md-nav md-nav--secondary";
    nav.setAttribute("aria-label", "Page sections");
    const list = document.createElement("ul");
    list.className = "md-nav__list";

    headings.forEach((heading) => {
      const item = document.createElement("li");
      item.className = "md-nav__item";
      const link = document.createElement("a");
      link.className = "md-nav__link";
      link.href = "#" + encodeURIComponent(heading.id);
      link.textContent = heading.textContent.trim();
      item.appendChild(link);
      list.appendChild(item);
    });

    nav.appendChild(list);
    inner.replaceChildren(nav);
    secondary.setAttribute("aria-label", "Page sections");
  }

  function attachSecureShareSidebar() {
    if (!isSecureShareRoute()) {
      document.body.classList.remove("secure-share-page");
      restoreNativeSecondaryToc();
      return;
    }
    document.body.classList.add("secure-share-page");
    // Secure Share uses the same secondary-sidebar markup as Tools.
    // Load the shared stylesheet before rendering so category and child
    // navigation receive identical indentation, guide lines, and spacing.
    injectStyles();
    renderCategorySidebar({ secureSharePage: true });
  }

  function init() {
    // Mount the shared category renderer on Secure Share; Tools mounts it after its view renders.
    attachSecureShareSidebar();
    // The mount point is the reliable page identity. Do not depend on a
    // particular domain, trailing slash, or MkDocs URL canonicalisation.
    const root = getRoot();
    if (!root) return;
    try {
      const h = window.location.hash || "";
      if (h.startsWith("#tool/")) {
        let id = h.slice("#tool/".length);
        try { id = decodeURIComponent(id); } catch (_) {}
        id = id.trim();
        if (TOOLS.some(t => t.id === id)) {
          activeToolId = id;
          currentView = "tool";
        } else {
          currentView = "catalog";
        }
      } else {
        currentView = "tool";
        activeToolId = TOOLS.some(t => t.id === activeToolId) ? activeToolId : "ioc";
      }
      render();
      root.setAttribute("data-psv-mounted", "true");
    } catch (error) {
      console.error("[PSV Tools] Workspace initialisation failed:", error);
      const detail = error && (error.stack || error.message) ? String(error.stack || error.message) : String(error);
      root.innerHTML = '<section class="psv-init-error" role="alert"><h2>Security tools could not start</h2><p>The application encountered this startup error:</p><pre class="psv-init-error-detail"></pre><p>Please share the error text above when reporting this issue.</p><button type="button" onclick="window.location.reload()">Reload tools</button></section>';
      const detailNode = root.querySelector(".psv-init-error-detail");
      if (detailNode) detailNode.textContent = detail;
    }
  }

  // MkDocs Material instant navigation and ordinary browser page loads.
  if (typeof document$ !== "undefined" && document$ && typeof document$.subscribe === "function") {
    document$.subscribe(() => init());
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
  window.addEventListener("pageshow", init);
})();