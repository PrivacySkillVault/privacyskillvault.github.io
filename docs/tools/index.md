# Tactical Security Tools & Quick References

A collection of custom log parsers, detection rules (Sigma/YARA), and operational cheat sheets built for threat hunting, telemetry analysis, and incident response.

---

## Tool Categories

<div class="psv-card-grid">
  <div class="psv-card">
    <h2 style="font-size: 1rem; margin-top: 0; margin-bottom: var(--psv-space-2);">1. Custom Utility Scripts</h2>
    <p class="psv-card__body">
      Python and Bash automation scripts for parsing raw log formats, extracting IOCs, and enriching telemetry against threat feeds.
    </p>
    <strong style="color: var(--psv-text); font-size: 0.75rem; display: block; margin-bottom: var(--psv-space-2);">Featured Utilities:</strong>
    <ul>
      <li>Log field extractors</li>
      <li>PCAP header parsers</li>
      <li>Automated geohash / IP lookup tools</li>
    </ul>
  </div>

  <div class="psv-card">
    <h2 style="font-size: 1rem; margin-top: 0; margin-bottom: var(--psv-space-2);">2. Detection Rule Sets</h2>
    <p class="psv-card__body">
      Pre-compiled YARA and Sigma rules for identifying adversary techniques across Windows Event Logs, Linux Auditd, and WAF traffic.
    </p>
    <strong style="color: var(--psv-text); font-size: 0.75rem; display: block; margin-bottom: var(--psv-space-2);">Featured Rules:</strong>
    <ul>
      <li>Unsigned process execution</li>
      <li>Obfuscated command-line detection</li>
      <li>Credential stuffing behavioral signatures</li>
    </ul>
  </div>

  <div class="psv-card">
    <h2 style="font-size: 1rem; margin-top: 0; margin-bottom: var(--psv-space-2);">3. Operational Cheatsheets</h2>
    <p class="psv-card__body">
      High-value reference guides for day-to-day SOC triage, network packet analysis, and forensic artifact locations.
    </p>
    <strong style="color: var(--psv-text); font-size: 0.75rem; display: block; margin-bottom: var(--psv-space-2);">Featured References:</strong>
    <ul>
      <li>Essential Windows Event IDs</li>
      <li>Wireshark display filters</li>
      <li>tshark command-line syntax</li>
    </ul>
  </div>
</div>

---

## Tactical Code Snippets & Detection Rules

### Tool 1: Log Parser & IOC Extractor (`log_parser.py`)

* **Category:** Python Utility
* **Target:** Web / WAF Logs
* **Use Case:** IOC Extraction

```python
import re
import sys

def extract_iocs(log_line):
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_line)
    urls = re.findall(r'https?://[^\s]+', log_line)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', log_line)
    return {
        "ips": ips,
        "urls": urls,
        "hashes": hashes
    }

def parse_log_file(path):
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                iocs = extract_iocs(line)
                if any(iocs.values()):
                    print(iocs)
    except FileNotFoundError:
        print(f"File not found: {path}")
    except OSError as exc:
        print(f"Error reading log file: {exc}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 log_parser.py <path_to_log_file>")
    else:
        parse_log_file(sys.argv[1])
```

### Tool 2: Sigma Rule — Suspicious PowerShell Parent Process

- **Category:** Sigma Rule
- **Target:** Windows Event 4688 / Sysmon 1
- **Status:** Active

```yaml
title: Suspicious PowerShell Child Process Execution
id: f38a29a1-7e82-4c22-b98a-112233445566
status: experimental
description: Detects powershell.exe being spawned by unexpected parent processes like Microsoft Office, MSHTA, or WMI.
author: Privacy Skill Vault
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
            - '\mshta.exe'
            - '\wmiprvse.exe'
    condition: selection
falsepositives:
    - Custom administrative automation scripts (verify parent path)
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

## Quick Reference Cheatsheets

High-frequency operational metrics and filter syntaxes for quick lookup.

### Cheat Sheet A: Essential Windows Event IDs for SOC Analysts

| **Event ID** | **Provider / Log Source** | **Description & Triage Focus** |
| ------------ | ------------------------- | ------------------------------- |
| **4624** | Security | Successful Logon (Check Logon Type 3 for Network, 10 for RDP) |
| **4625** | Security | Failed Logon Attempt (Brute-force / Credential Stuffing indicator) |
| **4688** | Security | New Process Created (Inspect command line flags and parent process) |
| **4720** | Security | A user account was created (Check for unauthorized privilege escalation) |
| **4104** | PowerShell / Operational | Script Block Logging (Contains raw, un-obfuscated script code) |
| **1** | Sysmon | Process Creation (Includes File Hashes, Parent Command Line, User) |
| **3** | Sysmon | Network Connection (Binds process ID to destination IP and Port) |

### Cheat Sheet B: High-Value Wireshark / TShark Filters

| **Analysis Objective** | **Wireshark Display Filter Syntax** |
| -------------------------------------- | --------------------------------------------------------- |
| **HTTP POST Data (Form Submissions)** | `http.request.method == "POST"` |
| **DNS Queries for Suspicious Domains** | `dns.flags.response == 0 and dns.qry.name contains "xyz"` |
| **SYN Flood / Port Scan Traffic** | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| **Cleartext Credentials (Basic Auth)** | `http.authorization contains "Basic"` |
| **TLS Client Hello (JA3 Extraction)** | `tls.handshake.type == 1` |

## Operational Maintenance Notice

<div class="psv-card">
  <h3 style="margin-top: 0;">Help Expand the Tools Vault</h3>
  <p class="psv-card__body">
    Contribute useful scripts, detection rules, operational references, and other security tooling that can help make the vault more useful for practical security work.
  </p>
  <div style="display: flex; flex-wrap: wrap; gap: 10px; margin-top: var(--psv-space-4);">
    <a href="#" class="md-button">Contribute Tools</a>
    <a href="#" class="md-button">Request a Tool</a>
  </div>
</div>

[Explore the Tools Vault →](https://tools.privacyskillvault.com/){ .md-button .md-button--primary }
