# Defensive Operations, Threat Analysis & Security Testing

<div style="background: rgba(11, 23, 54, 0.8); border: 1px solid var(--psv-border); border-radius: var(--psv-radius-lg); padding: var(--psv-space-6); margin-bottom: var(--psv-space-8);">
  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: var(--psv-space-6); align-items: center;">
    <div>
      <span style="color: var(--psv-accent); font-family: var(--psv-font-mono); font-size: 0.75rem; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: var(--psv-space-2); display: block;">
        PRACTICAL SECURITY • OPERATIONAL INSIGHTS
      </span>
      <h2 style="font-size: 1.75rem; font-weight: 800; line-height: 1.2; margin-top: 0; margin-bottom: var(--psv-space-4);">
        Defensive Operations, Threat Analysis &amp; <span style="color: var(--psv-primary);">Security Testing</span>
      </h2>
      <p style="color: var(--psv-text-muted); font-size: 0.875rem; line-height: 1.6; margin-bottom: var(--psv-space-6);">
        Documenting real-world SIEM workflows, fraud detection, and lab-based security experimentation. Focused on understanding why security controls fail, how alerts behave, and how systems perform under operational analysis.
      </p>
      <div style="display: flex; gap: var(--psv-space-4); flex-wrap: wrap;">
        <a href="investigations/" class="md-button md-button--primary">Explore Investigations →</a>
        <a href="labs/" class="md-button">View Lab Setups →</a>
      </div>
    </div>
    <div>
      <div style="background: #050C21; border: 1px solid var(--psv-border); border-radius: var(--psv-radius-md); padding: var(--psv-space-4); font-family: var(--psv-font-mono); font-size: 0.75rem; line-height: 1.6;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--psv-border); padding-bottom: var(--psv-space-2); margin-bottom: var(--psv-space-3);">
          <div style="display: flex; gap: 6px;">
            <span style="width: 10px; height: 10px; border-radius: 50%; background: #EF4444; display: inline-block;"></span>
            <span style="width: 10px; height: 10px; border-radius: 50%; background: #F59E0B; display: inline-block;"></span>
            <span style="width: 10px; height: 10px; border-radius: 50%; background: #10B981; display: inline-block;"></span>
          </div>
          <span style="color: var(--psv-text-muted); font-size: 0.65rem;">SOC Live Telemetry Feed</span>
        </div>
        <p style="color: var(--psv-accent); margin: 0 0 6px 0;"><span style="color: var(--psv-text-muted);">[2026-07-25 01:14:02]</span> SIEM_INGEST: Sysmon Event ID 1 (Process Creation)</p>
        <p style="color: var(--psv-warning); margin: 0 0 6px 0;"><span style="color: var(--psv-text-muted);">[ALERT]</span> Suspicious PowerShell Execution: <code>-NoP -NonI -W Hidden -e aX...</code></p>
        <p style="color: var(--psv-text-muted); margin: 0 0 6px 0;"><span style="color: var(--psv-text-muted);">[ANALYSIS]</span> Parent Image: <code>C:\Windows\System32\taskeng.exe</code> (Scheduled Task)</p>
        <p style="color: var(--psv-success); margin: 0;"><span style="color: var(--psv-text-muted);">[CORRELATION]</span> Matched Rule: <code>ATO_MFA_BYPASS_BEHAVIOR_09</code> (Risk Score: 85/100)</p>
      </div>
    </div>
  </div>
</div>

---

## Focus Areas

Core areas I work on and document through real-world analysis and lab testing.

<div class="psv-card-grid">
  <div class="psv-card">
    <div class="psv-card__meta">SOC &amp; Alert Triage</div>
    <h3 class="psv-card__title">SOC &amp; Alert Triage</h3>
    <p class="psv-card__body">
      Deep-dives into event correlation, false-positive reduction, and mapping alert workflows against attack vectors. Focused on raw log telemetry across Windows Security Events, Auditd, and Sysmon.
    </p>
  </div>

  <div class="psv-card">
    <div class="psv-card__meta">Fraud &amp; Anomaly Detection</div>
    <h3 class="psv-card__title">Fraud &amp; Anomaly Detection</h3>
    <p class="psv-card__body">
      Investigating account abuse patterns, operational anomalies, velocity spikes, and risk scoring logic to identify suspicious activity across application and transaction workflows.
    </p>
  </div>

  <div class="psv-card">
    <div class="psv-card__meta">Lab Experimentation</div>
    <h3 class="psv-card__title">Lab Experimentation</h3>
    <p class="psv-card__body">
      Building isolated lab environments (pfSense, Suricata, Elastic) to test network visibility, evaluate firewall rules, and observe real-time detection triggers.
    </p>
  </div>
</div>

---

## Lab Topology &amp; Telemetry Architecture

Simulating production conditions to analyze log fidelity, detection coverage, and alert latency across virtualized network segments.

<div style="display: flex; gap: var(--psv-space-4); margin-bottom: var(--psv-space-6); flex-wrap: wrap;">
  <div style="background: rgba(11, 23, 54, 0.9); border: 1px solid var(--psv-border); border-radius: var(--psv-radius-md); padding: 0.75rem 1rem; flex: 1; min-width: 200px;">
    <strong style="color: var(--psv-text); font-size: 0.8rem; display: block;">Network Visibility</strong>
    <span style="color: var(--psv-text-muted); font-size: 0.7rem;">pfSense, Suricata, Zeek telemetry</span>
  </div>
  <div style="background: rgba(11, 23, 54, 0.9); border: 1px solid var(--psv-border); border-radius: var(--psv-radius-md); padding: 0.75rem 1rem; flex: 1; min-width: 200px;">
    <strong style="color: var(--psv-text); font-size: 0.8rem; display: block;">Endpoint Telemetry</strong>
    <span style="color: var(--psv-text-muted); font-size: 0.7rem;">Windows Security Events, Sysmon, Auditd</span>
  </div>
  <div style="background: rgba(11, 23, 54, 0.9); border: 1px solid var(--psv-border); border-radius: var(--psv-radius-md); padding: 0.75rem 1rem; flex: 1; min-width: 200px;">
    <strong style="color: var(--psv-text); font-size: 0.8rem; display: block;">Ingestion Pipeline</strong>
    <span style="color: var(--psv-text-muted); font-size: 0.7rem;">Filebeat, Logstash into Elastic / Wazuh</span>
  </div>
</div>

<div style="background: var(--psv-surface); border: 1px solid var(--psv-border); border-radius: var(--psv-radius-md); padding: 1.5rem 1rem; overflow-x: auto;">
  <svg viewBox="0 0 950 260" style="width: 100%; min-width: 800px; height: auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
    <defs>
      <marker id="blue-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="#38BDF8" />
      </marker>
    </defs>
    <g transform="translate(40, 20)">
      <rect width="150" height="58" rx="8" fill="#0B1736" stroke="#2563EB" stroke-width="1.5"/>
      <text x="75" y="30" fill="#FFFFFF" text-anchor="middle" font-size="11" font-weight="700">Attack &amp;</text>
      <text x="75" y="44" fill="#FFFFFF" text-anchor="middle" font-size="11" font-weight="700">Traffic Sources</text>
    </g>
    <line x1="190" y1="49" x2="270" y2="49" stroke="#38BDF8" stroke-width="1.5" marker-end="url(#blue-arrow)"/>
    <g transform="translate(270, 20)">
      <rect width="140" height="58" rx="8" fill="#0B1736" stroke="#2563EB" stroke-width="1.5"/>
      <text x="70" y="30" fill="#FFFFFF" text-anchor="middle" font-size="11" font-weight="700">pfSense</text>
      <text x="70" y="44" fill="#FFFFFF" text-anchor="middle" font-size="11" font-weight="700">Firewall</text>
    </g>
    <line x1="410" y1="49" x2="550" y2="49" stroke="#38BDF8" stroke-width="1.5" marker-end="url(#blue-arrow)"/>
    <text x="480" y="41" fill="#94A3B8" text-anchor="middle" font-size="9" font-weight="600">SPAN / Mirror Port</text>
    <g transform="translate(550, 20)">
      <rect width="130" height="58" rx="8" fill="#0B1736" stroke="#2563EB" stroke-width="1.5"/>
      <text x="65" y="37" fill="#FFFFFF" text-anchor="middle" font-size="11" font-weight="700">Suricata IDS</text>
    </g>
    <line x1="680" y1="49" x2="740" y2="49" stroke="#38BDF8" stroke-width="1.5" marker-end="url(#blue-arrow)"/>
    <g transform="translate(740, 20)">
      <rect width="135" height="58" rx="8" fill="#0B1736" stroke="#2563EB" stroke-width="1.5"/>
      <text x="67" y="30" fill="#FFFFFF" text-anchor="middle" font-size="11" font-weight="700">Centralized</text>
      <text x="67" y="44" fill="#FFFFFF" text-anchor="middle" font-size="11" font-weight="700">SIEM</text>
    </g>
    <path d="M 340 78 L 340 140" fill="none" stroke="#38BDF8" stroke-width="1.5" marker-end="url(#blue-arrow)"/>
    <g transform="translate(240, 140)">
      <rect width="200" height="62" rx="8" fill="#0B1736" stroke="#2563EB" stroke-width="1.5"/>
      <text x="100" y="32" fill="#FFFFFF" text-anchor="middle" font-size="11" font-weight="700">Managed Host Endpoints</text>
      <text x="100" y="47" fill="#94A3B8" text-anchor="middle" font-size="10">Windows / Linux</text>
    </g>
    <path d="M 440 171 L 807 171 L 807 78" fill="none" stroke="#38BDF8" stroke-width="1.5" marker-end="url(#blue-arrow)"/>
    <text x="620" y="163" fill="#94A3B8" text-anchor="middle" font-size="9" font-weight="600">Sysmon &amp; Auditd Logs</text>
  </svg>
</div>

---

## Why Hands-On Lab Testing Matters

<div style="background: var(--psv-surface); border: 1px solid var(--psv-border); border-radius: var(--psv-radius-md); padding: var(--psv-space-6);">
  <p style="color: var(--psv-primary); font-weight: 600; margin-top: 0; margin-bottom: var(--psv-space-4);">
    Bridging the gap between theoretical security concepts and messy operational reality.
  </p>
  <p style="color: var(--psv-text-muted); font-size: 0.875rem; line-height: 1.6;">
    Much of cybersecurity content focuses heavily on theoretical concepts or simplified demonstrations that rarely reflect production environments. Real-world analysis is unpredictable:
  </p>
  <ul>
    <li><strong>Alerts can be extremely noisy</strong> and prone to false positives.</li>
    <li><strong>Logs are often incomplete</strong>, unparsed, or misconfigured.</li>
    <li><strong>Security tools behave differently</strong> depending on network architecture and logging depth.</li>
  </ul>
  <p style="color: var(--psv-text-muted); font-size: 0.875rem; line-height: 1.6; margin-bottom: 0;">
    The goal of Privacy Skill Vault is not just to showcase clean, successful outcomes, but to document why configurations break, how alerts fire under stress, and how issues are systematically identified through structured analysis.
  </p>
</div>

---

## Latest Investigations &amp; Lab Reports

Explore recent breakdowns of alert investigations, detection engineering notes, and security lab guides.

<div class="psv-card-grid">
  <div class="psv-card">
    <div class="psv-card__meta">SIEM INVESTIGATION • May 18, 2026</div>
    <h3 class="psv-card__title">Investigating Privilege Escalation via Token Manipulation</h3>
    <p class="psv-card__body">12 min read • Examining token impersonation access rights.</p>
    <a href="investigations/">Read Breakdown →</a>
  </div>

  <div class="psv-card">
    <div class="psv-card__meta">DETECTION ENGINEERING • May 12, 2026</div>
    <h3 class="psv-card__title">Reducing False Positives in Windows Logon Alerts</h3>
    <p class="psv-card__body">10 min read • Tuning correlation logic around service accounts.</p>
    <a href="investigations/">Read Breakdown →</a>
  </div>

  <div class="psv-card">
    <div class="psv-card__meta">LAB GUIDE • May 7, 2026</div>
    <h3 class="psv-card__title">Building a Detection Lab with pfSense, Suricata &amp; Elastic</h3>
    <p class="psv-card__body">15 min read • Multi-segment virtual lab routing and sensor setup.</p>
    <a href="labs/">View Lab Guide →</a>
  </div>
</div>
