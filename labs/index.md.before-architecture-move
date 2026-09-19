# Virtual Security Lab Architecture & Complete Setup Guide

A comprehensive, ground-up guide to building an isolated, dual-purpose SOC (Defensive) and Pentesting (Offensive) lab environment. From hypervisor deployment to telemetry pipelines and target node configurations.

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: var(--psv-space-4); margin-bottom: var(--psv-space-8);">
  <div class="psv-card">
    <strong style="color: var(--psv-text); display: block;">Hands-on Lab</strong>
    <span style="color: var(--psv-text-muted); font-size: 0.75rem;">Real-world simulations</span>
  </div>
  <div class="psv-card">
    <strong style="color: var(--psv-text); display: block;">SOC + Pentest</strong>
    <span style="color: var(--psv-text-muted); font-size: 0.75rem;">Dual purpose environment</span>
  </div>
  <div class="psv-card">
    <strong style="color: var(--psv-text); display: block;">End-to-end Guide</strong>
    <span style="color: var(--psv-text-muted); font-size: 0.75rem;">From setup to detection</span>
  </div>
  <div class="psv-card">
    <strong style="color: var(--psv-text); display: block;">Fully Isolated</strong>
    <span style="color: var(--psv-text-muted); font-size: 0.75rem;">Safe &amp; controlled testing</span>
  </div>
</div>

---

## Lab Network Architecture &amp; Subnet Mapping

Multi-segmented, isolated environment for safe offensive testing and defensive monitoring.

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: var(--psv-space-6); align-items: start; margin-bottom: var(--psv-space-8);">

  <div class="psv-card">
    <h3 style="font-size: 1rem; margin-top: 0; margin-bottom: var(--psv-space-2);">Lab Network Architecture</h3>
    <p style="font-size: 0.75rem; color: var(--psv-text-muted); margin-bottom: var(--psv-space-4);">Multi-segmented, isolated environment for safe offensive testing and defensive monitoring.</p>

    <div style="background: #050C21; padding: 1rem; border-radius: var(--psv-radius-md); border: 1px solid var(--psv-border); overflow-x: auto;">
      <svg viewBox="0 0 500 220" style="width: 100%; min-width: 400px; height: auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
        <rect x="200" y="15" width="100" height="32" rx="5" fill="#0B1736" stroke="#38BDF8" stroke-width="1.5"/>
        <text x="250" y="35" fill="#FFFFFF" text-anchor="middle" font-size="10" font-weight="bold">pfSense Router</text>

        <line x1="250" y1="47" x2="90" y2="105" stroke="#38BDF8" stroke-width="1.5" stroke-dasharray="3"/>
        <line x1="250" y1="47" x2="250" y2="105" stroke="#10B981" stroke-width="1.5"/>
        <line x1="250" y1="47" x2="410" y2="105" stroke="#EF4444" stroke-width="1.5"/>

        <rect x="20" y="105" width="140" height="70" rx="5" fill="#050C21" stroke="#38BDF8" stroke-width="1"/>
        <text x="90" y="125" fill="#38BDF8" text-anchor="middle" font-size="10" font-weight="bold">SOC Segment</text>
        <text x="90" y="145" fill="#94A3B8" text-anchor="middle" font-size="9">10.0.20.0/24</text>
        <text x="90" y="160" fill="#64748B" text-anchor="middle" font-size="8">SIEM / Suricata IDS</text>

        <rect x="180" y="105" width="140" height="70" rx="5" fill="#050C21" stroke="#10B981" stroke-width="1"/>
        <text x="250" y="125" fill="#10B981" text-anchor="middle" font-size="10" font-weight="bold">Target Endpoints</text>
        <text x="250" y="145" fill="#94A3B8" text-anchor="middle" font-size="9">10.0.30.0/24</text>
        <text x="250" y="160" fill="#64748B" text-anchor="middle" font-size="8">Win AD DC / Win 11 / Linux</text>

        <rect x="340" y="105" width="140" height="70" rx="5" fill="#050C21" stroke="#EF4444" stroke-width="1"/>
        <text x="410" y="125" fill="#EF4444" text-anchor="middle" font-size="10" font-weight="bold">Attack Segment</text>
        <text x="410" y="145" fill="#94A3B8" text-anchor="middle" font-size="9">10.0.40.0/24</text>
        <text x="410" y="160" fill="#64748B" text-anchor="middle" font-size="8">Kali Linux / Commando VM</text>
      </svg>
    </div>
  </div>

  <div class="psv-card">
    <h3 style="font-size: 1rem; margin-top: 0; margin-bottom: var(--psv-space-2);">Lab Subnet Mapping</h3>

    | Network Segment | Subnet / VLAN | Purpose |
    | :--- | :--- | :--- |
    | **WAN / Gateway** | `192.168.1.0/24` | Internet Egress |
    | **DMZ / Perimeter** | `10.0.10.0/24` | Public Services |
    | **Internal LAN / SOC** | `10.0.20.0/24` | Security Operations |
    | **Target Endpoints** | `10.0.30.0/24` | Victim Nodes |
    | **Attack Segment** | `10.0.40.0/24` | Isolated Testing |

    <h4 style="font-size: 0.875rem; color: var(--psv-text); margin-top: var(--psv-space-4); margin-bottom: var(--psv-space-2);">Key Objectives</h4>
    <ul>
      <li>Isolate attack traffic from SOC infrastructure</li>
      <li>Monitor all target network telemetry</li>
      <li>Practice real-world detection &amp; response</li>
      <li>Stay fully offline or controlled egress</li>
    </ul>
  </div>

</div>

---

## Step by Step Lab Setup Guide

<div style="display: flex; flex-direction: column; gap: var(--psv-space-4); margin-bottom: var(--psv-space-8);">

  <div class="psv-card">
    <h3 style="font-size: 1rem; color: var(--psv-accent); margin-top: 0; margin-bottom: var(--psv-space-2);">
      01. Phase 1: Hypervisor &amp; Virtual Network Core
    </h3>
    <p style="font-size: 0.8rem; color: var(--psv-text-muted); margin-bottom: var(--psv-space-4);">
      Build the foundation – VMware Workstation Pro, network segmentation, and pfSense firewall routing.
    </p>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: var(--psv-space-4); font-size: 0.8rem; color: var(--psv-text-muted);">
      <div>
        <strong style="color: var(--psv-text); display: block; margin-bottom: var(--psv-space-2);">VMware Workstation Pro Setup:</strong>
        <ul>
          <li>Install VMware Workstation Pro</li>
          <li>Configure VMnet0, VMnet1, VMnet2, VMnet3</li>
          <li>Disable VMware DHCP for isolated segments</li>
        </ul>
      </div>
      <div>
        <strong style="color: var(--psv-text); display: block; margin-bottom: var(--psv-space-2);">pfSense Firewall Installation &amp; Interfaces:</strong>
        <ul style="font-family: var(--psv-font-mono);">
          <li>em0 -> WAN (DHCP)</li>
          <li>em1 -> LAN (10.0.20.1/24)</li>
          <li>em2 -> OPT1 (10.0.30.1/24)</li>
          <li>em3 -> OPT2 (10.0.40.1/24)</li>
        </ul>
      </div>
    </div>
  </div>

  <div class="psv-card">
    <h3 style="font-size: 1rem; color: var(--psv-accent); margin-top: 0; margin-bottom: var(--psv-space-2);">
      02. Phase 2: Defensive Telemetry &amp; SOC Infrastructure
    </h3>
    <p style="font-size: 0.8rem; color: var(--psv-text-muted); margin: 0;">
      Deploy Suricata IDS, Elastic/Wazuh SIEM, and configure log ingestion pipelines.
    </p>
  </div>

  <div class="psv-card">
    <h3 style="font-size: 1rem; color: var(--psv-accent); margin-top: 0; margin-bottom: var(--psv-space-2);">
      03. Phase 3: Monitored Target Endpoints
    </h3>
    <p style="font-size: 0.8rem; color: var(--psv-text-muted); margin: 0;">
      Setup Windows AD/Windows 11 and Linux endpoints with Sysmon, Auditd, and agent shipping.
    </p>
  </div>

  <div class="psv-card">
    <h3 style="font-size: 1rem; color: var(--psv-accent); margin-top: 0; margin-bottom: var(--psv-space-2);">
      04. Phase 4: Isolated Offensive Testing Node
    </h3>
    <p style="font-size: 0.8rem; color: var(--psv-text-muted); margin: 0;">
      Deploy Kali Linux and validate attacks to verify end-to-end detection.
    </p>
  </div>

</div>

---

## Lab Stack &amp; Key Components

Technologies and tools powering the complete lab environment:

<div class="psv-card-grid">
  <div class="psv-card">
    <h3 class="psv-card__title">VMware Workstation Pro</h3>
    <p class="psv-card__body">Virtualization platform for multi-segment lab deployment.</p>
  </div>
  <div class="psv-card">
    <h3 class="psv-card__title">pfSense</h3>
    <p class="psv-card__body">Network routing, segmentation and traffic control.</p>
  </div>
  <div class="psv-card">
    <h3 class="psv-card__title">Elastic Stack</h3>
    <p class="psv-card__body">Centralized log collection, search and visualization.</p>
  </div>
  <div class="psv-card">
    <h3 class="psv-card__title">Wazuh</h3>
    <p class="psv-card__body">Open-source SIEM for threat detection and monitoring.</p>
  </div>
  <div class="psv-card">
    <h3 class="psv-card__title">Suricata</h3>
    <p class="psv-card__body">Network intrusion detection and traffic analysis.</p>
  </div>
  <div class="psv-card">
    <h3 class="psv-card__title">Sysmon</h3>
    <p class="psv-card__body">Deep Windows process and event monitoring.</p>
  </div>
  <div class="psv-card">
    <h3 class="psv-card__title">Filebeat / Winlogbeat</h3>
    <p class="psv-card__body">Log shipping to SIEM backend.</p>
  </div>
  <div class="psv-card">
    <h3 class="psv-card__title">Kali Linux</h3>
    <p class="psv-card__body">Offensive security testing and attack simulation.</p>
  </div>
</div>

---

## Downloadable Configurations

Ready-to-use configuration files for quick setup:

<div class="psv-card-grid">
  <div class="psv-card">
    <code style="font-weight: 700; color: var(--psv-text); display: block; margin-bottom: 4px;">sysmonconfig.xml</code>
    <span style="font-size: 0.75rem; color: var(--psv-text-muted);">Windows Endpoint</span>
  </div>
  <div class="psv-card">
    <code style="font-weight: 700; color: var(--psv-text); display: block; margin-bottom: 4px;">suricata.yaml</code>
    <span style="font-size: 0.75rem; color: var(--psv-text-muted);">Network IDS</span>
  </div>
  <div class="psv-card">
    <code style="font-weight: 700; color: var(--psv-text); display: block; margin-bottom: 4px;">audit.rules</code>
    <span style="font-size: 0.75rem; color: var(--psv-text-muted);">Linux Endpoint</span>
  </div>
  <div class="psv-card">
    <code style="font-weight: 700; color: var(--psv-text); display: block; margin-bottom: 4px;">filebeat.yml</code>
    <span style="font-size: 0.75rem; color: var(--psv-text-muted);">Log Shipping</span>
  </div>
</div>

---

## Build Your Own Cybersecurity Lab

Follow the complete guide, customize for your needs, and start hands-on security testing.

[Explore the Labs Vault →](https://labs.privacyskillvault.com/){ .md-button .md-button--primary }
