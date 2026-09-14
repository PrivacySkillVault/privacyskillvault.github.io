<style>
/* ==========================================================================
   PSV HOME PAGE — SELF-CONTAINED LANDING CANVAS & DESIGN SYSTEM
   Strictly scoped under .psv-home (Zero global selector leakage)
   ========================================================================== */

.psv-home {

  color: #E2E8F0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  position: relative;
  overflow-x: hidden;
  margin-top: calc(-1 * var(--psv-space-8, 32px)) !important;
  margin-bottom: calc(-1 * var(--psv-space-8, 32px)) !important;
  padding: 3.5rem 1.5rem 5rem 1.5rem;

}

.psv-home__container {
  max-width: 1200px;
  margin: 0 auto;
  box-sizing: border-box;
}

/* Hero Section */
.psv-home__hero {
  display: grid;
  grid-template-columns: 1.1fr 0.9fr;
  gap: 3rem;
  align-items: center;
  margin-bottom: 5rem;
}

.psv-home__hero-content {
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.psv-home__eyebrow {
  display: inline-block;
  color: #38BDF8;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 1.8px;
  text-transform: uppercase;
  margin-bottom: 0.75rem;
}

.psv-home__hero-title {
  font-size: 2.75rem;
  font-weight: 800;
  line-height: 1.15;
  color: #FFFFFF !important;
  margin: 0 0 1.25rem 0 !important;
  letter-spacing: -0.02em;
}

.psv-home__gradient-text {
  background: linear-gradient(135deg, #38BDF8 0%, #3B82F6 60%, #818CF8 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.psv-home__hero-desc {
  color: #94A3B8 !important;
  font-size: 1rem;
  line-height: 1.65;
  margin-bottom: 2rem !important;
  max-width: 540px;
}

.psv-home__hero-actions {
  display: flex;
  gap: 1rem;
  align-items: center;
  flex-wrap: wrap;
}

.psv-home__btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background-color: #2563EB;
  color: #FFFFFF !important;
  font-weight: 600;
  font-size: 0.875rem;
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  text-decoration: none !important;
  transition: background-color 0.2s, transform 0.15s;
  box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35);
}

.psv-home__btn-primary:hover {
  background-color: #1D4ED8;
  transform: translateY(-1px);
}

.psv-home__btn-secondary {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: rgba(15, 23, 42, 0.7);
  color: #E2E8F0 !important;
  border: 1px solid rgba(56, 189, 248, 0.25);
  font-weight: 600;
  font-size: 0.875rem;
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  text-decoration: none !important;
  transition: all 0.2s;
}

.psv-home__btn-secondary:hover {
  background: rgba(30, 41, 59, 0.9);
  border-color: rgba(56, 189, 248, 0.5);
  color: #FFFFFF !important;
}

.psv-home__hero-visual {
  background: rgba(11, 23, 54, 0.75);
  border: 1px solid rgba(56, 189, 248, 0.2);
  border-radius: 12px;
  overflow: hidden;
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6), 0 0 30px rgba(37, 99, 235, 0.15);
}

.psv-home__hero-visual-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1rem;
  background: rgba(5, 12, 33, 0.85);
  border-bottom: 1px solid rgba(56, 189, 248, 0.15);
}

.psv-home__hero-visual-dots {
  display: flex;
  gap: 6px;
}

.psv-home__hero-visual-dots span {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}

.psv-home__hero-visual-body {
  padding: 0.75rem 1.25rem;
}

/* Focus Areas */
.psv-home__section-header {
  text-align: center;
  margin-bottom: 2.75rem;
}

.psv-home__section-title {
  font-size: 1.85rem;
  font-weight: 700;
  color: #FFFFFF !important;
  margin: 0 0 0.5rem 0 !important;
}

.psv-home__section-subtitle {
  color: #94A3B8 !important;
  font-size: 0.875rem;
  margin: 0 auto !important;
  max-width: 600px;
}

.psv-home__focus-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1.75rem;
  margin-bottom: 5rem;
}

.psv-home__focus-card {
  background: rgba(11, 23, 54, 0.6);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  padding: 1.75rem;
  position: relative;
  overflow: hidden;
  transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
}

.psv-home__focus-card:hover {
  transform: translateY(-2px);
  border-color: rgba(56, 189, 248, 0.35);
  box-shadow: 0 12px 24px rgba(0, 0, 0, 0.4);
}

.psv-home__focus-card::before {
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
}

.psv-home__focus-card--blue::before { background: #38BDF8; }
.psv-home__focus-card--purple::before { background: #A855F7; }
.psv-home__focus-card--teal::before { background: #14B8A6; }

.psv-home__focus-icon {
  width: 44px;
  height: 44px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 1.25rem;
}

.psv-home__focus-card--blue .psv-home__focus-icon {
  background: rgba(56, 189, 248, 0.1);
  border: 1px solid rgba(56, 189, 248, 0.25);
  color: #38BDF8;
}

.psv-home__focus-card--purple .psv-home__focus-icon {
  background: rgba(168, 85, 247, 0.1);
  border: 1px solid rgba(168, 85, 247, 0.25);
  color: #A855F7;
}

.psv-home__focus-card--teal .psv-home__focus-icon {
  background: rgba(20, 184, 166, 0.1);
  border: 1px solid rgba(20, 184, 166, 0.25);
  color: #14B8A6;
}

.psv-home__focus-card h3 {
  font-size: 1.1rem;
  font-weight: 700;
  color: #FFFFFF !important;
  margin: 0 0 0.75rem 0 !important;
}

.psv-home__focus-card p {
  color: #94A3B8 !important;
  font-size: 0.825rem;
  line-height: 1.6;
  margin: 0 !important;
}

/* Architecture Section */
.psv-home__arch-panel {
  background: rgba(11, 23, 54, 0.65);
  border: 1px solid rgba(56, 189, 248, 0.25);
  border-radius: 14px;
  padding: 2.25rem;
  margin-bottom: 5rem;
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
}

.psv-home__mermaid-wrap {
  background: rgba(5, 12, 33, 0.85);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 10px;
  padding: 1.5rem 1rem;
  overflow-x: auto;
  margin-bottom: 2rem;
}

.psv-home__mermaid-wrap .mermaid {
  display: flex;
  justify-content: center;
  min-width: 860px;
}

.psv-home__lifecycle {
  background: rgba(15, 23, 42, 0.85);
  border: 1px solid rgba(56, 189, 248, 0.2);
  border-radius: 10px;
  padding: 1rem 1.5rem;
  margin-bottom: 2rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 0.75rem;
}

.psv-home__lifecycle-label {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.75rem;
  font-weight: 700;
  color: #38BDF8;
  letter-spacing: 1px;
  text-transform: uppercase;
}

.psv-home__lifecycle-steps {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
  font-size: 0.8rem;
  font-weight: 600;
  color: #E2E8F0;
}

.psv-home__lifecycle-sep {
  color: #38BDF8;
  opacity: 0.6;
}

.psv-home__layer-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1.25rem;
  margin-top: 1.75rem;
}

.psv-home__layer-card {
  background: rgba(15, 23, 42, 0.7);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 8px;
  padding: 1.25rem;
}

.psv-home__layer-card h4 {
  color: #38BDF8;
  font-size: 0.9rem;
  font-weight: 700;
  margin: 0 0 0.4rem 0 !important;
}

.psv-home__layer-card p {
  color: #94A3B8 !important;
  font-size: 0.8rem;
  line-height: 1.5;
  margin: 0 !important;
}

/* Methodology Section */
.psv-home__methodology {
  background: linear-gradient(135deg, rgba(11, 23, 54, 0.8) 0%, rgba(5, 12, 33, 0.95) 100%);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 14px;
  padding: 3rem 2.5rem;
  display: grid;
  grid-template-columns: 1fr 1px 1.4fr;
  gap: 2.5rem;
  align-items: center;
  margin-bottom: 5rem;
}

.psv-home__methodology-divider {
  background: rgba(255, 255, 255, 0.1);
  width: 1px;
  height: 100%;
}

.psv-home__methodology-title {
  font-size: 1.95rem;
  font-weight: 800;
  line-height: 1.2;
  color: #FFFFFF !important;
  margin: 0 0 1rem 0 !important;
}

.psv-home__methodology-sub {
  color: #38BDF8 !important;
  font-size: 0.9rem;
  font-weight: 600;
  line-height: 1.5;
  margin: 0 !important;
}

.psv-home__methodology-content {
  color: #94A3B8 !important;
  font-size: 0.875rem;
  line-height: 1.65;
}

.psv-home__checklist {
  list-style: none !important;
  padding: 0 !important;
  margin: 1rem 0 !important;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.psv-home__checklist li {
  display: flex;
  align-items: center;
  gap: 0.65rem;
  color: #E2E8F0 !important;
}

/* Reports Grid */
.psv-home__reports-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1.75rem;
  margin-bottom: 5rem;
}

.psv-home__report-card {
  background: rgba(11, 23, 54, 0.6);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  overflow: hidden;
  text-decoration: none !important;
  display: flex;
  flex-direction: column;
  transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
}

.psv-home__report-card:hover {
  transform: translateY(-3px);
  border-color: rgba(56, 189, 248, 0.35);
  box-shadow: 0 14px 28px rgba(0, 0, 0, 0.5);
}

.psv-home__report-thumbnail {
  height: 140px;
  background: #0B1736;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.psv-home__report-badge {
  position: absolute;
  top: 12px;
  left: 12px;
  background: rgba(15, 23, 42, 0.85);
  border: 1px solid rgba(56, 189, 248, 0.3);
  color: #38BDF8;
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.8px;
  padding: 3px 8px;
  border-radius: 4px;
  text-transform: uppercase;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.psv-home__report-body {
  padding: 1.25rem 1.5rem 1.5rem 1.5rem;
  flex: 1;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.psv-home__report-body h3 {
  color: #FFFFFF !important;
  font-size: 0.95rem;
  font-weight: 700;
  line-height: 1.4;
  margin: 0 0 1rem 0 !important;
}

.psv-home__report-meta {
  color: #64748B !important;
  font-size: 0.725rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

/* Footer */
.psv-home__footer {
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  padding: 2.5rem 0 1rem 0;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1.25rem;
  font-size: 0.75rem;
  color: #64748B;
}

.psv-home__footer-nav {
  display: flex;
  gap: 1.5rem;
}

.psv-home__footer-nav a {
  color: #94A3B8 !important;
  text-decoration: none !important;
  transition: color 0.15s;
}

.psv-home__footer-nav a:hover {
  color: #38BDF8 !important;
}

/* Streaming Simulated SOC Telemetry Widget */
.psv-home__stream-box {
  height: 220px;
  overflow-y: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.75rem;
  line-height: 1.65;
  padding: 0.5rem 0.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.psv-home__stream-box::-webkit-scrollbar {
  width: 5px;
}

.psv-home__stream-box::-webkit-scrollbar-thumb {
  background: rgba(56, 189, 248, 0.3);
  border-radius: 4px;
}

.psv-home__stream-entry {
  display: grid;
  grid-template-columns: 80px 100px 1fr;
  gap: 0.75rem;
  align-items: baseline;
  padding: 0.2rem 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
}

.psv-home__stream-time {
  color: #64748B;
}

.psv-home__stream-source {
  font-weight: 700;
  font-size: 0.7rem;
  letter-spacing: 0.5px;
  text-transform: uppercase;
}

.psv-home__stream-source--sysmon { color: #38BDF8; }
.psv-home__stream-source--suricata { color: #F59E0B; }
.psv-home__stream-source--auth { color: #10B981; }
.psv-home__stream-source--wazuh { color: #A855F7; }
.psv-home__stream-source--elastic { color: #EF4444; }
.psv-home__stream-source--zeek { color: #2DD4BF; }
.psv-home__stream-source--misp { color: #F472B6; }

.psv-home__stream-msg {
  color: #CBD5E1;
  word-break: break-word;
}

/* Responsive Rules */
@media (max-width: 960px) {
  .psv-home__hero {
    grid-template-columns: 1fr;
    gap: 2.5rem;
  }
  .psv-home__focus-grid,
  .psv-home__reports-grid {
    grid-template-columns: 1fr;
  }
  .psv-home__methodology {
    grid-template-columns: 1fr;
    padding: 2rem;
  }
  .psv-home__methodology-divider {
    display: none;
  }
}
</style>

<div class="psv-home">
  <div class="psv-home__container">

    <!-- 1. HERO SECTION -->
    <section class="psv-home__hero">
      <div class="psv-home__hero-content">
        <span class="psv-home__eyebrow">PRACTICAL SECURITY • OPERATIONAL INSIGHTS</span>
        <h1 class="psv-home__hero-title">
          Defensive Operations, Threat Analysis &amp; <span class="psv-home__gradient-text">Security Testing</span>
        </h1>
        <p class="psv-home__hero-desc">
          Documenting real-world SIEM workflows, fraud detection, and lab-based security experimentation. Focused on understanding why security controls fail, how alerts behave, and how systems perform under operational analysis.
        </p>
        <div class="psv-home__hero-actions">
          <a href="investigations/" class="psv-home__btn-primary">
            Explore Investigations →
          </a>
          <a href="labs/" class="psv-home__btn-secondary">
            View Lab Setups →
          </a>
        </div>
      </div>

      <!-- CLIENT-SIDE SIMULATED SOC EVENT STREAM WIDGET -->
      <div class="psv-home__hero-visual">
        <div class="psv-home__hero-visual-header">
          <div class="psv-home__hero-visual-dots">
            <span style="background: #EF4444;"></span>
            <span style="background: #F59E0B;"></span>
            <span style="background: #10B981;"></span>
          </div>
          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span style="display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #10B981; box-shadow: 0 0 6px #10B981;"></span>
            <span style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.675rem; color: #38BDF8; font-weight: 700; letter-spacing: 0.5px;">SOC EVENT STREAM — SIMULATED</span>
          </div>
        </div>
        <div style="padding: 0.75rem 1.25rem 0.25rem 1.25rem; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.7rem; color: #64748B; border-bottom: 1px solid rgba(255, 255, 255, 0.05); display: flex; justify-content: space-between;">
          <span>CLOCK: <strong id="psv-live-clock" style="color: #94A3B8;">--:--:--</strong></span>
          <span>DATE: <strong id="psv-live-date" style="color: #94A3B8;">----/--/--</strong></span>
        </div>
        <div class="psv-home__hero-visual-body">
          <div id="psv-soc-stream" class="psv-home__stream-box" aria-live="polite">
            <!-- Dynamically populated via client-side JavaScript -->
          </div>
        </div>
      </div>
    </section>

    <!-- 2. FOCUS AREAS -->
    <section>
      <div class="psv-home__section-header">
        <h2 class="psv-home__section-title">Focus Areas</h2>
        <p class="psv-home__section-subtitle">Core areas I work on and document through real-world analysis and lab testing.</p>
      </div>

      <div class="psv-home__focus-grid">
        <div class="psv-home__focus-card psv-home__focus-card--blue">
          <div class="psv-home__focus-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <h3>SOC &amp; Alert Triage</h3>
          <p>Deep-dives into event correlation, false-positive reduction, and mapping alert workflows against attack vectors. Focused on raw log telemetry across Windows Security Events, Auditd, and Sysmon.</p>
        </div>

        <div class="psv-home__focus-card psv-home__focus-card--purple">
          <div class="psv-home__focus-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 11c0 3.517-1.009 6.799-2.753 9.571m3.44-2.04l.053-.054A13.916 13.916 0 0016 11c0-2.222-.519-4.32-1.442-6.182M8.5 7.5c.343-1.2.98-2.28 1.838-3.17M12 2a10 10 0 1010 10A10 10 0 0012 2z"/></svg>
          </div>
          <h3>Fraud &amp; Anomaly Detection</h3>
          <p>Investigating account abuse patterns, operational anomalies, velocity spikes, and risk scoring logic to identify suspicious activity across application and transaction workflows.</p>
        </div>

        <div class="psv-home__focus-card psv-home__focus-card--teal">
          <div class="psv-home__focus-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2v7.31L4.15 19.3A2 2 0 005.86 22h12.28a2 2 0 001.71-2.7L14 9.31V2"/></svg>
          </div>
          <h3>Lab Experimentation</h3>
          <p>Building isolated lab environments (pfSense, Suricata, Elastic) to test network visibility, evaluate firewall rules, and observe real-time detection triggers.</p>
        </div>
      </div>
    </section>

    <!-- 3. INTEGRATED SECURITY LAB ARCHITECTURE -->
    <section class="psv-home__arch-panel">
      <div class="psv-home__topology-header">
        <div>
          <h2 style="font-size: 1.45rem; font-weight: 700; color: #FFFFFF; margin: 0 0 0.5rem 0;">Integrated Security Lab Architecture</h2>
          <p style="color: #94A3B8; font-size: 0.85rem; margin: 0; max-width: 600px; line-height: 1.5;">
            Logical capability architecture derived from the 30-phase security laboratory curriculum, illustrating telemetry collection, security operations, and operational resilience.
          </p>
        </div>
      </div>

      <!-- Security Lifecycle Strip -->
      <div class="psv-home__lifecycle">
        <span class="psv-home__lifecycle-label">Security Lifecycle:</span>
        <div class="psv-home__lifecycle-steps">
          <span>Build</span>
          <span class="psv-home__lifecycle-sep">→</span>
          <span>Attack</span>
          <span class="psv-home__lifecycle-sep">→</span>
          <span>Detect</span>
          <span class="psv-home__lifecycle-sep">→</span>
          <span>Investigate</span>
          <span class="psv-home__lifecycle-sep">→</span>
          <span>Respond</span>
          <span class="psv-home__lifecycle-sep">→</span>
          <span>Validate</span>
          <span class="psv-home__lifecycle-sep">→</span>
          <span>Operate</span>
        </div>
      </div>

      <!-- Logical Architecture Mermaid Diagram -->
      <div class="psv-home__mermaid-wrap">
```mermaid
flowchart TD
    subgraph S1["1. Virtual Lab Foundation"]
        VLP["Virtual Lab Platform\n(VMware / Hypervisor / Virtual Networks)"]
        FW["Network Control\n(pfSense Firewall Router)"]
        VLP --> FW
    end

    subgraph S2["2. Operational Environments & Controlled Activity"]
        ENT["Enterprise Environment\n(Active Directory / Windows / Linux)"]
        OFF["Offensive Simulation\n(Kali Linux / Penetration Testing Nodes)"]
        FW --> ENT
        FW --> OFF
        OFF -->|Controlled Lab Activity| ENV["Integrated Security Environment"]
        ENT --> ENV
    end

    subgraph S3["3. Security Visibility & Telemetry"]
        ET["Endpoint Telemetry\n(Sysmon / Auditd / Wazuh Agent)"]
        NT["Network Telemetry\n(Suricata IDS / Zeek)"]
        ENV -->|Host Activity| ET
        ENV -->|Network Traffic| NT
    end

    subgraph S4["4. Data & Log Pipeline"]
        PIPE["Log Collection & Forwarding\n(Filebeat / Winlogbeat / Logstash)"]
        ET --> PIPE
        NT --> PIPE
    end

    subgraph S5["5. Security Analytics & Detection"]
        ES["Elastic SIEM\n(Central Correlation & Analytics)"]
        WZ["Wazuh Manager & Security Platform\n(Host Analysis & EDR Management)"]
        PIPE --> ES
        PIPE --> WZ
    end

    subgraph S6["6. SOC Operations"]
        TH["TheHive\n(Case & Incident Management)"]
        MISP["MISP\n(Threat Intelligence Platform)"]
        SH["Shuffle\n(Security Workflow Automation)"]

        ES --> TH
        WZ --> TH
        ES --> MISP
        WZ --> MISP
        TH <--> SH
        MISP <--> SH
    end

    subgraph S7["7. Analysis & Investigation"]
        ACT["Detection Engineering / Incident Investigation / Threat Hunting"]
        TH --> ACT
        MISP --> ACT
        SH --> ACT
    end

    subgraph S8["8. Resilience & Operational Validation"]
        OPS["Monitoring, Backup & Disaster Recovery"]
        CAP["Enterprise Validation & Operations"]
        ACT --> OPS
        OPS --> CAP
    end

    classDef foundation fill:#0B1736,stroke:#2563EB,stroke-width:1.5px,color:#FFFFFF;
    classDef operational fill:#080E1A,stroke:#38BDF8,stroke-width:1px,color:#E2E8F0;
    classDef analytics fill:#050C21,stroke:#3B82F6,stroke-width:1.5px,color:#FFFFFF;
    classDef soc fill:#080E1A,stroke:#A855F7,stroke-width:1px,color:#E2E8F0;

    class VLP,FW foundation;
    class ENT,OFF,ENV,ET,NT,PIPE operational;
    class ES,WZ analytics;
    class TH,MISP,SH,ACT,OPS,CAP soc;

  </div>

  <p style="color: #CBD5E1; font-size: 0.85rem; line-height: 1.6; margin: 0 0 1.5rem 0;">
    Privacy Skill Vault Labs are built as an integrated security environment rather than a collection of isolated tutorials. The environment progresses from virtualization and enterprise infrastructure into security telemetry, offensive simulation, detection, investigation, threat intelligence, automation, resilience, and operational validation.
  </p>

  <!-- Architecture Layer Breakdown Cards -->
  <div class="psv-home__layer-grid">
    <div class="psv-home__layer-card">
      <h4>Foundation</h4>
      <p>Provides the virtualization, storage and networking platform on which the lab operates.</p>
    </div>
    <div class="psv-home__layer-card">
      <h4>Enterprise</h4>
      <p>Provides the systems and services that generate realistic authentication, process, network and operational activity.</p>
    </div>
    <div class="psv-home__layer-card">
      <h4>Visibility</h4>
      <p>Collects endpoint and network telemetry using the project's monitoring and logging components.</p>
    </div>
    <div class="psv-home__layer-card">
      <h4>Security Operations</h4>
      <p>Turns telemetry into detections, investigations, threat hunting and SOC workflows.</p>
    </div>
    <div class="psv-home__layer-card">
      <h4>Offensive Simulation</h4>
      <p>Produces controlled security activity that can be observed and detected.</p>
    </div>
    <div class="psv-home__layer-card">
      <h4>Intelligence &amp; Automation</h4>
      <p>Enriches security operations and automates selected workflows.</p>
    </div>
    <div class="psv-home__layer-card">
      <h4>Resilience</h4>
      <p>Monitors the environment and provides backup, recovery and operational validation.</p>
    </div>
  </div>
</section>

<!-- 4. OPERATIONAL METHODOLOGY -->
<section class="psv-home__methodology">
  <div>
    <h2 class="psv-home__methodology-title">Why Hands-On<br/>Lab Testing Matters</h2>
    <p class="psv-home__methodology-sub">Bridging the gap between theoretical security concepts and messy operational reality.</p>
  </div>

  <div class="psv-home__methodology-divider"></div>

  <div class="psv-home__methodology-content">
    <p style="margin-top: 0;">Much of cybersecurity content focuses heavily on theoretical concepts or simplified demonstrations that rarely reflect production environments. Real-world analysis is unpredictable:</p>
    <ul class="psv-home__checklist">
      <li>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
        Alerts can be extremely noisy and prone to false positives.
      </li>
      <li>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
        Logs are often incomplete, unparsed, or misconfigured.
      </li>
      <li>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
        Security tools behave differently depending on network architecture and logging depth.
      </li>
    </ul>
    <p style="margin-bottom: 0;">The goal of Privacy Skill Vault is not just to showcase clean, successful outcomes, but to document why configurations break, how alerts fire under stress, and how issues are systematically identified through structured analysis.</p>
  </div>
</section>

<!-- 5. RECENT TECHNICAL WRITE-UPS -->
<section>
  <div class="psv-home__section-header">
    <h2 class="psv-home__section-title">Latest Investigations &amp; Lab Reports</h2>
    <p class="psv-home__section-subtitle">Explore recent breakdowns of alert investigations, detection engineering notes, and security lab guides.</p>
  </div>

  <div class="psv-home__reports-grid">
    <a href="investigations/" class="psv-home__report-card">
      <div class="psv-home__report-thumbnail">
        <span class="psv-home__report-badge">SIEM INVESTIGATION</span>
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="1.5" opacity="0.35"><path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
      </div>
      <div class="psv-home__report-body">
        <h3>Investigating Privilege Escalation via Token Manipulation</h3>
        <div class="psv-home__report-meta">
          <span>May 18, 2026 • 12 min read</span>
          <span style="color: #38BDF8; font-weight: 700;">→</span>
        </div>
      </div>
    </a>

    <a href="investigations/" class="psv-home__report-card">
      <div class="psv-home__report-thumbnail">
        <span class="psv-home__report-badge">DETECTION ENGINEERING</span>
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="1.5" opacity="0.35"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div class="psv-home__report-body">
        <h3>Reducing False Positives in Windows Logon Alerts</h3>
        <div class="psv-home__report-meta">
          <span>May 12, 2026 • 10 min read</span>
          <span style="color: #38BDF8; font-weight: 700;">→</span>
        </div>
      </div>
    </a>

    <a href="labs/" class="psv-home__report-card">
      <div class="psv-home__report-thumbnail">
        <span class="psv-home__report-badge">LAB GUIDE</span>
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="1.5" opacity="0.35"><path d="M10 2v7.31L4.15 19.3A2 2 0 005.86 22h12.28a2 2 0 001.71-2.7L14 9.31V2"/></svg>
      </div>
      <div class="psv-home__report-body">
        <h3>Building a Detection Lab with pfSense, Suricata &amp; Elastic</h3>
        <div class="psv-home__report-meta">
          <span>May 7, 2026 • 15 min read</span>
          <span style="color: #38BDF8; font-weight: 700;">→</span>
        </div>
      </div>
    </a>
  </div>
</section>

<!-- 6. FOOTER -->
<footer class="psv-home__footer">
  <div>Copyright © 2026 Privacy Skill Vault. All rights reserved.</div>
  <nav class="psv-home__footer-nav">
    <a href="index.html">Home</a>
    <a href="learn/">Learn</a>
    <a href="labs/">Labs</a>
    <a href="investigations/">Investigations</a>
    <a href="tools/">Tools</a>
    <a href="blog/">Blog</a>
  </nav>
</footer>

  <script>
  (function () {
    function initializePSVHomeTelemetry() {
      const root = document.querySelector(".psv-home");
      if (!root) return;

      const clock = root.querySelector("#psv-live-clock");
      const date = root.querySelector("#psv-live-date");
      const stream = root.querySelector("#psv-soc-stream");

      if (!clock || !date || !stream) return;

      window.psvHomeTelemetryInitialized =
        window.psvHomeTelemetryInitialized || {
          timer: null,
          clockTimer: null,
          root: null
        };

      const state = window.psvHomeTelemetryInitialized;

      if (state.timer) {
        clearInterval(state.timer);
        state.timer = null;
      }

      if (state.clockTimer) {
        clearInterval(state.clockTimer);
        state.clockTimer = null;
      }

      state.root = root;

      const events = [
        ["SYSmon", "Process creation observed on endpoint"],
        ["Suricata", "Network signature matched controlled test traffic"],
        ["AUTH", "Windows authentication event received"],
        ["Wazuh", "Endpoint integrity event processed"],
        ["Elastic", "Security event indexed for correlation"],
        ["Zeek", "Network connection metadata received"],
        ["MISP", "Threat intelligence enrichment available"],
        ["SYSmon", "PowerShell activity observed in lab telemetry"],
        ["AUTH", "Account logon activity received"]
      ];

      function timestamp() {
        return new Date().toLocaleTimeString([], {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit"
        });
      }

      function updateClock() {
        const now = new Date();

        clock.textContent = now.toLocaleTimeString([], {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit"
        });

        date.textContent = now.toLocaleDateString([], {
          year: "numeric",
          month: "2-digit",
          day: "2-digit"
        });
      }

      function sourceClass(source) {
        return source.toLowerCase().replace(/[^a-z0-9]+/g, "-");
      }

      function appendEvent(index) {
        const [source, message] = events[index % events.length];

        const entry = document.createElement("div");
        entry.className = "psv-home__stream-entry";

        const time = document.createElement("span");
        time.className = "psv-home__stream-time";
        time.textContent = timestamp();

        const sourceElement = document.createElement("span");
        sourceElement.className =
          "psv-home__stream-source psv-home__stream-source--" +
          sourceClass(source);
        sourceElement.textContent = source;

        const messageElement = document.createElement("span");
        messageElement.className = "psv-home__stream-msg";
        messageElement.textContent = message;

        entry.appendChild(time);
        entry.appendChild(sourceElement);
        entry.appendChild(messageElement);

        stream.appendChild(entry);

        while (stream.children.length > 25) {
          stream.removeChild(stream.firstElementChild);
        }

        stream.scrollTop = stream.scrollHeight;
      }

      stream.innerHTML = "";

      // Exactly 9 initial simulated events.
      for (let i = 0; i < 9; i += 1) {
        appendEvent(i);
      }

      updateClock();

      state.clockTimer = setInterval(updateClock, 1000);

      let eventIndex = 9;
      state.timer = setInterval(function () {
        appendEvent(eventIndex);
        eventIndex += 1;
      }, 2800);
    }

    // Initial page load.
    if (document.readyState === "loading") {
      document.addEventListener(
        "DOMContentLoaded",
        initializePSVHomeTelemetry,
        { once: true }
      );
    } else {
      initializePSVHomeTelemetry();
    }

    // Support Material for MkDocs instant navigation without creating
    // duplicate timers.
    if (typeof document$ !== "undefined") {
      document$.subscribe(function () {
        initializePSVHomeTelemetry();
      });
    }
  })();
  </script>

</div>
