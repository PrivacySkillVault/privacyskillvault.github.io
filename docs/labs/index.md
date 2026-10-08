<div class="psv-labs-page">

<section class="psv-labs-hero">

  <div class="psv-labs-hero__main">

    <p class="psv-labs-eyebrow psv-labs-label"><span class="psv-labs-eyebrow">HANDS-ON SECURITY LABS</span></p>

    <h1>
  Build. Test. <span class="psv-labs-heading-accent">Investigate.</span>
</h1>

    <p class="psv-labs-hero__lead">
      The Labs section brings together the hands-on environments, experiments,
      and practical exercises used to turn cybersecurity concepts into working skills.
    </p>

    <p class="psv-labs-hero__support">
      The environment is built as an integrated security laboratory — combining
      infrastructure, enterprise systems, defensive activity, telemetry, detection,
      investigation, automation, and operational validation.
    </p>

  </div>

          <div class="psv-labs-hero__visual">
  <div class="psv-labs-ops-console" role="img" aria-label="Lab Operations workflow showing build, attack, detect, investigate, respond and validate">
    <div class="psv-labs-ops-console__top">
      <span class="psv-labs-ops-dots" aria-hidden="true"><i></i><i></i><i></i></span>
      <span class="psv-labs-ops-console__title">LAB OPERATIONS</span>
      <span class="psv-labs-ops-console__status">CONTROLLED ENVIRONMENT</span>
    </div>

    <div class="psv-labs-ops-console__body">
      <div class="psv-labs-ops-track" aria-hidden="true"></div>

      <div class="psv-labs-ops-step">
        <span class="psv-labs-ops-step__num">01</span>
        <span class="psv-labs-ops-step__icon">▣</span>
        <strong>BUILD</strong>
        <small>Infrastructure</small>
      </div>

      <div class="psv-labs-ops-step">
        <span class="psv-labs-ops-step__num">02</span>
        <span class="psv-labs-ops-step__icon">⌁</span>
        <strong>ATTACK</strong>
        <small>Simulation</small>
      </div>

      <div class="psv-labs-ops-step psv-labs-ops-step--active">
        <span class="psv-labs-ops-step__num">03</span>
        <span class="psv-labs-ops-step__icon">⌕</span>
        <strong>DETECT</strong>
        <small>Telemetry</small>
      </div>

      <div class="psv-labs-ops-step">
        <span class="psv-labs-ops-step__num">04</span>
        <span class="psv-labs-ops-step__icon">◌</span>
        <strong>INVESTIGATE</strong>
        <small>Evidence</small>
      </div>

      <div class="psv-labs-ops-step">
        <span class="psv-labs-ops-step__num">05</span>
        <span class="psv-labs-ops-step__icon">↗</span>
        <strong>RESPOND</strong>
        <small>Action</small>
      </div>

      <div class="psv-labs-ops-step">
        <span class="psv-labs-ops-step__num">06</span>
        <span class="psv-labs-ops-step__icon">✓</span>
        <strong>VALIDATE</strong>
        <small>Repeat</small>
      </div>
    </div>

    <div class="psv-labs-ops-console__footer">
      <span>SIMULATE</span>
      <span>OBSERVE</span>
      <span>INVESTIGATE</span>
      <span>VALIDATE</span>
    </div>
  </div>
</div></section>


<!-- =====================================================
     INTEGRATED LAB ARCHITECTURE
     ===================================================== -->

<section class="psv-labs-section">

  <p class="psv-labs-section-label psv-labs-label"><span class="psv-labs-eyebrow">ONE CONNECTED ENVIRONMENT</span></p>

  <h2>Integrated Lab Architecture</h2>

  <p class="psv-labs-section-intro">
    The laboratory is designed as one connected environment, where activity
    in one part of the lab can become telemetry, evidence, and investigation
    elsewhere.
  </p>


  <div class="psv-labs-architecture">

    <div class="psv-labs-architecture__top">

      <div class="psv-labs-arch-box psv-labs-arch-box--wide">
        <span class="psv-labs-arch-label">EXTERNAL</span>
        <strong>Internet / WAN</strong>
        <small>Controlled connectivity</small>
      </div>

      <div class="psv-labs-arch-arrow">↓</div>

      <div class="psv-labs-arch-box psv-labs-arch-box--wide">
        <span class="psv-labs-arch-label">NETWORK CONTROL</span>
        <strong>pfSense</strong>
        <small>Routing · Segmentation · Firewall</small>
      </div>

    </div>


    <div class="psv-labs-arch-columns">

      <div class="psv-labs-arch-column psv-labs-arch-column--enterprise">

        <span class="psv-labs-arch-column-label">
          ENTERPRISE ENVIRONMENT
        </span>

        <div class="psv-labs-arch-item">
          <strong>Windows</strong>
          <span>Active Directory · Clients</span>
        </div>

        <div class="psv-labs-arch-item">
          <strong>Linux</strong>
          <span>Servers · Services</span>
        </div>

      </div>


      <div class="psv-labs-arch-column psv-labs-arch-column--attack">

        <span class="psv-labs-arch-column-label">
          ATTACK ENVIRONMENT
        </span>

        <div class="psv-labs-arch-item">
          <strong>Kali Linux</strong>
          <span>Security testing</span>
        </div>

        <div class="psv-labs-arch-item">
          <strong>Simulation</strong>
          <span>Controlled activity</span>
        </div>

      </div>


      <div class="psv-labs-arch-column psv-labs-arch-column--services">

        <span class="psv-labs-arch-column-label">
          SERVICES
        </span>

        <div class="psv-labs-arch-item">
          <strong>Applications</strong>
          <span>Lab services</span>
        </div>

        <div class="psv-labs-arch-item">
          <strong>Infrastructure</strong>
          <span>Core services</span>
        </div>

      </div>

    </div>


    <div class="psv-labs-architecture__flow">

      <div class="psv-labs-flow-title">
        SECURITY VISIBILITY
      </div>

      <div class="psv-labs-flow-grid">

        <div>
          <strong>System Activity</strong>
          <span>Endpoints &amp; network</span>
        </div>

        <div>
          <strong>Telemetry</strong>
          <span>Sysmon · Auditd · Suricata · Zeek</span>
        </div>

        <div>
          <strong>Centralization</strong>
          <span>Agents · Beats · Log pipeline</span>
        </div>

      </div>

    </div>


    <div class="psv-labs-architecture__flow">

      <div class="psv-labs-flow-title">
        SECURITY OPERATIONS
      </div>

      <div class="psv-labs-flow-grid psv-labs-flow-grid--four">

        <div>
          <strong>Elastic Security</strong>
          <span>SIEM &amp; analytics</span>
        </div>

        <div>
          <strong>Wazuh</strong>
          <span>Endpoint security</span>
        </div>

        <div>
          <strong>Suricata / Zeek</strong>
          <span>Network visibility</span>
        </div>

        <div>
          <strong>TheHive / MISP</strong>
          <span>Cases &amp; intelligence</span>
        </div>

      </div>

    </div>


    <div class="psv-labs-architecture__lifecycle">

      <span>BUILD</span>
      <i>→</i>
      <span>ATTACK</span>
      <i>→</i>
      <span>DETECT</span>
      <i>→</i>
      <span>INVESTIGATE</span>
      <i>→</i>
      <span>RESPOND</span>
      <i>→</i>
      <span>VALIDATE</span>

    </div>

  </div>

  <p class="psv-labs-architecture-note">
    Exact virtual networks, addressing, host configuration, and deployment
    procedures are documented inside the individual laboratory phases.
  </p>

</section>


<!-- =====================================================
     SEVEN LAB AREAS
     ===================================================== -->

<section class="psv-labs-section" id="lab-areas">

  <p class="psv-labs-section-label psv-labs-label"><span class="psv-labs-eyebrow">30 PHASES</span></p>

  <h2>The Seven Lab Areas</h2>

  <p class="psv-labs-section-intro">
    The complete laboratory is organized into seven connected areas covering
    the build, operation, testing, investigation, and validation of the environment.
  </p>


  <div class="psv-labs-areas">


    <details class="psv-labs-area">

      <summary>
        <span class="psv-labs-area__number">01</span>

        <span class="psv-labs-area__content">
          <small>PHASES 01–06</small>
          <strong>Foundation &amp; Lab Platform</strong>
          <em>
            Build the host platform, virtualization environment, storage,
            networking, and base operating systems.
          </em>
        </span>

        <span class="psv-labs-area__toggle">View phases</span>
      </summary>

      <div class="psv-labs-phase-list">
        <span>01 · Host Platform Preparation</span>
        <span>02 · VMware Workstation Pro Installation &amp; Configuration</span>
        <span>03 · Lab Storage &amp; Project Organization</span>
        <span>04 · Virtual Network Infrastructure</span>
        <span>05 · Base Operating System Installation</span>
        <span>06 · Base Operating System Configuration</span>
      </div>

    </details>


    <details class="psv-labs-area">

      <summary>
        <span class="psv-labs-area__number">02</span>

        <span class="psv-labs-area__content">
          <small>PHASES 07–10</small>
          <strong>Enterprise Infrastructure</strong>
          <em>
            Establish identity, Windows and Linux systems, services,
            clients, and the infrastructure required for security operations.
          </em>
        </span>

        <span class="psv-labs-area__toggle">View phases</span>
      </summary>

      <div class="psv-labs-phase-list">
        <span>07 · Active Directory &amp; Core Services</span>
        <span>08 · Enterprise Server Configuration</span>
        <span>09 · Windows Client Deployment</span>
        <span>10 · Linux Server Configuration</span>
      </div>

    </details>


    <details class="psv-labs-area">

      <summary>
        <span class="psv-labs-area__number">03</span>

        <span class="psv-labs-area__content">
          <small>PHASES 11–16</small>
          <strong>Security Visibility &amp; SOC</strong>
          <em>
            Introduce SIEM, endpoint telemetry, network monitoring,
            EDR, centralized logging, and SOC platform capabilities.
          </em>
        </span>

        <span class="psv-labs-area__toggle">View phases</span>
      </summary>

      <div class="psv-labs-phase-list">
        <span>11 · SIEM Platform Installation</span>
        <span>12 · Endpoint Telemetry Collection</span>
        <span>13 · Network Security Monitoring</span>
        <span>14 · Endpoint Detection &amp; Response (EDR)</span>
        <span>15 · Log Collection &amp; Centralization</span>
        <span>16 · SOC Platform Configuration</span>
      </div>

    </details>


    <details class="psv-labs-area">

      <summary>
        <span class="psv-labs-area__number">04</span>

        <span class="psv-labs-area__content">
          <small>PHASES 17–19</small>
          <strong>Offensive Security &amp; Simulation</strong>
          <em>
            Build the controlled offensive environment and generate
            security activity that can be observed and investigated.
          </em>
        </span>

        <span class="psv-labs-area__toggle">View phases</span>
      </summary>

      <div class="psv-labs-phase-list">
        <span>17 · Penetration Testing Platform</span>
        <span>18 · Vulnerable Lab Targets</span>
        <span>19 · Attack Simulation</span>
      </div>

    </details>


    <details class="psv-labs-area">

      <summary>
        <span class="psv-labs-area__number">05</span>

        <span class="psv-labs-area__content">
          <small>PHASES 20–22</small>
          <strong>Detection, Investigation &amp; Hunting</strong>
          <em>
            Turn telemetry into detections, investigations,
            and practical threat-hunting workflows.
          </em>
        </span>

        <span class="psv-labs-area__toggle">View phases</span>
      </summary>

      <div class="psv-labs-phase-list">
        <span>20 · Detection Engineering</span>
        <span>21 · Incident Investigation</span>
        <span>22 · Threat Hunting</span>
      </div>

    </details>


    <details class="psv-labs-area">

      <summary>
        <span class="psv-labs-area__number">06</span>

        <span class="psv-labs-area__content">
          <small>PHASES 23–27</small>
          <strong>Threat Intelligence, Automation &amp; Resilience</strong>
          <em>
            Connect intelligence, optional cyber-fraud activity,
            automation, monitoring, backup, and recovery.
          </em>
        </span>

        <span class="psv-labs-area__toggle">View phases</span>
      </summary>

      <div class="psv-labs-phase-list">
        <span>23 · Threat Intelligence Integration</span>
        <span>24 · Cyber Fraud Environment (Optional)</span>
        <span>25 · Security Automation</span>
        <span>26 · Monitoring &amp; Health Checks</span>
        <span>27 · Backup &amp; Recovery</span>
      </div>

    </details>


    <details class="psv-labs-area">

      <summary>
        <span class="psv-labs-area__number">07</span>

        <span class="psv-labs-area__content">
          <small>PHASES 28–30</small>
          <strong>Validation, Capstone &amp; Operations</strong>
          <em>
            Validate the environment, bring the components together,
            exercise the resulting capability, and maintain it operationally.
          </em>
        </span>

        <span class="psv-labs-area__toggle">View phases</span>
      </summary>

      <div class="psv-labs-phase-list">
        <span>28 · Enterprise Validation</span>
        <span>29 · Capstone Exercises</span>
        <span>30 · Operations &amp; Maintenance</span>
      </div>

    </details>

  </div>

</section>


<!-- =====================================================
     CTA
     ===================================================== -->

<section class="psv-labs-cta">

  <div>

    <p class="psv-labs-label"><span class="psv-labs-eyebrow">THE LAB ENVIRONMENT</span></p>


    <span>
      Explore the complete laboratory phases and detailed implementation
      documentation inside the Labs Vault.
    </span>

  </div>

  <a
    href="https://labs.privacyskillvault.com/"
    target="_blank"
    rel="noopener"
  >
    EXPLORE LAB PHASES →
  </a>

</section>


</div>
