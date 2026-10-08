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

    <svg
      class="psv-labs-reference-visual"
      viewBox="0 0 820 420"
      role="img"
      aria-label="Privacy Skill Vault laboratory workflow from build and testing through telemetry, detection, investigation and response"
    >

      <defs>

        <pattern
          id="psvReferenceGrid"
          width="24"
          height="24"
          patternUnits="userSpaceOnUse"
        >
          <path
            d="M24 0H0V24"
            fill="none"
            stroke="currentColor"
            stroke-width=".6"
            opacity=".08"
          />
        </pattern>

        <linearGradient
          id="psvBlueBase"
          x1="0"
          y1="0"
          x2="0"
          y2="1"
        >
          <stop offset="0%" stop-color="#FFFFFF" stop-opacity=".95"/>
          <stop offset="100%" stop-color="#DDEBFF" stop-opacity=".55"/>
        </linearGradient>

        <linearGradient
          id="psvCyanBase"
          x1="0"
          y1="0"
          x2="0"
          y2="1"
        >
          <stop offset="0%" stop-color="#FFFFFF" stop-opacity=".95"/>
          <stop offset="100%" stop-color="#D9FFFF" stop-opacity=".55"/>
        </linearGradient>

        <linearGradient
          id="psvPurpleBase"
          x1="0"
          y1="0"
          x2="0"
          y2="1"
        >
          <stop offset="0%" stop-color="#FFFFFF" stop-opacity=".95"/>
          <stop offset="100%" stop-color="#EEE2FF" stop-opacity=".6"/>
        </linearGradient>

        <filter
          id="psvReferenceGlow"
          x="-80%"
          y="-80%"
          width="260%"
          height="260%"
        >
          <feGaussianBlur stdDeviation="8"/>
        </filter>

        <filter
          id="psvReferenceSoftGlow"
          x="-80%"
          y="-80%"
          width="260%"
          height="260%"
        >
          <feGaussianBlur stdDeviation="3"/>
        </filter>

      </defs>


      <!-- =================================================
           BACKGROUND GRID
           ================================================= -->

      <rect
        x="8"
        y="8"
        width="804"
        height="404"
        rx="10"
        class="psv-reference-background"
      />

      <rect
        x="8"
        y="8"
        width="804"
        height="404"
        rx="10"
        class="psv-reference-grid"
      />


      <!-- =================================================
           BUILD / TEST
           ================================================= -->

      <g class="psv-reference-card">

        <rect
          x="22"
          y="55"
          width="142"
          height="155"
          rx="9"
          class="card"
        />

        <text x="38" y="79" class="card-label">
          BUILD / TEST
        </text>

        <line
          x1="38"
          y1="89"
          x2="148"
          y2="89"
          class="card-line"
        />

        <text x="57" y="116" class="item">
          Windows
        </text>

        <text x="57" y="143" class="item">
          Linux
        </text>

        <text x="57" y="170" class="item">
          Kali
        </text>

        <circle cx="43" cy="112" r="3" class="item-dot"/>
        <circle cx="43" cy="139" r="3" class="item-dot"/>
        <circle cx="43" cy="166" r="3" class="item-dot"/>

        <text x="38" y="193" class="item-sub">
          enterprise · attack
        </text>

      </g>


      <!-- =================================================
           TELEMETRY
           ================================================= -->

      <g class="psv-reference-card">

        <rect
          x="183"
          y="55"
          width="142"
          height="155"
          rx="9"
          class="card"
        />

        <text x="199" y="79" class="card-label">
          TELEMETRY
        </text>

        <line
          x1="199"
          y1="89"
          x2="309"
          y2="89"
          class="card-line"
        />

        <text x="218" y="116" class="item">
          Sysmon
        </text>

        <text x="218" y="143" class="item">
          Auditd
        </text>

        <text x="218" y="170" class="item">
          Suricata
        </text>

        <text x="218" y="197" class="item">
          Zeek
        </text>

        <circle cx="204" cy="112" r="3" class="item-dot"/>
        <circle cx="204" cy="139" r="3" class="item-dot"/>
        <circle cx="204" cy="166" r="3" class="item-dot"/>
        <circle cx="204" cy="193" r="3" class="item-dot"/>

      </g>


      <!-- =================================================
           FLOW 1
           ================================================= -->

      <path
        d="M164 132 H183"
        class="reference-arrow-line"
      />

      <path
        d="M176 126 L184 132 L176 138"
        class="reference-arrow"
      />


      <!-- =================================================
           DETECTION CORE
           ================================================= -->

      <g class="psv-reference-detection">

        <!-- glow -->

        <ellipse
          cx="409"
          cy="181"
          rx="82"
          ry="22"
          class="detection-glow"
        />

        <!-- upper rings -->

        <ellipse
          cx="409"
          cy="75"
          rx="51"
          ry="13"
          class="detection-ring"
        />

        <ellipse
          cx="409"
          cy="84"
          rx="51"
          ry="13"
          class="detection-ring secondary"
        />

        <!-- cylinder -->

        <ellipse
          cx="409"
          cy="102"
          rx="45"
          ry="14"
          class="server-top"
        />

        <rect
          x="364"
          y="102"
          width="90"
          height="78"
          class="server-body"
        />

        <ellipse
          cx="409"
          cy="180"
          rx="45"
          ry="14"
          class="server-bottom"
        />

        <!-- server layers -->

        <ellipse
          cx="409"
          cy="120"
          rx="42"
          ry="12"
          class="server-line"
        />

        <ellipse
          cx="409"
          cy="145"
          rx="42"
          ry="12"
          class="server-line"
        />

        <ellipse
          cx="409"
          cy="169"
          rx="42"
          ry="12"
          class="server-line"
        />

        <!-- lights -->

        <circle cx="386" cy="120" r="2.5" class="server-light"/>
        <circle cx="397" cy="120" r="2.5" class="server-light"/>
        <circle cx="408" cy="120" r="2.5" class="server-light"/>
        <circle cx="419" cy="120" r="2.5" class="server-light"/>
        <circle cx="430" cy="120" r="2.5" class="server-light"/>

        <circle cx="386" cy="145" r="2.5" class="server-light"/>
        <circle cx="397" cy="145" r="2.5" class="server-light"/>
        <circle cx="408" cy="145" r="2.5" class="server-light"/>
        <circle cx="419" cy="145" r="2.5" class="server-light"/>
        <circle cx="430" cy="145" r="2.5" class="server-light"/>

        <!-- platform -->

        <ellipse
          cx="409"
          cy="190"
          rx="70"
          ry="15"
          class="detection-platform-glow"
        />

        <ellipse
          cx="409"
          cy="188"
          rx="66"
          ry="13"
          class="detection-platform"
        />

        <text
          x="409"
          y="219"
          text-anchor="middle"
          class="detection-label"
        >
          DETECTION
        </text>

        <text
          x="409"
          y="235"
          text-anchor="middle"
          class="detection-sub"
        >
          Elastic · Wazuh
        </text>

      </g>


      <!-- =================================================
           FLOW 2
           ================================================= -->

      <path
        d="M325 132 H355"
        class="reference-arrow-line"
      />

      <path
        d="M348 126 L356 132 L348 138"
        class="reference-arrow"
      />


      <!-- =================================================
           INVESTIGATION
           ================================================= -->

      <g class="psv-reference-card">

        <rect
          x="493"
          y="55"
          width="142"
          height="155"
          rx="9"
          class="card investigation"
        />

        <text x="509" y="79" class="card-label">
          INVESTIGATE
        </text>

        <line
          x1="509"
          y1="89"
          x2="619"
          y2="89"
          class="card-line"
        />

        <text x="528" y="124" class="item">
          TheHive
        </text>

        <text x="528" y="160" class="item">
          MISP
        </text>

        <circle cx="514" cy="120" r="3" class="investigation-dot"/>
        <circle cx="514" cy="156" r="3" class="investigation-dot"/>

        <text x="509" y="193" class="item-sub">
          evidence · intelligence
        </text>

      </g>


      <!-- =================================================
           FLOW 3
           ================================================= -->

      <path
        d="M635 132 H665"
        class="reference-arrow-line"
      />

      <path
        d="M658 126 L666 132 L658 138"
        class="reference-arrow"
      />


      <!-- =================================================
           RESPONSE
           ================================================= -->

      <g class="psv-reference-card">

        <rect
          x="675"
          y="55"
          width="120"
          height="155"
          rx="9"
          class="card response"
        />

        <text x="691" y="79" class="card-label">
          RESPOND
        </text>

        <line
          x1="691"
          y1="89"
          x2="779"
          y2="89"
          class="card-line"
        />

        <text x="706" y="120" class="response-item">
          ✓ Evidence
        </text>

        <text x="706" y="151" class="response-item">
          ✓ Response
        </text>

        <text x="706" y="182" class="response-item">
          ✓ Validate
        </text>

      </g>


      <!-- =================================================
           LOWER LIFECYCLE
           ================================================= -->

      <path
        d="M96 238
           C96 275 96 287 135 287
           H190"
        class="lifecycle-line"
      />

      <path
        d="M724 238
           C724 275 724 287 685 287
           H630"
        class="lifecycle-line"
      />

      <path
        d="M190 281 L198 287 L190 293"
        class="lifecycle-arrow"
      />

      <path
        d="M630 281 L622 287 L630 293"
        class="lifecycle-arrow"
      />

      <text
        x="410"
        y="291"
        text-anchor="middle"
        class="lifecycle-text"
      >
        BUILD → TEST → OBSERVE → INVESTIGATE → RESPOND → VALIDATE
      </text>


      <!-- =================================================
           SMALL TECHNICAL MARKERS
           ================================================= -->

      <circle cx="35" cy="335" r="2" class="marker"/>
      <circle cx="47" cy="335" r="2" class="marker"/>
      <circle cx="59" cy="335" r="2" class="marker"/>

      <line
        x1="72"
        y1="335"
        x2="748"
        y2="335"
        class="technical-line"
      />

      <text
        x="35"
        y="356"
        class="technical-text"
      >
        SECURITY LAB / CONTROLLED ENVIRONMENT
      </text>

      <text
        x="785"
        y="356"
        text-anchor="end"
        class="technical-text"
      >
        PSV
      </text>

    </svg>

  </div>

</section>


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
