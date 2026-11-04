---
title: Secure Share
---

<style>
body.secure-share-page .md-content__inner>h1:first-child{display:none}
#secure-share-layout{display:grid!important;grid-template-columns:minmax(0,1fr) 245px!important;grid-template-rows:auto;gap:1.5rem;align-items:start;width:100%;max-width:100%;margin:0;padding:0 0 2rem}
#secure-share-main{display:block;grid-column:1;grid-row:1;min-width:0;width:100%;max-width:100%}
#secure-share-heading{display:none}
#secure-share-heading .eyebrow{display:block;margin:0 0 .35rem;color:var(--md-accent-fg-color);font:700 .68rem/1.4 "Roboto Mono",monospace;letter-spacing:.1em;text-transform:uppercase}
#secure-share-heading h1{margin:0 0 .45rem;font-size:1.8rem;font-weight:700;letter-spacing:-.02em;color:var(--md-default-fg-color)}
#secure-share-heading p{margin:0;color:var(--md-default-fg-color--light);font-size:.9rem;line-height:1.65}
#secure-share-frame{display:block;width:100%;height:1080px;min-height:820px;border:1px solid var(--md-default-fg-color--lightest);border-radius:10px;background:var(--md-default-bg-color)}
#secure-share-categories{display:block;grid-column:2;grid-row:1;width:245px;min-width:0;position:sticky;top:1.25rem;max-height:calc(100vh - 2.5rem);overflow:auto}
#secure-share-categories .psv-tool-sidebar{padding:0!important;border:0!important;background:transparent!important}
#secure-share-categories .psv-tool-sidebar>.md-nav__title{display:block;margin:0 0 .65rem;padding:.0 .2rem;color:var(--md-default-fg-color);font-size:.78rem;font-weight:700}
#secure-share-categories .psv-category-group{margin:.15rem 0;border-bottom:1px solid var(--md-default-fg-color--lightest)}
#secure-share-categories .psv-category-group>summary{display:flex;align-items:center;justify-content:space-between;gap:.5rem;padding:.55rem .2rem;cursor:pointer;font:inherit;font-size:.8rem;font-weight:600;list-style:none}
#secure-share-categories .psv-category-group>summary::-webkit-details-marker{display:none}
#secure-share-categories .psv-category-tools{padding:.1rem 0 .45rem .6rem}
#secure-share-categories .psv-sidebar-tool{display:block;width:100%;margin:0;border:0;padding:.2rem .6rem;border-radius:4px;background:transparent;color:var(--md-default-fg-color--light);font:inherit;font-size:.78rem;line-height:1.4;text-align:left;text-decoration:none;cursor:pointer}
#secure-share-categories .psv-sidebar-tool:hover,#secure-share-categories .psv-sidebar-tool.active{background:var(--md-default-bg-color);color:var(--md-accent-fg-color)}
#secure-share-categories .psv-sidebar-tool.active{font-weight:650}
#secure-share-categories .psv-vault-count{margin-left:auto;padding-left:.5rem;color:var(--md-default-fg-color--light);font:inherit;font-size:.85em}
@media(max-width:900px){#secure-share-layout{grid-template-columns:minmax(0,1fr)!important}#secure-share-main{grid-column:1;grid-row:1}#secure-share-categories{grid-column:1;grid-row:2;width:100%;position:static;max-height:none}}
@media(max-width:560px){#secure-share-frame{height:1180px;min-height:900px}}
</style>

<div id="secure-share-layout">
  <main id="secure-share-main">
    <iframe
      id="secure-share-frame"
      title="Privacy Skill Vault Secure Share workspace"
      loading="eager"
      referrerpolicy="no-referrer"
      allow="clipboard-read; clipboard-write"
    ></iframe>
  </main>

  <aside id="secure-share-categories" class="md-sidebar md-sidebar--secondary" aria-label="Tools categories">
    <div class="md-sidebar__scrollwrap">
      <div class="md-sidebar__inner">
        <nav class="md-nav md-nav--secondary psv-tool-sidebar" aria-label="Tool categories">
          <label class="md-nav__title">Tool categories</label>
          <div class="md-nav__list psv-category-accordion">
            <details class="md-nav__item psv-category-group">
              <summary class="md-nav__link"><span>SOC &amp; Detection</span><span class="psv-vault-count">6</span></summary>
              <div class="md-nav psv-category-tools">
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/sigma">Sigma Rule Preview</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/events">Event ID Encyclopedia</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/regex">Log Regex Sandbox</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/spl">Splunk SPL Builder</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/parser">Log Parser &amp; Normaliser</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/device">Device Intelligence</a>
              </div>
            </details>
            <details class="md-nav__item psv-category-group">
              <summary class="md-nav__link"><span>Threat Intelligence</span><span class="psv-vault-count">2</span></summary>
              <div class="md-nav psv-category-tools">
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/ioc">Bulk IoC Extractor</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/ti">Threat Intel Hub</a>
              </div>
            </details>
            <details class="md-nav__item psv-category-group" open>
              <summary class="md-nav__link"><span>DFIR &amp; Forensics</span><span class="psv-vault-count">7</span></summary>
              <div class="md-nav psv-category-tools">
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/yara">YARA Rule Builder</a>
                <a class="md-nav__link psv-nav__link psv-sidebar-tool" href="/tools/#tool/deobfuscator">Script De-obfuscator</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/json">JSON Log Beautifier</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/case">Incident Case Workspace</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/share">Secure Evidence Share</a>
                <a class="md-nav__link psv-sidebar-tool active" href="/secure-share/" aria-current="page">Secure Share (Live Transfer)</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/evidence">Evidence Integrity</a>
              </div>
            </details>
            <details class="md-nav__item psv-category-group">
              <summary class="md-nav__link"><span>Network &amp; Email</span><span class="psv-vault-count">2</span></summary>
              <div class="md-nav psv-category-tools">
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/headers">Email Header Analyzer</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/cvss">CVSS v3.1 Calculator</a>
              </div>
            </details>
            <details class="md-nav__item psv-category-group">
              <summary class="md-nav__link"><span>Incident Utilities</span><span class="psv-vault-count">3</span></summary>
              <div class="md-nav psv-category-tools">
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/timestamp">Timestamp Converter</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/severity">Triage Heuristic</a>
                <a class="md-nav__link psv-sidebar-tool" href="/tools/#tool/report">Incident Report Builder</a>
              </div>
            </details>
          </div>
        </nav>
      </div>
    </div>
  </aside>
</div>

<script>
(() => {
  document.body.classList.add("secure-share-page");
  const frame = document.getElementById("secure-share-frame");
  if (!frame) return;
  const syncTheme = () => {
    try {
      const dark = document.documentElement.getAttribute("data-md-color-scheme") === "slate";
      const doc = frame.contentDocument;
      if (!doc) return;
      const vars = dark
        ? { "--ink":"#e6edf3","--muted":"#9ba7b4","--line":"#30363d","--panel":"#161b22","--page":"#0b0f14","--blue":"#58a6ff","--blue-dark":"#79b8ff","--red":"#f85149","--green":"#3fb950" }
        : { "--ink":"#172033","--muted":"#586579","--line":"#d9e1ec","--panel":"#ffffff","--page":"#f7f9fc","--blue":"#1f6feb","--blue-dark":"#1d5fd0","--red":"#b42318","--green":"#16794b" };
      Object.entries(vars).forEach(([key,value]) => doc.documentElement.style.setProperty(key,value));
      doc.documentElement.style.colorScheme = dark ? "dark" : "light";
    } catch (_) {}
  };
  frame.addEventListener("load", syncTheme);
  frame.src = "/assets/secure-share-app.html" + window.location.search + window.location.hash;
  const observer = new MutationObserver(syncTheme);
  observer.observe(document.documentElement,{attributes:true,attributeFilter:["data-md-color-scheme"]});
  window.addEventListener("message",(event)=>{
    if(event.origin!==window.location.origin||!event.data||event.data.type!=="psv-secure-share-height")return;
    const height=Number(event.data.height);
    if(Number.isFinite(height)&&height>=500&&height<=12000)frame.style.height=height+"px";
  });
})();
</script>
