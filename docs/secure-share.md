---
title: Secure Share
---

<style>
/* Match the Tools page outer Material layout: central workspace with native right navigation. */
body.secure-share-page .md-grid{width:100%!important;max-width:1480px!important}
body.secure-share-page .md-main__inner{box-sizing:border-box;width:100%!important;max-width:1480px!important;margin:0 auto!important;align-items:flex-start!important}
body.secure-share-page .md-content{box-sizing:border-box;flex:1 1 auto!important;width:100%!important;min-width:0!important;max-width:none!important;margin:0!important}
body.secure-share-page .md-content__inner{box-sizing:border-box;width:100%!important;max-width:none!important;margin:0!important;padding:1.4rem 1rem 3rem!important}
body.secure-share-page .md-content__inner>h1:first-child{display:none}
#secure-share-layout{display:block!important;width:100%!important;max-width:none!important;margin:0;padding:0 0 2rem}
#secure-share-main{display:block;min-width:0;width:100%;max-width:none}
#secure-share-heading{display:block;margin:0 0 1rem}
#secure-share-heading .eyebrow{display:block;margin:0 0 .35rem;color:var(--md-accent-fg-color);font:700 .68rem/1.4 "Roboto Mono",monospace;letter-spacing:.1em;text-transform:uppercase}
#secure-share-heading h1{margin:0 0 .45rem;font-size:1.5625em;font-weight:700;letter-spacing:normal;color:var(--md-typeset-color)}
#secure-share-heading p{margin:0;color:var(--md-default-fg-color--light);font-size:1em;line-height:1.72}
#secure-share-frame{display:block;width:100%;height:1080px;min-height:820px;border:0;border-radius:0;background:transparent}
.md-sidebar--secondary .psv-tool-sidebar{display:block!important;position:static!important;max-height:none!important;overflow:visible!important;margin:0!important;padding:0!important;border:0!important;border-radius:0!important;background:transparent!important}
.md-sidebar--secondary .psv-tool-sidebar>.md-nav__title{display:block;margin:0 0 .65rem;padding:0 .2rem;color:var(--md-default-fg-color);font-size:.78rem;font-weight:700}
.md-sidebar--secondary .psv-tool-sidebar>.psv-category-accordion{display:block!important;visibility:visible!important;margin-top:.85rem}
.md-sidebar--secondary .psv-tool-sidebar .psv-category-group{display:block!important;visibility:visible!important;margin:0;border:0;border-bottom:1px solid var(--md-default-fg-color--lightest)}
.md-sidebar--secondary .psv-tool-sidebar .psv-category-group>summary{display:flex!important;align-items:center;justify-content:space-between;gap:.5rem;margin:0;padding:.65rem .55rem;border:0;border-radius:7px;background:transparent;color:var(--md-default-fg-color);cursor:pointer;font:inherit;font-size:.8rem;font-weight:650;line-height:1.4;text-align:left;list-style:none}
.md-sidebar--secondary .psv-tool-sidebar .psv-category-group>summary::-webkit-details-marker{display:none}
.md-sidebar--secondary .psv-tool-sidebar .psv-category-tools{display:block;padding:.1rem 0 .45rem .6rem}
.md-sidebar--secondary .psv-tool-sidebar .psv-sidebar-tool{display:block!important;width:100%;margin:0;border:0;padding:.35rem .6rem;border-radius:6px;background:transparent;color:var(--md-default-fg-color--light);font:inherit;font-size:.76rem;line-height:1.45;text-align:left;text-decoration:none;cursor:pointer}
.md-sidebar--secondary .psv-tool-sidebar .psv-category-group>summary:hover,.md-sidebar--secondary .psv-tool-sidebar .psv-sidebar-tool:hover{background:var(--md-default-bg-color);color:var(--md-accent-fg-color)}\n.md-sidebar--secondary .psv-tool-sidebar .psv-sidebar-tool.active{background:var(--md-default-bg-color);box-shadow:inset 3px 0 var(--md-accent-fg-color);color:var(--md-accent-fg-color)}
.md-sidebar--secondary .psv-tool-sidebar .psv-sidebar-tool.active{font-weight:650}
.md-sidebar--secondary .psv-tool-sidebar .psv-vault-count{margin-left:auto;padding-left:.5rem;color:var(--md-default-fg-color--light);font:inherit;font-size:.85em}
@media(max-width:900px){body.secure-share-page .md-main__inner{display:block!important}.md-sidebar--secondary .psv-tool-sidebar{position:static!important;max-height:none!important;overflow:visible!important}}
@media(max-width:560px){body.secure-share-page .md-content__inner{padding:.7rem .8rem 2rem!important}#secure-share-frame{height:1180px;min-height:900px}}
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
  const sidebar = document.getElementById("secure-share-categories");
  const categoryNav = sidebar && sidebar.querySelector(".psv-tool-sidebar");
  let nativeSecondary = document.querySelector('.md-sidebar--secondary[data-md-type="toc"]');
  if (!nativeSecondary) {
    const mainInner = document.querySelector(".md-main__inner");
    if (mainInner) {
      nativeSecondary = document.createElement("div");
      nativeSecondary.className = "md-sidebar md-sidebar--secondary";
      nativeSecondary.setAttribute("data-md-component", "sidebar");
      nativeSecondary.setAttribute("data-md-type", "toc");
      const scroll = document.createElement("div");
      scroll.className = "md-sidebar__scrollwrap";
      const inner = document.createElement("div");
      inner.className = "md-sidebar__inner";
      scroll.appendChild(inner);
      nativeSecondary.appendChild(scroll);
      mainInner.appendChild(nativeSecondary);
    }
  }
  const nativeSecondaryInner = nativeSecondary && nativeSecondary.querySelector(".md-sidebar__inner");
  if (categoryNav && nativeSecondaryInner) {
    nativeSecondaryInner.replaceChildren(categoryNav);
    sidebar.remove();
    nativeSecondary.setAttribute("aria-label", "Tools categories");
  } else if (categoryNav) {
    /* Keep the category navigation visible in the content column if Material's sidebar is unavailable. */
    sidebar.classList.add("secure-share-categories-fallback");
    sidebar.style.display = "block";
    sidebar.style.width = "100%";
  }
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
