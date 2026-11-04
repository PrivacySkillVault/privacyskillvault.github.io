---
title: Secure Share
---

<style>
#secure-share-layout{display:grid!important;grid-template-columns:minmax(0,1fr) 245px!important;grid-template-rows:auto;gap:1.5rem;align-items:start;width:100%;max-width:100%;margin:0;padding:0 0 2rem}
#secure-share-main{display:block;grid-column:1;grid-row:1;min-width:0;width:100%;max-width:100%}
#secure-share-heading{display:none}
#secure-share-heading .eyebrow{display:block;margin:0 0 .35rem;color:var(--md-accent-fg-color);font:700 .68rem/1.4 "Roboto Mono",monospace;letter-spacing:.1em;text-transform:uppercase}
#secure-share-heading h1{margin:0 0 .45rem;font-size:1.8rem;font-weight:700;letter-spacing:-.02em;color:var(--md-default-fg-color)}
#secure-share-heading p{margin:0;color:var(--md-default-fg-color--light);font-size:.9rem;line-height:1.65}
#secure-share-frame{display:block;width:100%;height:1080px;min-height:820px;border:1px solid var(--md-default-fg-color--lightest);border-radius:10px;background:var(--md-default-bg-color)}
#secure-share-categories{display:block;grid-column:2;grid-row:1;width:245px;min-width:0;position:sticky;top:1.25rem;max-height:calc(100vh - 2.5rem);overflow:auto;padding:.9rem;border:1px solid var(--md-default-fg-color--lightest);border-radius:10px;background:var(--md-code-bg-color)}
#secure-share-categories .sidebar-title{display:block;margin:0 0 .65rem;padding:0 .25rem;color:var(--md-default-fg-color);font-size:.78rem;font-weight:700}
#secure-share-categories details{margin:.15rem 0;border:0;border-radius:7px}
#secure-share-categories summary{display:flex;align-items:center;justify-content:space-between;gap:.5rem;padding:.62rem .55rem;border-radius:7px;color:var(--md-default-fg-color);font-size:.79rem;font-weight:600;cursor:pointer;list-style:none}
#secure-share-categories summary::-webkit-details-marker{display:none}
#secure-share-categories summary:hover{background:var(--md-default-bg-color)}
#secure-share-categories details[open] summary{color:var(--md-accent-fg-color)}
#secure-share-categories .count{color:var(--md-default-fg-color--light);font-size:.68rem}
#secure-share-categories .category-items{display:grid;gap:.15rem;padding:.2rem .25rem .4rem .65rem}
#secure-share-categories a{display:block;padding:.48rem .55rem;border-radius:6px;color:var(--md-default-fg-color--light);font-size:.74rem;line-height:1.45;text-decoration:none}
#secure-share-categories a:hover{background:var(--md-default-bg-color);color:var(--md-accent-fg-color)}
#secure-share-categories a.active{background:var(--md-default-bg-color);box-shadow:inset 3px 0 var(--md-accent-fg-color);color:var(--md-accent-fg-color);font-weight:650}
#secure-share-categories .sidebar-foot{margin-top:.7rem;padding:.7rem .35rem 0;border-top:1px solid var(--md-default-fg-color--lightest);font-size:.7rem;line-height:1.55;color:var(--md-default-fg-color--light)}
#secure-share-categories .sidebar-foot a{padding:.35rem 0;color:var(--md-accent-fg-color)}
@media(max-width:900px){#secure-share-layout{grid-template-columns:minmax(0,1fr)!important}#secure-share-main{grid-column:1;grid-row:1}#secure-share-categories{grid-column:1;grid-row:2;width:100%;position:static;max-height:none;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.3rem}#secure-share-categories .sidebar-title,#secure-share-categories .sidebar-foot{grid-column:1/-1}}
@media(max-width:560px){#secure-share-categories{grid-template-columns:1fr}#secure-share-frame{height:1180px;min-height:900px}#secure-share-heading h1{font-size:1.55rem}}
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

  <aside id="secure-share-categories" aria-label="Tools categories">
    <span class="sidebar-title">Tool categories</span>
    <details>
      <summary><span>SOC &amp; Detection</span><span class="count">Detection tools</span></summary>
      <div class="category-items">
        <a href="/tools/">View SOC &amp; Detection tools</a>
      </div>
    </details>
    <details>
      <summary><span>Threat Intelligence</span><span class="count">Intel tools</span></summary>
      <div class="category-items">
        <a href="/tools/">View Threat Intelligence tools</a>
      </div>
    </details>
    <details open>
      <summary><span>DFIR &amp; Forensics</span><span class="count">Active category</span></summary>
      <div class="category-items">
        <a href="/tools/">Incident Case Report</a>
        <a href="/tools/">Secure Evidence Share</a>
        <a href="/secure-share/" class="active" aria-current="page">Secure Share (Live Transfer)</a>
        <a href="/tools/">File Integrity / SHA-256</a>
      </div>
    </details>
    <details>
      <summary><span>Network &amp; Email</span><span class="count">Analysis tools</span></summary>
      <div class="category-items">
        <a href="/tools/">View Network &amp; Email tools</a>
      </div>
    </details>
    <details>
      <summary><span>Incident Utilities</span><span class="count">Utility tools</span></summary>
      <div class="category-items">
        <a href="/tools/">View Incident Utilities</a>
      </div>
    </details>
    <div class="sidebar-foot">
      Secure Share is listed under DFIR &amp; Forensics. The existing Secure Evidence Share remains a separate passphrase-based tool.
      <a href="/tools/">← Back to all tools</a>
    </div>
  </aside>
</div>

<script>
(() => {
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
