---
title: Secure Share
---

<style>
/* Keep the standard MkDocs Material page width and native secondary sidebar.
   Only the Secure Share content itself is customised; page columns are not. */
body.secure-share-page .md-content__inner>h1:first-child{display:none}
#secure-share-layout{display:block;width:100%;max-width:100%;margin:0;padding:0 0 2rem}
#secure-share-main{display:block;min-width:0;width:100%;max-width:100%}
#secure-share-heading{display:block;margin:0 0 1rem}
#secure-share-heading .eyebrow{display:block;margin:0 0 .35rem;color:var(--md-accent-fg-color);font:700 .68rem/1.4 "Roboto Mono",monospace;letter-spacing:.1em;text-transform:uppercase}
#secure-share-heading h1{margin:0 0 .45rem;font-size:1.5625em;font-weight:700;letter-spacing:normal;color:var(--md-typeset-color)}
#secure-share-heading p{margin:0;color:var(--md-default-fg-color--light);font-size:1em;line-height:1.72}
#secure-share-frame{display:block;width:100%;height:1080px;min-height:820px;border:0;border-radius:0;background:transparent}

/* Category navigation inherits Material's shared navigation appearance.
   Page-specific styles are intentionally not applied to this component. */
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


</div>

<script>
(() => {
  document.body.classList.add("secure-share-page");
  const frame = document.getElementById("secure-share-frame");
  if (!frame) return;
  /* The right category navigation is mounted centrally by tools-workbench-v2.js,
     using the same TOOLS data and sidebar renderer as the Tools page. */
  const syncTheme = () => {
    try {
      const root = document.documentElement;
      const scheme = root.getAttribute("data-md-color-scheme") ||
        (document.body && document.body.getAttribute("data-md-color-scheme")) || "";
      const dark = scheme === "slate" || scheme === "dark" ||
        root.style.colorScheme === "dark";
      const doc = frame.contentDocument;
      if (!doc || !doc.documentElement) return;
      const appRoot = doc.documentElement;
      appRoot.setAttribute("data-theme", dark ? "dark" : "light");
      const vars = dark
        ? { "--ink":"#e6edf3","--muted":"#9ba7b4","--line":"#30363d","--panel":"#161b22","--page":"#0b0f14","--field":"#0d1117","--field-border":"#30363d","--soft":"#161b22","--soft-border":"#30363d","--blue":"#58a6ff","--blue-dark":"#79b8ff","--red":"#f85149","--green":"#3fb950","--notice-bg":"#111d2b","--notice-ink":"#c9d1d9","--good-bg":"#10251b","--good-border":"#238636","--bad-bg":"#2b1717","--bad-border":"#8e3430","--progress-track":"#30363d","--progress-fill":"#3fb950" }
        : { "--ink":"#172033","--muted":"#586579","--line":"#d9e1ec","--panel":"#ffffff","--page":"#f7f9fc","--field":"#ffffff","--field-border":"#cbd5e1","--soft":"#f8fafc","--soft-border":"#e2e8f0","--blue":"#1f6feb","--blue-dark":"#1d5fd0","--red":"#b42318","--green":"#16794b","--notice-bg":"#eff6ff","--notice-ink":"#43536b","--good-bg":"#f0fdf4","--good-border":"#86c9a8","--bad-bg":"#fff7f6","--bad-border":"#e6aaa5","--progress-track":"#e5eaf0","--progress-fill":"#238b58" };
      Object.entries(vars).forEach(([key,value]) => appRoot.style.setProperty(key,value));
      appRoot.style.colorScheme = dark ? "dark" : "light";
      doc.body.style.backgroundColor = "var(--page)";
      doc.body.style.color = "var(--ink)";
    } catch (_) {}
  };
  frame.addEventListener("load", syncTheme);
  frame.src = "/assets/secure-share-app.html" + window.location.search + window.location.hash;
  const observer = new MutationObserver(syncTheme);
  observer.observe(document.documentElement,{attributes:true,attributeFilter:["data-md-color-scheme","style"]});
  if (document.body) observer.observe(document.body,{attributes:true,attributeFilter:["data-md-color-scheme"]});
  window.addEventListener("message",(event)=>{
    if(event.origin!==window.location.origin||!event.data||event.data.type!=="psv-secure-share-height")return;
    const height=Number(event.data.height);
    if(Number.isFinite(height)&&height>=500&&height<=12000)frame.style.height=height+"px";
  });
})();
</script>
