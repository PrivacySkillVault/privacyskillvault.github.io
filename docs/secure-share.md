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
      const dark = document.documentElement.getAttribute("data-md-color-scheme") === "slate";
      const doc = frame.contentDocument;
      if (!doc) return;
      doc.documentElement.dataset.theme = dark ? "dark" : "light";
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
