---
title: Secure Share
---

<div style="width:100%;min-height:820px;">
  <iframe
    id="secure-share-app"
    title="Privacy Skill Vault Secure Share"
    style="display:block;width:100%;min-height:820px;border:0;border-radius:12px;background:#f6f8fb;"
    loading="eager"
    referrerpolicy="no-referrer"
    allow="clipboard-read; clipboard-write"
  ></iframe>
</div>

<script>
(() => {
  const frame = document.getElementById("secure-share-app");
  if (!frame) return;
  frame.src = "/assets/secure-share-app.html" + window.location.search + window.location.hash;
  window.addEventListener("message", (event) => {
    if (event.origin !== window.location.origin || !event.data || event.data.type !== "psv-secure-share-height") return;
    const height = Number(event.data.height);
    if (Number.isFinite(height) && height >= 500 && height <= 12000) frame.style.height = height + "px";
  });
})();
</script>
