// content.js — PhishGuard
// Shadow DOM overlay, debounced hover pre-scan, click intercept

(function () {
  if (window.__phishguardLoaded) return;
  window.__phishguardLoaded = true;

  const LOG = (...a) => console.log("[PhishGuard]", ...a);

  // ─── State ────────────────────────────────────────────────────────────────
  let shadowHost   = null;   // the <div> injected into page
  let shadowRoot   = null;   // shadow root inside it
  let cardEl       = null;   // the card inside shadow root
  let autoTimer    = null;   // auto-dismiss timeout
  let pendingUrl   = null;   // url blocked, waiting for user choice
  let hoverTimer   = null;   // debounce timer for hover

  // ─── Messaging ────────────────────────────────────────────────────────────

  function sendMsg(type, payload) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type, ...payload }, (r) => {
          if (chrome.runtime.lastError) { LOG("msg error:", chrome.runtime.lastError.message); resolve(null); }
          else resolve(r);
        });
      } catch (e) { LOG("msg exception:", e); resolve(null); }
    });
  }

  // ─── URL helpers ──────────────────────────────────────────────────────────

  function cleanUrl(href) {
    try { return new URL(href, location.href).href; } catch (_) { return href; }
  }

  function skipUrl(url) {
    if (!url) return true;
    return ["chrome://","chrome-extension://","about:","javascript:","data:","file://"]
      .some(p => url.startsWith(p)) || !url.startsWith("http");
  }

  // ─── Shadow DOM overlay ───────────────────────────────────────────────────

  function ensureShadow() {
    if (shadowHost) return;
    shadowHost = document.createElement("div");
    shadowHost.id = "phishguard-host";
    // Host sits outside normal flow, z-index above everything
    shadowHost.style.cssText = "all:initial;position:fixed;top:0;right:0;z-index:2147483647;pointer-events:none;";
    document.documentElement.appendChild(shadowHost);
    shadowRoot = shadowHost.attachShadow({ mode: "open" });

    // Inject scoped styles inside shadow
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      #pg-card {
        position: fixed;
        top: 76px;
        right: 18px;
        width: 320px;
        background: #fff;
        border-radius: 12px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.22);
        font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
        font-size: 13px;
        color: #1f2328;
        overflow: hidden;
        pointer-events: all;
        animation: pgIn .18s ease;
      }
      @keyframes pgIn { from { opacity:0; transform:translateX(20px); } to { opacity:1; transform:translateX(0); } }
      .pg-head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px 14px;
        position: relative;
        color: #fff;
      }
      .pg-emoji  { font-size: 18px; }
      .pg-label  { font-size: 15px; font-weight: 700; }
      .pg-badge  {
        margin-left: auto;
        margin-right: 24px;
        background: rgba(255,255,255,0.25);
        border-radius: 6px;
        padding: 2px 8px;
        font-size: 12px;
        font-weight: 600;
      }
      .pg-close {
        position: absolute;
        top: 6px; right: 8px;
        background: none; border: none;
        color: #fff; font-size: 20px;
        cursor: pointer; line-height: 1; padding: 0 4px;
      }
      .pg-body   { padding: 12px 14px; }
      .pg-url    { font-size: 11px; color: #57606a; word-break: break-all; margin-bottom: 8px; }
      .pg-slabel { font-size: 11px; color: #57606a; margin-bottom: 4px; }
      .pg-bar-bg { background: #e5e7eb; border-radius: 4px; height: 8px; margin-bottom: 10px; }
      .pg-bar    { height: 8px; border-radius: 4px; transition: width .4s; }
      .pg-reasons { margin-bottom: 8px; }
      .pg-reason  { font-size: 11px; color: #57606a; padding: 2px 0; border-bottom: 1px solid #f3f4f6; }
      .pg-mitre   { font-size: 10px; color: #7c5cd8; margin-bottom: 8px; }
      .pg-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 4px; }
      .pg-btn {
        flex: 1; min-width: 100px;
        padding: 7px 0; border-radius: 6px; border: none;
        cursor: pointer; font-size: 12px; font-weight: 600;
      }
      .pg-note {
        font-size: 11px; font-weight: 600; margin-bottom: 8px;
        padding: 6px 8px; border-radius: 6px;
        color: #dc2626; background: #fff5f5; border: 1px solid #fecaca;
      }
      .pg-scanning { font-size: 11px; color: #57606a; font-style: italic; padding: 4px 0; }
    `;
    shadowRoot.appendChild(style);
  }

  function removeOverlay() {
    if (autoTimer) { clearTimeout(autoTimer); autoTimer = null; }
    if (cardEl)    { cardEl.remove(); cardEl = null; }
    pendingUrl = null;
  }

  function color(v) { return {Safe:"#16a34a",Suspicious:"#d97706",Dangerous:"#dc2626"}[v]||"#6b7280"; }
  function emoji(v) { return {Safe:"✅",Suspicious:"⚠️",Dangerous:"🚨"}[v]||"❓"; }

  // Build or update the card in the shadow DOM
  function showCard(result, opts = {}) {
    ensureShadow();
    if (autoTimer) { clearTimeout(autoTimer); autoTimer = null; }

    const { url, score, verdict, reasons, mitre_tags } = result;
    const c   = color(verdict);
    const em  = emoji(verdict);
    const bar = Math.max(score, 4);
    const shortUrl = url && url.length > 55 ? url.slice(0, 55) + "…" : (url || "");

    // Remove old card
    if (cardEl) cardEl.remove();

    const card = document.createElement("div");
    card.id = "pg-card";

    const reasonsHtml = (reasons || []).slice(0, 4)
      .map(r => `<div class="pg-reason">• ${r}</div>`).join("")
      || '<div class="pg-reason">No threats detected</div>';

    const mitreHtml = (mitre_tags && mitre_tags.length)
      ? `<div class="pg-mitre">🔖 ${mitre_tags.slice(0,2).join(" | ")}</div>` : "";

    card.innerHTML = `
      <div class="pg-head" style="background:${c}">
        <span class="pg-emoji">${em}</span>
        <span class="pg-label">${verdict}</span>
        <span class="pg-badge">${score}% risk</span>
        <button class="pg-close" id="pg-x">×</button>
      </div>
      <div class="pg-body">
        <div class="pg-url" title="${url}">${shortUrl}</div>
        <div class="pg-slabel">Threat Score: ${score}/100</div>
        <div class="pg-bar-bg"><div class="pg-bar" style="background:${c};width:${bar}%"></div></div>
        <div class="pg-reasons">${reasonsHtml}</div>
        ${mitreHtml}
        <div class="pg-actions" id="pg-actions"></div>
      </div>`;

    shadowRoot.appendChild(card);
    cardEl = card;

    card.querySelector("#pg-x").addEventListener("click", removeOverlay);

    const actions = card.querySelector("#pg-actions");

    if (verdict === "Safe") {
      // Auto-hide after 3s, then navigate if pending
      autoTimer = setTimeout(() => {
        removeOverlay();
        if (pendingUrl) { window.location.href = pendingUrl; pendingUrl = null; }
      }, 3000);

    } else if (verdict === "Suspicious") {
      const back = mkBtn("← Go Back",       "#fee2e2", "#dc2626");
      const fwd  = mkBtn("Continue anyway",  "#f3f4f6", "#374151");
      back.addEventListener("click", () => { removeOverlay(); history.back(); });
      fwd.addEventListener("click",  () => {
        const dest = pendingUrl; removeOverlay();
        if (dest) window.location.href = dest;
      });
      actions.appendChild(back);
      actions.appendChild(fwd);

    } else if (verdict === "Dangerous") {
      const note = document.createElement("div");
      note.className = "pg-note";
      note.textContent = "⚠️ Stay Alert — Do NOT enter any real credentials.";
      actions.parentNode.insertBefore(note, actions);

      const back   = mkBtn("← Go Back to Safety", "#fee2e2", "#dc2626");
      const poison = mkBtn("🪤 PhishTrap",          "#7c5cd8", "#fff");
      back.style.flex = "2";
      back.addEventListener("click",   () => { removeOverlay(); history.back(); });
      poison.addEventListener("click", () => activatePhishTrap(url));
      actions.appendChild(back);
      actions.appendChild(poison);
    }

    // Live update: if opts.live the card was shown early (e.g. from cache) and
    // a fresher result may arrive — caller can call showCard again to patch it.
  }

  function mkBtn(label, bg, fg) {
    const b = document.createElement("button");
    b.className = "pg-btn";
    b.textContent = label;
    b.style.cssText = `background:${bg};color:${fg};`;
    return b;
  }

  // Show a "scanning…" placeholder immediately on click before result arrives
  function showScanning(url) {
    ensureShadow();
    if (autoTimer) { clearTimeout(autoTimer); autoTimer = null; }
    if (cardEl) cardEl.remove();

    const card = document.createElement("div");
    card.id = "pg-card";
    const shortUrl = url.length > 55 ? url.slice(0, 55) + "…" : url;
    card.innerHTML = `
      <div class="pg-head" style="background:#6b7280">
        <span class="pg-emoji">🔍</span>
        <span class="pg-label">Scanning…</span>
        <button class="pg-close" id="pg-x">×</button>
      </div>
      <div class="pg-body">
        <div class="pg-url">${shortUrl}</div>
        <div class="pg-scanning">Checking against phishing database…</div>
      </div>`;
    shadowRoot.appendChild(card);
    cardEl = card;
    card.querySelector("#pg-x").addEventListener("click", removeOverlay);
  }

  // ─── Scan current page on load ────────────────────────────────────────────

  async function scanCurrentPage() {
    const url = window.location.href;
    if (skipUrl(url)) { LOG("skip:", url); return; }

    LOG("scanning page:", url);
    const result = await sendMsg("SCAN_URL", { url });
    if (!result) { LOG("no result — backend offline?"); return; }

    LOG("result:", result.verdict, result.score);
    showCard(result);

    if (result.verdict === "Dangerous") {
      sendMsg("BLOCK_TAB", { url, result });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scanCurrentPage);
  } else {
    scanCurrentPage();
  }

  // ─── Hover — debounced 150 ms pre-scan (cache warming) ───────────────────

  document.addEventListener("mouseover", (e) => {
    const link = e.target.closest("a[href]");
    if (!link) return;
    const url = cleanUrl(link.href);
    if (skipUrl(url)) return;

    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => {
      sendMsg("SCAN_URL", { url }); // warm cache silently
    }, 150);
  });

  document.addEventListener("mouseout", (e) => {
    if (e.target.closest("a[href]")) clearTimeout(hoverTimer);
  });

  // ─── Click intercept ──────────────────────────────────────────────────────

  document.addEventListener("click", async (e) => {
    const link = e.target.closest("a[href]");
    if (!link) return;

    const url = cleanUrl(link.href);
    if (skipUrl(url)) return;

    // Same origin — skip
    try { if (new URL(url).origin === window.location.origin) return; }
    catch (_) { return; }

    // _blank — new tab, scanCurrentPage handles it on load
    if (link.target === "_blank") return;

    e.preventDefault();
    e.stopPropagation();
    pendingUrl = url;

    // Show scanning placeholder immediately (feels instant)
    showScanning(url);

    const result = await sendMsg("SCAN_URL", { url });
    if (!result) {
      // Backend down — proceed silently
      removeOverlay();
      window.location.href = url;
      return;
    }

    // Update card with real result
    showCard(result);

    if (result.verdict === "Safe") {
      // showCard sets 3s timer then navigates — nothing else needed
    } else if (result.verdict === "Suspicious") {
      // overlay locked — user must choose
    } else if (result.verdict === "Dangerous") {
      sendMsg("BLOCK_TAB", { url, result });
    }
  }, true);

  // ─── Escape key ───────────────────────────────────────────────────────────

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") removeOverlay();
  });

  // ─── Messages from background (tab navigation) ────────────────────────────

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "SHOW_RESULT" && msg.result) {
      LOG("SHOW_RESULT from bg:", msg.result.verdict);
      if (msg.result.verdict !== "Safe") showCard(msg.result);
    }
  });

  // ─── PhishTrap ────────────────────────────────────────────────────────────

  async function activatePhishTrap(url) {
    const site = (() => { try { return new URL(url).hostname; } catch (_) { return url; } })();
    const tokenData = await sendMsg("CREATE_TOKEN", { site });
    if (!tokenData) { alert("PhishTrap: Backend unavailable."); return; }

    // Replace card body with trap info
    if (cardEl) {
      const body = cardEl.querySelector(".pg-body");
      if (body) body.innerHTML = `
        <div style="color:#7c5cd8;font-weight:700;margin-bottom:8px;">🪤 PhishTrap Active</div>
        <div style="font-size:11px;color:#57606a;margin-bottom:6px;">Submit these fake credentials on the phishing site:</div>
        <div style="background:#f7f8fa;border-radius:6px;padding:8px;margin-bottom:8px;">
          <div style="font-size:12px;margin-bottom:4px;"><b>Email:</b> ${tokenData.username}</div>
          <div style="font-size:12px;"><b>Password:</b> ${tokenData.password}</div>
        </div>
        <div style="font-size:10px;color:#57606a;">Token: ${tokenData.token}</div>
        <div style="font-size:10px;color:#16a34a;margin-top:6px;">✅ Chrome notification when attacker uses these creds.</div>`;
    }
    autoFillDecoy(tokenData.username, tokenData.password, tokenData.token);
  }

  function autoFillDecoy(username, password, token) {
    for (const form of document.querySelectorAll("form")) {
      const emailEl = form.querySelector('input[type="email"],input[name*="user"],input[name*="email"],input[name*="login"]');
      const passEl  = form.querySelector('input[type="password"]');
      if (emailEl && passEl) {
        emailEl.value = username;
        passEl.value  = password;
        sendMsg("SUBMIT_DECOY", { token, username, password });
        break;
      }
    }
  }

  LOG("loaded on", window.location.href);
})();
