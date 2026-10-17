// popup.js — PhishGuard popup

const COLORS = {
  Safe:       "#16a34a",
  Suspicious: "#d97706",
  Dangerous:  "#dc2626",
  Unknown:    "#6b7280",
};
const EMOJIS = {
  Safe:       "✅",
  Suspicious: "⚠️",
  Dangerous:  "🚨",
  Unknown:    "❓",
};

function sendMsg(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...payload }, (r) => {
      if (chrome.runtime.lastError) resolve(null);
      else resolve(r);
    });
  });
}

// ─── Renderers ────────────────────────────────────────────────────────────────

function renderResult(url, result) {
  const { score, verdict, reasons, mitre_tags } = result;
  const color    = COLORS[verdict]  || COLORS.Unknown;
  const emoji    = EMOJIS[verdict]  || "❓";
  const barWidth = Math.max(score, 4);

  document.getElementById("main-content").innerHTML = `
    <div class="score-card">
      <div class="score-header" style="border-left:4px solid ${color};">
        <span style="font-size:18px">${emoji}</span>
        <span class="verdict-badge" style="background:${color}">${verdict}</span>
        <span class="score-num" style="color:${color}">${score}</span>
      </div>
      <div class="score-body">
        <div class="url-text" title="${url}">${url.length > 52 ? url.slice(0,52)+"…" : url}</div>
        <div class="bar-bg"><div class="bar-fill" style="width:${barWidth}%;background:${color}"></div></div>
        <div class="reasons-title">Detection Signals</div>
        ${(reasons||[]).slice(0,4).map(r=>`<div class="reason-item">• ${r}</div>`).join("")
          || '<div class="reason-item">No threats detected</div>'}
        ${mitre_tags&&mitre_tags.length
          ? `<div class="mitre-text">🔖 ${mitre_tags.slice(0,2).join(" | ")}</div>` : ""}
      </div>
    </div>`;
}

function renderNeutral(msg) {
  document.getElementById("main-content").innerHTML = `
    <div class="state-box" style="color:#57606a;">🌐 ${msg}</div>`;
}

function renderError(msg) {
  document.getElementById("main-content").innerHTML = `
    <div class="state-box">⚠️ ${msg}</div>`;
}

// ─── Stats ────────────────────────────────────────────────────────────────────

async function loadStats() {
  const stats = await sendMsg("GET_STATS");
  if (!stats) return;
  document.getElementById("stats-row").style.display = "flex";
  document.getElementById("stat-total").textContent = stats.total_scans;
  document.getElementById("stat-safe").textContent  = stats.safe;
  document.getElementById("stat-sus").textContent   = stats.suspicious;
  document.getElementById("stat-dan").textContent   = stats.dangerous;
}

// ─── Main init ────────────────────────────────────────────────────────────────

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url || "";

  // ── Case 1: warning.html is open — show its stored scan result ──────────────
  if (url.startsWith("chrome-extension://") && url.includes("warning.html")) {
    const params    = new URL(url).searchParams;
    const tabIdStr  = params.get("tab");
    const blockedUrl = params.get("url") ? decodeURIComponent(params.get("url")) : null;

    console.log("[PhishGuard popup] warning.html detected, tab=", tabIdStr, "url=", blockedUrl);

    // Try reading stored scan result
    let data = null;
    if (tabIdStr) {
      const key    = `scan_${tabIdStr}`;
      const stored = await chrome.storage.local.get(key);
      data         = stored[key] || null;
      console.log("[PhishGuard popup] storage key", key, "→", data);
    }

    if (data) {
      renderResult(data.url || blockedUrl || url, data);
    } else if (blockedUrl) {
      // Fallback: scan the blocked URL live
      const result = await sendMsg("SCAN_URL", { url: blockedUrl });
      if (result) renderResult(blockedUrl, result);
      else renderError("Backend unreachable.");
    } else {
      renderError("Blocked page — no scan data available.");
    }

    loadStats();
    return;
  }

  // ── Case 2: Browser-internal page — show neutral message ────────────────────
  const browserPrefixes = ["chrome://", "chrome-extension://", "edge://", "about:", "data:", "file://"];
  if (!url || browserPrefixes.some(p => url.startsWith(p))) {
    renderNeutral("Browser page — not scanned.");
    loadStats();
    return;
  }

  // ── Case 3: Normal HTTP/HTTPS page ──────────────────────────────────────────
  const result = await sendMsg("SCAN_URL", { url });
  if (!result) {
    renderError("Backend unreachable. Is the server running?");
    return;
  }

  renderResult(url, result);
  loadStats();
}

// ─── Buttons ─────────────────────────────────────────────────────────────────

document.getElementById("btn-dashboard").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
});

document.getElementById("btn-rescan").addEventListener("click", () => {
  document.getElementById("main-content").innerHTML = `
    <div class="state-box" id="loading-box">
      <div class="spinner"></div>Re-scanning…
    </div>`;
  init();
});

init();
