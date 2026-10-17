// warning.js — PhishGuard block page logic

const params = new URLSearchParams(location.search);
const tabId  = params.get("tab");
const rawUrl = params.get("url");
const blockedUrl = rawUrl ? decodeURIComponent(rawUrl) : null;

console.log("[PhishGuard warning] tabId:", tabId, "url:", blockedUrl);

// ─── Show URL immediately from query param ────────────────────────────────────

document.getElementById("blocked-url").textContent = blockedUrl || "(unknown)";

// ─── Load full scan result from storage ──────────────────────────────────────

async function loadScanData() {
  let data = null;

  // 1. Try storage keyed by tabId
  if (tabId) {
    const key = `scan_${tabId}`;
    const stored = await chrome.storage.local.get(key);
    data = stored[key] || null;
    console.log("[PhishGuard warning] storage lookup:", key, "→", data);
  }

  // 2. Fallback: call backend directly with the URL
  if (!data && blockedUrl) {
    console.log("[PhishGuard warning] Falling back to /analyze for:", blockedUrl);
    try {
      const resp = await fetch("http://localhost:8000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: blockedUrl }),
      });
      if (resp.ok) {
        const j = await resp.json();
        data = { url: j.url, score: j.score, verdict: j.verdict, reasons: j.reasons, mitre_tags: j.mitre_tags };
        console.log("[PhishGuard warning] fallback result:", data);
      }
    } catch (e) {
      console.warn("[PhishGuard warning] Fallback fetch failed:", e);
    }
  }

  if (!data) {
    document.getElementById("reasons-list").innerHTML =
      '<div class="no-data">No scan data found. Open this page by clicking a suspicious link.</div>';
    document.getElementById("score-circle").textContent = "?";
    return;
  }

  renderData(data);
}

// ─── Render scan result into the page ────────────────────────────────────────

function renderData(data) {
  const { url, score, reasons, mitre_tags } = data;

  console.log("[PhishGuard warning] Rendering — score:", score, "reasons:", reasons, "mitre:", mitre_tags);

  // URL
  document.getElementById("blocked-url").textContent = url || blockedUrl || "(unknown)";

  // Score circle + bar
  document.getElementById("score-circle").textContent = score;
  document.getElementById("score-bar").style.width = Math.max(score, 4) + "%";

  // Reasons list
  const list = document.getElementById("reasons-list");
  list.innerHTML = "";
  const reasonArr = Array.isArray(reasons) ? reasons : [];
  if (reasonArr.length) {
    reasonArr.forEach(r => {
      const d = document.createElement("div");
      d.className = "reason-item";
      d.textContent = r;
      list.appendChild(d);
    });
  } else {
    list.innerHTML = '<div class="reason-item">Site matched phishing blocklist</div>';
  }

  // MITRE tags
  const mitreArr = Array.isArray(mitre_tags) ? mitre_tags : [];
  if (mitreArr.length) {
    document.getElementById("mitre-section").textContent = "🔖 " + mitreArr.join("  |  ");
  }
}

// ─── Buttons ──────────────────────────────────────────────────────────────────

document.getElementById("btn-back").addEventListener("click", () => {
  if (history.length > 1) {
    history.go(-2); // -2 because warning.html itself is in history
  } else {
    chrome.tabs.getCurrent(t => t && chrome.tabs.update(t.id, { url: "https://www.google.com" }));
  }
});

document.getElementById("btn-proceed").addEventListener("click", async () => {
  if (!blockedUrl) return;
  if (!confirm("⚠️ This site is dangerous. Are you absolutely sure you want to proceed?")) return;

  // Add to allowlist so background.js won't block it again
  await chrome.runtime.sendMessage({ type: "ADD_ALLOWLIST", url: blockedUrl });
  window.location.href = blockedUrl;
});

document.getElementById("btn-poison").addEventListener("click", async () => {
  const site = (() => { try { return new URL(blockedUrl).hostname; } catch (_) { return blockedUrl || "unknown"; } })();
  const resp = await chrome.runtime.sendMessage({ type: "CREATE_TOKEN", site });
  if (!resp) { alert("PhishTrap: Backend unavailable."); return; }

  // Submit decoy to tripwire
  chrome.runtime.sendMessage({ type: "SUBMIT_DECOY", token: resp.token, username: resp.username, password: resp.password });

  // Show trap panel
  document.getElementById("trap-user").textContent  = "Email:    " + resp.username;
  document.getElementById("trap-pass").textContent  = "Password: " + resp.password;
  document.getElementById("trap-token").textContent = "Token:    " + resp.token;
  document.getElementById("trap-panel").style.display = "block";

  document.getElementById("btn-poison").textContent = "🪤 Trap Active";
  document.getElementById("btn-poison").disabled = true;
});

// ─── Init ─────────────────────────────────────────────────────────────────────

loadScanData();
