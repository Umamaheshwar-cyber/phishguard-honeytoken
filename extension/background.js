// background.js — PhishGuard MV3 Service Worker
// Handles: API calls, scan cache, tab blocking, notifications, token polling

const API = "http://localhost:8000";
const CACHE = {}; // url → {score, verdict, reasons, mitre_tags, ts}
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const TOKEN_POLL_INTERVAL = 30 * 1000; // 30 seconds

// ─── Scan URL ────────────────────────────────────────────────────────────────

async function scanUrl(url) {
  // Return cached result if fresh
  const cached = CACHE[url];
  if (cached && Date.now() - cached.ts < CACHE_TTL) {
    return cached;
  }

  try {
    const resp = await fetch(`${API}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const result = {
      url: data.url,
      score: data.score,
      verdict: data.verdict,
      reasons: data.reasons,
      mitre_tags: data.mitre_tags,
      in_blocklist: data.in_blocklist,
      ts: Date.now(),
    };
    CACHE[url] = result;
    return result;
  } catch (e) {
    console.error("[PhishGuard] scanUrl failed:", e);
    return { url, score: 0, verdict: "Unknown", reasons: ["Backend unreachable"], mitre_tags: [], ts: Date.now() };
  }
}

// ─── Create Honeytoken ───────────────────────────────────────────────────────

async function createToken(site) {
  try {
    const resp = await fetch(`${API}/token/create`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ site }),
    });
    return await resp.json();
  } catch (e) {
    console.error("[PhishGuard] createToken failed:", e);
    return null;
  }
}

// ─── Submit decoy credentials ────────────────────────────────────────────────

async function submitDecoy(token, username, password) {
  try {
    await fetch(`${API}/decoy-login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, username, password }),
    });
  } catch (e) {
    console.error("[PhishGuard] submitDecoy failed:", e);
  }
}

// ─── Poll token status ───────────────────────────────────────────────────────

async function pollTokens() {
  const stored = await chrome.storage.local.get("activeTokens");
  const tokens = stored.activeTokens || [];
  const stillActive = [];

  for (const t of tokens) {
    try {
      const resp = await fetch(`${API}/token/status/${t.token}`);
      const data = await resp.json();
      if (data.status === "Triggered") {
        chrome.notifications.create(`trigger_${t.token}`, {
          type: "basic",
          iconUrl: "icons/icon48.png",
          title: "⚠️ PhishTrap TRIGGERED!",
          message: `Attacker used your honeytoken on ${t.site}!\nToken: ${t.token}`,
          priority: 2,
        });
        // Don't add back to active list
      } else {
        stillActive.push(t);
      }
    } catch (_) {
      stillActive.push(t); // keep if backend unreachable
    }
  }

  await chrome.storage.local.set({ activeTokens: stillActive });
}

// ─── Session allowlist ───────────────────────────────────────────────────────
// URLs the user explicitly chose to proceed on — skip blocking for these.

async function isAllowed(url) {
  const s = await chrome.storage.local.get("allowlist");
  const list = s.allowlist || [];
  return list.includes(url);
}

async function addToAllowlist(url) {
  const s = await chrome.storage.local.get("allowlist");
  const list = s.allowlist || [];
  if (!list.includes(url)) {
    list.push(url);
    await chrome.storage.local.set({ allowlist: list });
  }
}

// ─── Tab blocking (Dangerous verdict) ───────────────────────────────────────

async function blockTab(tabId, url, result) {
  // Store full result keyed by tabId so warning.html can read it cleanly
  await chrome.storage.local.set({
    [`scan_${tabId}`]: {
      url: result.url || url,
      score: result.score,
      verdict: result.verdict,
      reasons: result.reasons || [],
      mitre_tags: result.mitre_tags || [],
    }
  });
  console.log("[PhishGuard] blockTab stored scan for tab", tabId, result);

  const warningUrl = chrome.runtime.getURL(
    `warning.html?tab=${tabId}&url=${encodeURIComponent(url)}`
  );
  await chrome.tabs.update(tabId, { url: warningUrl });
}

// ─── Message handler ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SCAN_URL") {
    scanUrl(msg.url).then(sendResponse);
    return true; // async
  }

  if (msg.type === "BLOCK_TAB") {
    blockTab(sender.tab.id, msg.url, msg.result).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === "CREATE_TOKEN") {
    createToken(msg.site).then(async (tokenData) => {
      if (tokenData) {
        // Store in active tokens list
        const stored = await chrome.storage.local.get("activeTokens");
        const tokens = stored.activeTokens || [];
        tokens.push({ token: tokenData.token, site: tokenData.site });
        await chrome.storage.local.set({ activeTokens: tokens });
      }
      sendResponse(tokenData);
    });
    return true;
  }

  if (msg.type === "SUBMIT_DECOY") {
    submitDecoy(msg.token, msg.username, msg.password).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === "GET_STATS") {
    fetch(`${API}/stats`).then(r => r.json()).then(sendResponse).catch(() => sendResponse(null));
    return true;
  }

  if (msg.type === "GET_SCANS") {
    fetch(`${API}/scans`).then(r => r.json()).then(sendResponse).catch(() => sendResponse([]));
    return true;
  }

  if (msg.type === "GET_TOKENS") {
    fetch(`${API}/tokens`).then(r => r.json()).then(sendResponse).catch(() => sendResponse([]));
    return true;
  }

  if (msg.type === "ADD_ALLOWLIST") {
    addToAllowlist(msg.url).then(() => sendResponse({ ok: true }));
    return true;
  }
});

// ─── Tab navigation listener ────────────────────────────────────────────────
// Catches address bar navigation, search result clicks that open in same tab,
// and any redirect — content.js scanCurrentPage() is the primary handler,
// but this pushes the result back as a message for extra reliability.

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  const url = tab.url || "";
  if (!url.startsWith("http")) return;
  // Skip warning.html itself to avoid redirect loop
  if (url.includes("warning.html")) return;

  // Skip if user already chose to proceed on this URL
  if (await isAllowed(url)) return;

  const result = await scanUrl(url);
  if (!result || result.verdict === "Safe" || result.verdict === "Unknown") return;

  // Push result to content script so it can show the overlay
  try {
    await chrome.tabs.sendMessage(tabId, { type: "SHOW_RESULT", result });
  } catch (_) {}

  // For dangerous sites, redirect to block page
  if (result.verdict === "Dangerous") {
    await blockTab(tabId, url, result);
  }
});

// ─── Start polling ───────────────────────────────────────────────────────────

setInterval(pollTokens, TOKEN_POLL_INTERVAL);
pollTokens(); // immediate first poll
