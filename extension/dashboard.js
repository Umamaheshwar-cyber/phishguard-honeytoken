// dashboard.js — PhishGuard Dashboard

function sendMsg(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...payload }, resolve);
  });
}

function formatDate(str) {
  if (!str) return "—";
  try {
    return new Date(str).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
  } catch (_) { return str; }
}

function verdictBadge(v) {
  const cls = { Safe: "safe", Suspicious: "suspicious", Dangerous: "dangerous" }[v] || "unknown";
  return `<span class="badge badge-${cls}">${v || "Unknown"}</span>`;
}

// ─── Stats ────────────────────────────────────────────────────────────────────

async function loadStats() {
  const stats = await sendMsg("GET_STATS");
  if (!stats) {
    document.getElementById("status-dot").className = "status-dot";
    document.getElementById("status-text").textContent = "Backend offline";
    return;
  }
  document.getElementById("status-dot").className = "status-dot online";
  document.getElementById("status-text").textContent = "Backend online";

  document.getElementById("s-total").textContent = stats.total_scans;
  document.getElementById("s-safe").textContent = stats.safe;
  document.getElementById("s-sus").textContent = stats.suspicious;
  document.getElementById("s-dan").textContent = stats.dangerous;
  document.getElementById("s-tok-active").textContent = stats.tokens_active;
  document.getElementById("s-tok-trig").textContent = stats.tokens_triggered;
}

// ─── Scans ────────────────────────────────────────────────────────────────────

async function loadScans() {
  document.getElementById("scans-spinner").style.display = "block";
  document.getElementById("scans-table").style.display = "none";
  document.getElementById("scans-empty").style.display = "none";

  const scans = await sendMsg("GET_SCANS") || [];
  document.getElementById("scans-spinner").style.display = "none";
  document.getElementById("scan-count").textContent = `${scans.length} records`;

  if (!scans.length) {
    document.getElementById("scans-empty").style.display = "block";
    return;
  }

  const tbody = document.getElementById("scans-body");
  tbody.innerHTML = "";

  scans.forEach((s, i) => {
    const reasons = Array.isArray(s.reasons) ? s.reasons : [];
    const mitre = Array.isArray(s.mitre_tags) ? s.mitre_tags : [];
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="color:#57606a">${i + 1}</td>
      <td><div class="url-cell" title="${s.url}">${s.url}</div></td>
      <td>${verdictBadge(s.verdict)}</td>
      <td><b style="color:${scoreColor(s.score)}">${s.score}</b>/100</td>
      <td><div class="reasons-cell">${reasons.slice(0, 3).join("<br>") || "—"}</div></td>
      <td><div class="mitre-cell">${mitre.slice(0, 2).join("<br>") || "—"}</div></td>
      <td style="white-space:nowrap;color:#57606a">${formatDate(s.scanned_at)}</td>
    `;
    tbody.appendChild(tr);
  });

  document.getElementById("scans-table").style.display = "table";
}

// ─── Tokens ───────────────────────────────────────────────────────────────────

async function loadTokens() {
  document.getElementById("tokens-spinner").style.display = "block";
  document.getElementById("tokens-table").style.display = "none";
  document.getElementById("tokens-empty").style.display = "none";

  const tokens = await sendMsg("GET_TOKENS") || [];
  document.getElementById("tokens-spinner").style.display = "none";
  document.getElementById("token-count").textContent = `${tokens.length} tokens`;

  if (!tokens.length) {
    document.getElementById("tokens-empty").style.display = "block";
    return;
  }

  const tbody = document.getElementById("tokens-body");
  tbody.innerHTML = "";

  tokens.forEach((t, i) => {
    const statusCls = t.status === "Triggered" ? "triggered" : "active";
    const tr = document.createElement("tr");
    if (t.status === "Triggered") tr.style.background = "#fff5f5";

    tr.innerHTML = `
      <td style="color:#57606a">${i + 1}</td>
      <td><b>${t.site}</b></td>
      <td><span class="mono">${t.token}</span> <button class="btn-copy" data-val="${t.token}">Copy</button></td>
      <td class="mono">${t.username}</td>
      <td class="mono">${t.password}</td>
      <td><span class="badge badge-${statusCls}">${t.status}</span></td>
      <td style="white-space:nowrap;color:#57606a">${formatDate(t.created_at)}</td>
      <td style="white-space:nowrap;color:${t.status === "Triggered" ? "#dc2626" : "#57606a"}">${formatDate(t.triggered_at)}</td>
    `;
    tbody.appendChild(tr);
  });

  document.getElementById("tokens-table").style.display = "table";

  // Copy buttons
  document.querySelectorAll(".btn-copy").forEach(btn => {
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(btn.dataset.val).then(() => {
        btn.textContent = "✓";
        setTimeout(() => { btn.textContent = "Copy"; }, 1200);
      });
    });
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scoreColor(score) {
  if (score >= 60) return "#dc2626";
  if (score >= 30) return "#d97706";
  return "#16a34a";
}

// ─── Tabs ─────────────────────────────────────────────────────────────────────

document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

// ─── Refresh ──────────────────────────────────────────────────────────────────

async function loadAll() {
  await Promise.all([loadStats(), loadScans(), loadTokens()]);
}

document.getElementById("btn-refresh").addEventListener("click", loadAll);

// ─── Init ─────────────────────────────────────────────────────────────────────

loadAll();
