# 🛡️ PhishGuard + PhishTrap + Honeytoken

Real-time phishing detection Chrome extension with explainable scores, overlay cards, and deception technology honeytokens.

---

## 📁 Project Structure

```
phishing guard/
├── backend/
│   ├── main.py           ← FastAPI app (all endpoints)
│   ├── rules.py          ← Detection rules engine + scoring
│   ├── models.py         ← SQLite schema + helpers
│   ├── openphish.py      ← OpenPhish blocklist cache (auto-refresh hourly)
│   ├── requirements.txt
│   └── phishguard.db     ← Auto-created on first run
└── extension/
    ├── manifest.json     ← MV3 Chrome Extension
    ├── background.js     ← Service worker (API proxy, cache, notifications)
    ├── content.js        ← Hover/click intercept + overlay card
    ├── popup.html/js     ← Extension popup (current tab score)
    ├── warning.html      ← Dangerous site block page
    ├── dashboard.html/js ← Stats, scans, PhishTrap token table
    └── icons/            ← icon16.png, icon48.png, icon128.png
```

---

## 🚀 Setup & Run

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

Backend starts at `http://localhost:8000`  
API docs: `http://localhost:8000/docs`

### 2. Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Pin PhishGuard to toolbar

### 3. Icons (required)

Add 3 PNG icons to `extension/icons/`:
- `icon16.png` (16×16)
- `icon48.png` (48×48)  
- `icon128.png` (128×128)

> Quick option: use any shield/guard PNG and resize. Free icons at [flaticon.com](https://www.flaticon.com) or [icons8.com](https://icons8.com).

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/analyze` | Scan URL → score, verdict, reasons, MITRE tags |
| `POST` | `/token/create` | Create PhishTrap honeytoken for a site |
| `POST` | `/decoy-login` | Tripwire: attacker submits fake creds → token triggered |
| `GET` | `/tokens` | List all honeytokens |
| `GET` | `/scans` | List recent scans |
| `GET` | `/stats` | Aggregate stats |
| `GET` | `/token/status/{token}` | Check if a specific token was triggered |

---

## 🔍 Detection Rules

| Rule | Weight |
|------|--------|
| OpenPhish blocklist match | +80 |
| IP address as host | +30 |
| @ symbol in URL | +25 |
| Punycode / IDN domain | +25 |
| Suspicious TLD (.tk, .ml, .xyz…) | +20 |
| Excessive subdomains (>4 parts) | +15 |
| Redirect pattern in URL | +15 |
| No HTTPS | +10 |
| Long URL (>75 chars) | +10 |
| Phishing keywords | +8 per keyword (max +24) |

**Verdict thresholds:**
- `0–29` → ✅ Safe
- `30–59` → ⚠️ Suspicious  
- `60–100` → 🚨 Dangerous

---

## 🪤 PhishTrap Flow

```
Dangerous site detected
        ↓
User clicks "PhishTrap" button
        ↓
Backend generates unique honeytoken + fake credentials
        ↓
Extension shows fake creds to user / auto-fills form
        ↓
Decoy submitted to /decoy-login tripwire endpoint
        ↓
Attacker uses fake creds elsewhere → token status = "Triggered"
        ↓
Chrome notification fires → Dashboard shows triggered token
```

---

## 🔒 Security Concepts (Viva)

| Concept | Implementation |
|---------|----------------|
| **MITRE ATT&CK T1566** | Phishing link detection |
| **MITRE ATT&CK T1056** | Input capture detection (password fields) |
| **Deception Technology** | Honeytokens via PhishTrap |
| **Explainable AI/Detection** | Rule weights + human-readable reasons |
| **Privacy-first** | 100% localhost, zero cloud data |
| **Ethical bounds** | Only fake credentials, no real passwords ever |

---

## 🧪 Testing

Use these for safe testing:
- [PhishTank](https://www.phishtank.com) — reported phishing URLs
- Craft a local `localhost` dummy phishing page  
- URLs with suspicious TLDs, IPs, or punycode

---

## ⚠️ Ethics & Disclaimer

- Only fake/decoy credentials are used — no real user passwords are ever captured
- PhishTrap is for **defensive deception** only
- Test only on PhishTank-reported URLs or your own dummy pages
- Do not use on real users without consent
