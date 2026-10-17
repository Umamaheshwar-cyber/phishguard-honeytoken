import uuid
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from models import init_db, get_conn
from rules import analyze_url, verdict
import openphish

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    openphish.start()
    logger.info("PhishGuard backend started")
    yield


app = FastAPI(title="PhishGuard API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Chrome extension origin is chrome-extension://...
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Schemas ─────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str

class TokenCreateRequest(BaseModel):
    site: str

class DecoyLoginRequest(BaseModel):
    token: str
    username: str
    password: str


# ─── /analyze ────────────────────────────────────────────────────────────────

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    in_bl = openphish.is_in_blocklist(url)
    score, reasons, mitre_tags = analyze_url(url, in_bl)
    verd = verdict(score)

    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO scans (url, score, verdict, reasons, mitre_tags) VALUES (?,?,?,?,?)",
            (url, score, verd, json.dumps(reasons), json.dumps(mitre_tags))
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "url": url,
        "score": score,
        "verdict": verd,
        "reasons": reasons,
        "mitre_tags": mitre_tags,
        "in_blocklist": in_bl,
    }


# ─── /token/create ───────────────────────────────────────────────────────────

@app.post("/token/create")
def token_create(req: TokenCreateRequest):
    site = req.site.strip()
    if not site:
        raise HTTPException(status_code=400, detail="site is required")

    token = str(uuid.uuid4()).replace("-", "")[:16]
    username = f"user_{token[:6]}@decoy.phishguard"
    password = f"P@ss_{token[6:14]}!trap"

    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO tokens (site, token, username, password) VALUES (?,?,?,?)",
            (site, token, username, password)
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "token": token,
        "site": site,
        "username": username,
        "password": password,
    }


# ─── /decoy-login (tripwire) ─────────────────────────────────────────────────

@app.post("/decoy-login")
def decoy_login(req: DecoyLoginRequest):
    """Attacker submits fake creds → token triggered."""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM tokens WHERE token = ?", (req.token,)
        ).fetchone()

        if not row:
            # Silently accept — don't reveal it's a trap
            return {"status": "ok"}

        if row["status"] == "Active":
            conn.execute(
                "UPDATE tokens SET status='Triggered', triggered_at=? WHERE token=?",
                (datetime.utcnow().isoformat(), req.token)
            )
            conn.commit()
            logger.warning(f"[TRIPWIRE] Token {req.token} TRIGGERED for site {row['site']}")

    finally:
        conn.close()

    return {"status": "ok"}


# ─── /tokens ─────────────────────────────────────────────────────────────────

@app.get("/tokens")
def get_tokens():
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM tokens ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ─── /scans ──────────────────────────────────────────────────────────────────

@app.get("/scans")
def get_scans(limit: int = 50):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["reasons"] = json.loads(d["reasons"])
            d["mitre_tags"] = json.loads(d["mitre_tags"])
            result.append(d)
        return result
    finally:
        conn.close()


# ─── /stats ──────────────────────────────────────────────────────────────────

@app.get("/stats")
def get_stats():
    conn = get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        dangerous = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict='Dangerous'").fetchone()[0]
        suspicious = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict='Suspicious'").fetchone()[0]
        safe = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict='Safe'").fetchone()[0]
        tokens_active = conn.execute("SELECT COUNT(*) FROM tokens WHERE status='Active'").fetchone()[0]
        tokens_triggered = conn.execute("SELECT COUNT(*) FROM tokens WHERE status='Triggered'").fetchone()[0]
        return {
            "total_scans": total,
            "dangerous": dangerous,
            "suspicious": suspicious,
            "safe": safe,
            "tokens_active": tokens_active,
            "tokens_triggered": tokens_triggered,
        }
    finally:
        conn.close()


# ─── /token/status ───────────────────────────────────────────────────────────

@app.get("/token/status/{token}")
def token_status(token: str):
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT status, triggered_at FROM tokens WHERE token=?", (token,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Token not found")
        return dict(row)
    finally:
        conn.close()
