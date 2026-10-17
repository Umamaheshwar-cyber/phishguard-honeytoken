import re
from urllib.parse import urlparse
from typing import List, Tuple

# ─── Rule weights ────────────────────────────────────────────────────────────
# Each rule returns (score_delta: int, reason: str) or None

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".loan", ".work", ".date", ".racing", ".download", ".stream",
    ".gdn", ".bid", ".win", ".accountant", ".science", ".faith"
}

# Brand names intentionally excluded — they match legit domains (google.com, apple.com etc.)
# Only include action/threat words that appear in phishing paths
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "password", "confirm", "wallet",
    "support", "invoice", "suspended", "urgent", "alert", "validate",
    "webscr", "ebayisapi", "cmd=_login",
]

MITRE_MAP = {
    "OpenPhish blocklist match": "T1566.002 - Spearphishing Link",
    "IP address used as host": "T1583.005 - Botnet",
    "@ symbol in URL": "T1566.001 - Spearphishing Attachment",
    "Punycode / IDN domain": "T1566.002 - Spearphishing Link",
    "Suspicious TLD": "T1583.001 - Domains",
    "Phishing keyword in URL": "T1566 - Phishing",
    "No HTTPS": "T1040 - Network Sniffing",
    "Excessive subdomains": "T1583.001 - Domains",
    "Excessively long URL": "T1566 - Phishing",
    "Suspicious URL redirect pattern": "T1566 - Phishing",
}


# Trusted domains — never flag keyword matches on these
TRUSTED_DOMAINS = {
    "google.com", "google.co.in", "googleapis.com",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.in",
    "paypal.com",
    "ebay.com",
    "netflix.com",
    "github.com", "githubusercontent.com",
    "youtube.com", "youtu.be",
    "twitter.com", "x.com",
    "facebook.com", "instagram.com",
    "linkedin.com",
    "wikipedia.org",
    "stackoverflow.com",
}


def _is_trusted(host: str) -> bool:
    """Return True if host is a known trusted domain or subdomain of one."""
    host = host.lower().lstrip("www.")
    if host in TRUSTED_DOMAINS:
        return True
    for td in TRUSTED_DOMAINS:
        if host.endswith("." + td):
            return True
    return False


def analyze_url(url: str, in_blocklist: bool) -> Tuple[int, List[str], List[str]]:
    """
    Returns (total_score, reasons_list, mitre_tags_list).
    score 0-100. 0=clean, 100=definitely phishing.
    """
    score = 0
    reasons: List[str] = []
    mitre_tags: List[str] = []

    def add(delta: int, reason: str):
        nonlocal score
        score += delta
        reasons.append(f"{reason} (+{delta})")
        tag = MITRE_MAP.get(reason)
        if tag and tag not in mitre_tags:
            mitre_tags.append(tag)

    # ── 1. OpenPhish blocklist ──────────────────────────────────────────────
    if in_blocklist:
        add(80, "OpenPhish blocklist match")

    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        host = parsed.hostname or ""
        path = parsed.path or ""
        # host+path only — exclude query string to avoid UTM/tracking false positives
        host_path = (host + path).lower()
        full = url.lower()

        # ── 2. IP address as host ───────────────────────────────────────────
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if ip_pattern.match(host):
            add(30, "IP address used as host")

        # ── 3. @ symbol in URL ──────────────────────────────────────────────
        if "@" in url:
            add(25, "@ symbol in URL")

        # ── 4. Punycode / IDN ───────────────────────────────────────────────
        if "xn--" in host.lower():
            add(25, "Punycode / IDN domain")

        # ── 5. Suspicious TLD ───────────────────────────────────────────────
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                add(20, "Suspicious TLD")
                break

        # ── 6. Excessive subdomains (>3) ────────────────────────────────────
        parts = host.split(".")
        if len(parts) > 4:
            add(15, "Excessive subdomains")

        # ── 7. Long URL — measure host+path only, ignore query string ────────
        if len(host + path) > 75:
            add(10, "Excessively long URL")

        # ── 8. No HTTPS ─────────────────────────────────────────────────────
        if parsed.scheme == "http":
            add(10, "No HTTPS")

        # ── 9. Phishing keywords — host+path only, skip trusted domains ──────
        if not _is_trusted(host):
            keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in host_path]
            if keyword_hits:
                add(min(len(keyword_hits) * 8, 24), "Phishing keyword in URL")

        # ── 10. Redirect pattern ────────────────────────────────────────────
        if re.search(r"(redirect|url=|next=|goto=|return=)", full):
            add(15, "Suspicious URL redirect pattern")

    except Exception:
        pass

    score = min(score, 100)
    return score, reasons, mitre_tags


def verdict(score: int) -> str:
    if score >= 60:
        return "Dangerous"
    if score >= 30:
        return "Suspicious"
    return "Safe"
