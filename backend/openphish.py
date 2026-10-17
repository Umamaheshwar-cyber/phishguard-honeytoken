import requests
import threading
import time
import logging

logger = logging.getLogger(__name__)

OPENPHISH_URL = "https://openphish.com/feed.txt"
_blocklist: set = set()
_lock = threading.Lock()


def _fetch():
    global _blocklist
    try:
        resp = requests.get(OPENPHISH_URL, timeout=10)
        if resp.status_code == 200:
            lines = {line.strip().lower() for line in resp.text.splitlines() if line.strip()}
            with _lock:
                _blocklist = lines
            logger.info(f"[OpenPhish] Loaded {len(lines)} entries")
        else:
            logger.warning(f"[OpenPhish] HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"[OpenPhish] Fetch failed: {e}")


def _refresh_loop():
    while True:
        _fetch()
        time.sleep(3600)  # refresh every hour


def start():
    """Start background refresh thread."""
    t = threading.Thread(target=_refresh_loop, daemon=True)
    t.start()


def is_in_blocklist(url: str) -> bool:
    url_lower = url.lower()
    with _lock:
        # exact match
        if url_lower in _blocklist:
            return True
        # prefix match (blocklist entry is prefix of url)
        for entry in _blocklist:
            if url_lower.startswith(entry):
                return True
    return False
