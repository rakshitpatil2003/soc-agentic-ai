"""Tamper-evident audit log: JSON-lines file where each entry hashes the previous one."""
import hashlib
import json
from datetime import datetime, timezone

from . import config

LOG_FILE = config.LOG_DIR / "audit.jsonl"
_MEMORY = []  # fallback if the file system is read-only


def _hash(entry, prev):
    body = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256((prev + body).encode()).hexdigest()


def read_events():
    try:
        if LOG_FILE.exists():
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
    except OSError:
        pass
    return list(_MEMORY)


def log_event(event, alert_id, actor, details=None):
    events = read_events()
    prev = events[-1]["hash"] if events else "GENESIS"
    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "event": event, "alert_id": alert_id, "actor": actor,
        "details": details or {}, "prev_hash": prev,
    }
    entry["hash"] = _hash({k: v for k, v in entry.items() if k != "hash"}, prev)
    try:
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        _MEMORY.append(entry)
    return entry


def verify_chain():
    """Returns (ok, message)."""
    prev = "GENESIS"
    for i, e in enumerate(read_events()):
        body = {k: v for k, v in e.items() if k != "hash"}
        if e.get("prev_hash") != prev or _hash(body, prev) != e.get("hash"):
            return False, f"Chain broken at entry #{i + 1}"
        prev = e["hash"]
    return True, "Audit chain verified: no tampering detected"
