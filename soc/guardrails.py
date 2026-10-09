"""Data, model and action guardrails (Stage 4)."""
import hashlib
import json
import re

from . import config

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_RE = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})\b|(?:api[_-]?key|secret|token|passwd|password)\s*[=:]\s*\S+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|in|ru|cn|biz|info|xyz|top|example|test|invalid|local|corp|internal)\b", re.I)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|prompts?)",
    r"disregard (the )?(system|previous|above|prior)",
    r"mark (this )?(alert )?as (benign|dismiss|false positive|safe)",
    r"do not (escalate|alert|report)",
    r"recommended[_ ]?(hitl[_ ])?action\s*[:=]\s*\"?dismiss",
    r"you are now\b",
    r"reveal (the )?system prompt",
    r"\bjailbreak\b",
]
INJECTION_RE = re.compile("|".join(f"(?:{p})" for p in INJECTION_PATTERNS), re.I)


# ---------- Data guardrails: privacy / confidentiality ----------
def mask_text(text):
    """Mask e-mails and secrets. Returns (masked_text, number_of_masks)."""
    n = 0
    def _sub(label):
        def inner(m):
            nonlocal n
            n += 1
            return label
        return inner
    text = EMAIL_RE.sub(_sub("[EMAIL]"), text)
    text = SECRET_RE.sub(_sub("[REDACTED_SECRET]"), text)
    return text, n


def mask_payload(obj, _key=None):
    """Recursively mask a JSON-like object. Returns (masked_obj, mask_count)."""
    if isinstance(obj, dict):
        out, total = {}, 0
        for k, v in obj.items():
            if k == "user" and isinstance(v, str) and v:
                out[k] = "USER-" + hashlib.sha256(v.encode()).hexdigest()[:6]
                total += 1
            else:
                out[k], c = mask_payload(v, k)
                total += c
        return out, total
    if isinstance(obj, list):
        res = [mask_payload(i) for i in obj]
        return [r[0] for r in res], sum(r[1] for r in res)
    if isinstance(obj, str):
        clean = "".join(ch for ch in obj if ch == "\n" or ch == "\t" or ord(ch) >= 32)[:2000]
        return mask_text(clean)
    return obj, 0


# ---------- Model guardrails: prompt injection ----------
def find_injection(obj, path="alert"):
    """Return list of {field, match} for suspected prompt-injection phrases."""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            hits += find_injection(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += find_injection(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        for m in INJECTION_RE.finditer(obj):
            hits.append({"field": path, "match": m.group(0)})
    return hits


def neutralise_injection(obj):
    """Replace injection phrases with a neutral marker before the text reaches the LLM."""
    if isinstance(obj, dict):
        return {k: neutralise_injection(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [neutralise_injection(v) for v in obj]
    if isinstance(obj, str):
        return INJECTION_RE.sub("[REMOVED: suspected prompt injection]", obj)
    return obj


# ---------- Model guardrails: structured output + grounding ----------
def extract_indicators(text):
    t = text or ""
    found = set(IP_RE.findall(t)) | {d.lower() for d in DOMAIN_RE.findall(t)} | {h.lower() for h in HASH_RE.findall(t)}
    return found


def ungrounded_indicators(llm_text, context_text):
    """Indicators the model mentions that were NOT in the evidence we supplied (hallucination proxy)."""
    return sorted(extract_indicators(llm_text) - extract_indicators(context_text))


def parse_json_object(raw):
    raw = (raw or "").strip()
    raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.M).strip()
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in model output")
    return json.loads(raw[start:end + 1])


def validate_output(obj):
    """Strict schema check. Returns (ok, errors, normalised)."""
    errors = []
    need = ["Risk_Score", "Threat_Summary", "Missing_Context", "Recommended_HITL_Action"]
    if not isinstance(obj, dict):
        return False, ["output is not a JSON object"], None
    for k in need:
        if k not in obj:
            errors.append(f"missing key {k}")
    if errors:
        return False, errors, None
    rs = obj["Risk_Score"]
    if isinstance(rs, bool) or not isinstance(rs, (int, float)) or not (1 <= rs <= 10):
        errors.append("Risk_Score must be a number 1-10")
    if not isinstance(obj["Threat_Summary"], str) or not obj["Threat_Summary"].strip():
        errors.append("Threat_Summary must be a non-empty string")
    if not isinstance(obj["Missing_Context"], list):
        errors.append("Missing_Context must be an array")
    if obj["Recommended_HITL_Action"] not in config.VALID_ACTIONS:
        errors.append("Recommended_HITL_Action must be Approve, Escalate or Dismiss")
    if errors:
        return False, errors, None
    norm = {
        "Risk_Score": float(rs),
        "Threat_Summary": obj["Threat_Summary"].strip(),
        "Missing_Context": [str(x) for x in obj["Missing_Context"]],
        "Recommended_HITL_Action": obj["Recommended_HITL_Action"],
    }
    return True, [], norm
