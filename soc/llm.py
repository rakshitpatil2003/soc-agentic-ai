"""Minimal OpenAI-compatible chat client (works with OpenRouter, Groq, Together, Ollama, etc.)."""
import os
import time
import requests


class LLMError(Exception):
    pass


def settings():
    return {
        "key": os.getenv("LLM_API_KEY", "").strip(),
        "base": os.getenv("LLM_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/"),
    }


def has_key():
    return bool(settings()["key"])


def chat(model_id, system, user, timeout=60, max_tokens=500):
    """Returns (text, latency_seconds). Raises LLMError on any failure."""
    s = settings()
    if not s["key"]:
        raise LLMError("No LLM_API_KEY configured")
    payload = {
        "model": model_id,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0,
        "max_tokens": max_tokens,
    }
    headers = {"Authorization": f"Bearer {s['key']}", "Content-Type": "application/json"}
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{s['base']}/chat/completions", json=payload, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        raise LLMError(f"Network/timeout error: {e}") from e
    latency = time.perf_counter() - t0
    if r.status_code != 200:
        raise LLMError(f"HTTP {r.status_code} from provider: {r.text[:200]}")
    try:
        text = r.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, ValueError) as e:
        raise LLMError(f"Unexpected provider response: {r.text[:200]}") from e
    return text, latency
