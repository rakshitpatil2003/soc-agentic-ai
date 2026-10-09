"""The five specialised agents. Agents 1-4 are tool/data agents, agent 5 uses the LLM."""
import json

from . import config, guardrails, llm

VERDICT_RANK = {"unknown": 0, "benign": 1, "suspicious": 2, "malicious": 3}


# 1 ─ Alert Correlation Agent ------------------------------------------------
def alert_correlation_agent(alert):
    masked, n_masked = guardrails.mask_payload(alert)
    injection = guardrails.find_injection(alert)
    safe_payload = guardrails.neutralise_injection(masked)

    corpus = json.dumps(masked, ensure_ascii=False)
    indicators = sorted(guardrails.extract_indicators(corpus))

    signals = set()
    cat = str(alert.get("category", "")).lower()
    if cat in config.SIGNAL_WEIGHTS:
        signals.add(cat)
    # brute force = failed-login burst AND a later successful login
    ev_types = {str(e.get("type", "")).lower() for e in alert.get("related_events", []) or []}
    if cat == "authentication" and {"failed_login_burst", "successful_login"} <= ev_types:
        signals.add("brute_force_success")
    missing = [f for f in config.REQUIRED_FIELDS if not str(alert.get(f, "")).strip()]
    mitigated = str(alert.get("action_taken", "")).lower() in ("quarantined", "blocked")
    return {
        "masked_payload": safe_payload, "masks_applied": n_masked, "indicators": indicators,
        "signals": sorted(signals), "missing_fields": missing, "mitigated": mitigated,
        "injection_findings": injection,
    }


# 2 ─ Threat Intelligence Agent ---------------------------------------------
def threat_intel_agent(indicators):
    db = config.load_json("threat_intel.json")["indicators"]
    findings = []
    for ioc in indicators:
        hit = db.get(ioc) or db.get(ioc.lower())
        if hit:
            findings.append({"indicator": ioc, **hit})
    verdict, conf, actor = "unknown", 0.0, "Unknown"
    for f in findings:
        if VERDICT_RANK[f["verdict"]] > VERDICT_RANK[verdict]:
            verdict, conf, actor = f["verdict"], f["confidence"], f["actor"]
    return {"findings": findings, "verdict": verdict, "confidence": conf, "actor": actor,
            "unmatched": [i for i in indicators if i not in {f['indicator'] for f in findings}]}


# 3 ─ Asset Context Agent ----------------------------------------------------
def asset_context_agent(alert):
    data = config.load_json("assets.json")
    hosts, nets = data["hosts"], data["networks"]
    involved, gaps = [], []
    for key in ("dst_host", "src_host"):
        name = str(alert.get(key, "")).strip()
        if name and name in hosts:
            involved.append({"host": name, **hosts[name]})
        elif name and key == "dst_host":
            gaps.append(f"{name} not found in CMDB")
    network = None
    ip = str(alert.get("src_ip", ""))
    for prefix, info in nets.items():
        if ip.startswith(prefix):
            network = {"prefix": prefix, **info}
            break
    crit = max([h["criticality"] for h in involved], default=3)  # unknown asset -> assume medium
    return {"assets": involved, "network": network, "criticality": crit,
            "vendor_access": bool(network and network["vendor_access"]), "gaps": gaps}


# 4 ─ Risk / Prioritisation Agent --------------------------------------------
def risk_agent(corr, intel, asset):
    parts = [("Asset criticality", float(asset["criticality"]))]
    for s in corr["signals"]:
        w = config.SIGNAL_WEIGHTS.get(s, 0.0)
        if w:
            parts.append((f"Behaviour: {s}", w))
    w = config.INTEL_WEIGHTS.get(intel["verdict"], 0.0)
    if w:
        parts.append((f"Threat intel: {intel['verdict']} (conf {intel['confidence']})", round(w * intel["confidence"], 2)))
    if asset["vendor_access"]:
        parts.append(("Source is third-party vendor network", config.VENDOR_ACCESS_POINTS))
    if corr["mitigated"]:
        parts.append(("Already mitigated by EDR/WAF", config.MITIGATED_POINTS))
    score = round(min(10.0, max(1.0, sum(p for _, p in parts))), 1)
    return {"score": score, "severity": config.severity_band(score),
            "breakdown": [{"factor": f, "points": p} for f, p in parts]}


# 5 ─ Incident Summary Agent (LLM) -------------------------------------------
def build_user_prompt(corr, intel, asset):
    evidence = {
        "alert": corr["masked_payload"],
        "detected_signals": corr["signals"],
        "already_mitigated": corr["mitigated"],
        "missing_fields": corr["missing_fields"],
        "threat_intel": {"verdict": intel["verdict"], "confidence": intel["confidence"],
                         "actor": intel["actor"], "findings": intel["findings"]},
        "asset_context": {"assets": asset["assets"], "network": asset["network"],
                          "criticality_1_to_5": asset["criticality"], "cmdb_gaps": asset["gaps"]},
    }
    return "<ALERT_DATA>\n" + json.dumps(evidence, indent=1, ensure_ascii=False) + "\n</ALERT_DATA>\nReturn the JSON object now."


def deterministic_summary(corr, intel, asset, risk, reason):
    """Degraded-mode summary when the LLM is unavailable (exception handling path)."""
    miss = list(corr["missing_fields"]) + asset["gaps"]
    if intel["verdict"] == "unknown":
        miss.append("No threat-intel match for observed indicators")
    action = "Escalate" if risk["score"] >= config.THRESHOLDS["low_max"] else "Approve"
    text = (f"[Rule-based summary - {reason}] {risk['severity']} severity (score {risk['score']}). "
            f"Signals: {', '.join(corr['signals']) or 'none'}. Intel verdict: {intel['verdict']}.")
    return {"Risk_Score": risk["score"], "Threat_Summary": text, "Missing_Context": miss,
            "Recommended_HITL_Action": action}


def incident_summary_agent(model_id, corr, intel, asset, simulate_outage=False):
    """Calls the LLM; validates schema; one stricter retry. Returns dict with metrics for benchmarking."""
    user = build_user_prompt(corr, intel, asset)
    out = {"ok": False, "summary": None, "first_try_ok": False, "retries": 0, "latency": 0.0,
           "raw": "", "errors": [], "ungrounded": []}
    prompt = user
    for attempt in range(2):
        try:
            if simulate_outage:
                raise llm.LLMError("Simulated LLM outage (demo toggle)")
            raw, lat = llm.chat(model_id, config.SYSTEM_PROMPT, prompt)
            out["latency"] += lat
            out["raw"] = raw
            obj = guardrails.parse_json_object(raw)
            ok, errs, norm = guardrails.validate_output(obj)
        except llm.LLMError as e:
            out["errors"].append(str(e))
            break  # provider problems: do not hammer the API, fall back
        except (ValueError, json.JSONDecodeError) as e:
            ok, errs, norm = False, [f"invalid JSON: {e}"], None
        if ok:
            out.update(ok=True, summary=norm, first_try_ok=(attempt == 0), retries=attempt)
            text = norm["Threat_Summary"] + " " + " ".join(norm["Missing_Context"])
            out["ungrounded"] = guardrails.ungrounded_indicators(text, user)
            return out
        out["errors"] += errs
        out["retries"] = attempt + 1
        prompt = user + "\nYour previous reply was invalid (" + "; ".join(errs) + "). Reply with ONLY the JSON object."
    return out
