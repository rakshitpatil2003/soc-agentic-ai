"""SOC Orchestrator: routes an alert through the agents with conditional logic, guardrails,
exception handling and a mandatory human approval gate.
Step roles:  A = Autonomous   H = Human-in-the-loop   E = Escalation
"""
import time

from . import agents, audit, config, guardrails, llm

RANK = {"Dismiss": 0, "Approve": 1, "Escalate": 2}


def run(alert, model_label=None, simulate_outage=False, progress=None, write_audit=True):
    T = config.THRESHOLDS
    t_start = time.perf_counter()
    steps, events = [], []

    def record(name, role, status, summary, data, t0):
        s = {"name": name, "role": role, "status": status, "summary": summary,
             "duration": round(time.perf_counter() - t0, 3), "data": data}
        steps.append(s)
        if progress:
            progress(s)
        return s

    # ── Step 0: ingest + validate ─────────────────────────────────────────
    t0 = time.perf_counter()
    if not isinstance(alert, dict) or not alert:
        record("Alert Ingestion", "A", "error", "Rejected: payload is not a JSON object", {}, t0)
        return {"status": "rejected", "steps": steps, "error": "Invalid alert payload"}
    alert_id = str(alert.get("alert_id", "UNKNOWN"))
    record("Alert Ingestion", "A", "ok", f"Alert {alert_id} received from {alert.get('source', 'unknown source')}", {}, t0)

    # ── Step 1: correlation (fatal if it fails) ───────────────────────────
    t0 = time.perf_counter()
    try:
        corr = agents.alert_correlation_agent(alert)
    except Exception as e:  # noqa: BLE001
        record("Alert Correlation Agent", "A", "error", f"Failed: {e}", {}, t0)
        return {"status": "failed", "steps": steps, "error": str(e)}
    record("Alert Correlation Agent", "A", "ok",
           f"{len(corr['indicators'])} indicators, signals={corr['signals'] or 'none'}, {corr['masks_applied']} items masked",
           {k: v for k, v in corr.items() if k != "masked_payload"}, t0)

    # ── Step 2: injection guardrail ───────────────────────────────────────
    t0 = time.perf_counter()
    if corr["injection_findings"]:
        events.append({"guardrail": "Prompt-injection filter",
                       "detail": f"{len(corr['injection_findings'])} suspicious phrase(s) neutralised",
                       "findings": corr["injection_findings"]})
        record("Input Guardrail", "A", "warn", "Prompt injection detected and neutralised before LLM call", corr["injection_findings"], t0)
    else:
        record("Input Guardrail", "A", "ok", "No injection patterns found; PII/secrets masked", {}, t0)

    # ── Step 3/4: threat intel + asset context (degrade gracefully) ───────
    t0 = time.perf_counter()
    try:
        intel = agents.threat_intel_agent(corr["indicators"])
        record("Threat Intelligence Agent", "A", "ok",
               f"Verdict: {intel['verdict']} ({intel['actor']}), {len(intel['findings'])} IOC match(es)", intel, t0)
    except Exception as e:  # noqa: BLE001
        intel = {"findings": [], "verdict": "unknown", "confidence": 0.0, "actor": "Unknown", "unmatched": corr["indicators"]}
        events.append({"guardrail": "Exception handling", "detail": f"Threat intel lookup failed: {e}"})
        record("Threat Intelligence Agent", "A", "error", f"Lookup failed, continuing with 'unknown': {e}", {}, t0)

    t0 = time.perf_counter()
    try:
        asset = agents.asset_context_agent(alert)
        record("Asset Context Agent", "A", "ok",
               f"Criticality {asset['criticality']}/5, vendor access: {asset['vendor_access']}", asset, t0)
    except Exception as e:  # noqa: BLE001
        asset = {"assets": [], "network": None, "criticality": 3, "vendor_access": False, "gaps": ["Asset lookup failed"]}
        events.append({"guardrail": "Exception handling", "detail": f"Asset lookup failed: {e}"})
        record("Asset Context Agent", "A", "error", f"Lookup failed, assuming criticality 3: {e}", {}, t0)

    # ── Step 5: deterministic risk scoring ────────────────────────────────
    t0 = time.perf_counter()
    risk = agents.risk_agent(corr, intel, asset)
    record("Risk / Prioritisation Agent", "A", "ok", f"Risk {risk['score']} → {risk['severity']}", risk, t0)

    # ── Step 6: conditional routing decision ──────────────────────────────
    t0 = time.perf_counter()
    incomplete = bool(corr["missing_fields"] or asset["gaps"])
    if corr["injection_findings"]:
        path = "Guarded path (injection suspected)"
    elif incomplete:
        path = "Exception path (incomplete evidence)"
    elif risk["score"] >= T["high_min"]:
        path = "High-risk path"
    elif risk["score"] >= T["low_max"]:
        path = "Ambiguous path (needs human judgement)"
    else:
        path = "Standard path (low risk)"
    record("Orchestrator Routing", "A", "ok", f"Selected: {path}", {"path": path}, t0)

    # ── Step 7: Incident Summary Agent (LLM) with fallback ────────────────
    t0 = time.perf_counter()
    model_id, llm_meta = None, {"first_try_ok": False, "retries": 0, "latency": 0.0, "ungrounded": [], "errors": [], "ok": False}
    degraded, reason = False, ""
    if model_label and llm.has_key():
        model_id = next((m["id"] for m in config.load_models() if m["label"] == model_label), None)
    if model_id:
        llm_meta = agents.incident_summary_agent(model_id, corr, intel, asset, simulate_outage)
        summary = llm_meta["summary"]
        if not llm_meta["ok"]:
            degraded, reason = True, "; ".join(llm_meta["errors"])[:160] or "LLM output invalid"
    else:
        degraded, reason = True, "demo mode (no API key / model selected)"
    if degraded:
        summary = agents.deterministic_summary(corr, intel, asset, risk, reason)
        events.append({"guardrail": "Exception handling", "detail": f"Degraded mode: {reason}"})
        record("Incident Summary Agent", "A", "warn", f"LLM unavailable → rule-based fallback ({reason})", summary, t0)
    else:
        record("Incident Summary Agent", "A", "ok",
               f"{model_label}: risk {summary['Risk_Score']}, action {summary['Recommended_HITL_Action']} "
               f"({llm_meta['latency']:.1f}s, retries={llm_meta['retries']})", summary, t0)
        if llm_meta["ungrounded"]:
            events.append({"guardrail": "Grounding check",
                           "detail": f"Model mentioned indicators not in evidence: {llm_meta['ungrounded']}"})

    # ── Step 8: governance reconciliation (action guardrails) ─────────────
    t0 = time.perf_counter()
    flags = []
    if corr["injection_findings"]:
        flags.append("prompt_injection_detected")
    if degraded:
        flags.append("llm_unavailable")
    if incomplete:
        flags.append("incomplete_evidence")
    if abs(summary["Risk_Score"] - risk["score"]) > T["disagreement"]:
        flags.append("model_vs_engine_disagreement")
    if llm_meta["ungrounded"]:
        flags.append("ungrounded_indicators")

    forcing = [f for f in flags if f != "llm_unavailable"]  # fallback is informational; engine score still decides
    if risk["score"] >= T["low_max"] or forcing:
        policy = "Escalate"
    elif risk["score"] < 2.0 and intel["verdict"] == "benign":  # known-good, very low risk
        policy = "Dismiss"
    else:
        policy = "Approve"
    llm_action = summary["Recommended_HITL_Action"]
    final = max([llm_action, policy], key=lambda a: RANK[a])  # never less cautious than policy
    if final != llm_action:
        events.append({"guardrail": "Action override",
                       "detail": f"Model proposed '{llm_action}' but policy requires '{final}' (risk {risk['score']}, flags {flags or 'none'})"})
    if final == "Escalate":
        route = "Incident Commander" if risk["score"] >= T["commander_min"] else "Tier 2 Analyst"
    elif final == "Approve":
        route = "Auto-remediation (awaiting analyst approval)"
    else:
        route = "Close as false positive (awaiting analyst approval)"
    record("Governance Check", "A", "ok", f"Final action: {final} → {route}", {"flags": flags, "policy_action": policy}, t0)

    # ── Step 9: HITL gate (execution paused) ──────────────────────────────
    t0 = time.perf_counter()
    role = "E" if final == "Escalate" else "H"
    record("HITL Decision Gate", role, "pending", "Execution paused. Awaiting human analyst decision.", {"route": route}, t0)

    result = {
        "status": "awaiting_human", "alert_id": alert_id, "model": model_label if not degraded else f"{model_label or 'none'} (fallback)",
        "path": path, "risk": risk, "summary": summary, "llm": llm_meta, "degraded": degraded,
        "final_action": final, "policy_action": policy, "route": route, "flags": flags,
        "guardrail_events": events, "steps": steps, "total_latency": round(time.perf_counter() - t_start, 2),
        "intel": intel, "asset": asset, "corr": corr,
    }
    if write_audit:
        audit.log_event("workflow_completed", alert_id, "SOC-Orchestrator", {
            "model": result["model"], "path": path, "risk": risk["score"], "severity": risk["severity"],
            "llm_action": llm_action, "final_action": final, "route": route, "flags": flags,
            "guardrail_events": [e["detail"] for e in events]})
    return result
