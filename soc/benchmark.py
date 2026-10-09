"""Runs every test case on every selected model with identical prompts/evidence and computes metrics."""
import pandas as pd

from . import config, orchestrator

SEV_ORDER = ["Low", "Medium", "High", "Critical"]


def run_benchmark(model_labels, cases, on_progress=None):
    rows, total, i = [], len(model_labels) * len(cases), 0
    for label in model_labels:
        for case in cases:
            i += 1
            if on_progress:
                on_progress(i, total, f"{label} · {case['alert']['alert_id']}")
            res = orchestrator.run(case["alert"], label, write_audit=False)
            truth = case["ground_truth"]
            m = res.get("llm", {})
            summ = m.get("summary") if m.get("ok") else None
            pred_sev = config.severity_band(summ["Risk_Score"]) if summ else "n/a"
            llm_action = summ["Recommended_HITL_Action"] if summ else "n/a"
            rows.append({
                "model": label, "case": case["name"], "alert_id": case["alert"]["alert_id"],
                "truth_severity": truth["severity"], "llm_severity": pred_sev,
                "severity_correct": pred_sev == truth["severity"],
                "truth_action": truth["action"], "llm_action": llm_action,
                "action_correct": llm_action == truth["action"],
                "final_action_after_guardrails": res.get("final_action"),
                "final_correct": res.get("final_action") == truth["action"],
                "false_positive": bool(truth["action"] != "Escalate" and llm_action == "Escalate"),
                "missed_escalation": bool(truth["action"] == "Escalate" and llm_action not in ("Escalate",)),
                "schema_first_try": bool(m.get("first_try_ok")),
                "ungrounded_indicators": len(m.get("ungrounded", [])),
                "latency_s": round(m.get("latency", 0.0), 2),
                "completed_without_fallback": bool(m.get("ok")),
                "explanation_quality_1to5": None,
            })
    return pd.DataFrame(rows)


def summarize(df):
    g = df.groupby("model", sort=False)
    out = pd.DataFrame({
        "Severity accuracy %": g["severity_correct"].mean() * 100,
        "Escalation accuracy % (raw LLM)": g["action_correct"].mean() * 100,
        "Escalation accuracy % (after guardrails)": g["final_correct"].mean() * 100,
        "False positives": g["false_positive"].sum(),
        "Missed escalations": g["missed_escalation"].sum(),
        "Schema compliance % (1st try)": g["schema_first_try"].mean() * 100,
        "Hallucination rate % (cases w/ ungrounded IOCs)": g["ungrounded_indicators"].apply(lambda s: (s > 0).mean() * 100),
        "Avg latency (s)": g["latency_s"].mean(),
        "Task completion %": g["completed_without_fallback"].mean() * 100,
    })
    if df["explanation_quality_1to5"].notna().any():
        out["Explanation quality (1-5)"] = g["explanation_quality_1to5"].mean()
    return out.round(2)
