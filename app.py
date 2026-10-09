"""Governed Agentic AI - SOC Alert Triage & Incident Investigation (Streamlit UI)."""
import json
import os

import pandas as pd
import streamlit as st

from soc import audit, benchmark, config, llm, orchestrator

st.set_page_config(page_title="Governed Agentic AI SOC", page_icon="🛡️", layout="wide")

# Secrets (Streamlit Cloud / local .streamlit/secrets.toml) -> environment variables
for _k in ("LLM_API_KEY", "LLM_BASE_URL"):
    try:
        if _k in st.secrets:
            os.environ[_k] = str(st.secrets[_k])
    except Exception:  # no secrets file locally -> demo mode
        pass

CASES = config.load_json("alerts.json")
MODELS = [m["label"] for m in config.load_models()]
LIVE = llm.has_key()
CUSTOM = "✏️ Custom alert (paste JSON)"
ICON = {"ok": "✅", "warn": "⚠️", "error": "❌", "pending": "⏸️"}

# ───────────────────────── Sidebar ─────────────────────────
with st.sidebar:
    st.title("🛡️ SOC Control Panel")
    if LIVE:
        st.success("LLM provider connected")
        model_label = st.radio("Open-weight model", MODELS)
    else:
        st.warning("No API key found → **Demo mode**: rule-based summary, no LLM calls. See README to add a key.")
        model_label = None
    outage = st.checkbox("Simulate LLM outage (exception-handling demo)", value=False)
    analyst = st.text_input("Analyst name (for audit log)", value="analyst.demo")
    st.caption("Legend: **A** Autonomous · **H** Human-in-the-loop · **E** Escalation")

st.title("🛡️ Governed Agentic AI SOC Dashboard")
st.caption("Automated alert triage & incident investigation with human-in-the-loop oversight")

tab_triage, tab_bench, tab_audit, tab_gov = st.tabs(
    ["🚨 Triage Console", "📊 Model Benchmark", "🧾 Audit Log", "🏛️ Architecture & Governance"])


def log_decision(action):
    res = st.session_state["result"]
    entry = audit.log_event("hitl_decision", res["alert_id"], analyst or "unknown", {
        "decision": action, "ai_recommendation": res["final_action"], "route": res["route"],
        "risk": res["risk"]["score"], "comment": st.session_state.get("comment", "")})
    st.session_state["decision"] = {"action": action, "entry": entry}


# ───────────────────────── Tab 1: triage ─────────────────────────
with tab_triage:
    left, right = st.columns([1, 2])
    with left:
        choice = st.selectbox("Select alert scenario", [c["name"] for c in CASES] + [CUSTOM])
        if choice == CUSTOM:
            template = json.dumps(CASES[0]["alert"], indent=2)
            raw = st.text_area("Alert JSON", value=template, height=320)
            try:
                alert = json.loads(raw)
                parse_err = None
            except json.JSONDecodeError as e:
                alert, parse_err = None, str(e)
                st.error(f"Invalid JSON: {e}")
        else:
            alert, parse_err = next(c["alert"] for c in CASES if c["name"] == choice), None
            st.json(alert, expanded=False)
        run = st.button("🚀 Trigger agentic workflow", type="primary", width="stretch", disabled=parse_err is not None)

    with right:
        if run:
            st.session_state["decision"] = None
            with st.status("SOC Orchestrator running…", expanded=True) as status:
                def on_step(s):
                    st.write(f"{ICON.get(s['status'], '•')} **[{s['role']}] {s['name']}** — {s['summary']}")
                res = orchestrator.run(alert, model_label, simulate_outage=outage, progress=on_step)
                status.update(label="Workflow finished — awaiting human decision" if res["status"] == "awaiting_human"
                              else "Workflow stopped", state="complete" if res["status"] == "awaiting_human" else "error")
            st.session_state["result"] = res

        res = st.session_state.get("result")
        if res and res["status"] != "awaiting_human":
            st.error(f"Workflow could not complete: {res.get('error')}")
        elif res:
            c1, c2, c3 = st.columns(3)
            c1.metric("Risk score (engine)", res["risk"]["score"])
            c2.metric("Severity", res["risk"]["severity"])
            c3.metric("Recommended action", res["final_action"])
            banner = f"**Route → {res['route']}** · path: {res['path']}"
            (st.error if res["final_action"] == "Escalate" and "Commander" in res["route"]
             else st.warning if res["final_action"] == "Escalate" else st.success)(banner)
            if res["degraded"]:
                st.warning("Degraded mode: LLM was not used for this summary. Routed conservatively.")

            st.markdown("#### Incident summary")
            sm = res["summary"]
            st.write(sm["Threat_Summary"])
            st.markdown("**Missing context:** " + ("; ".join(sm["Missing_Context"]) if sm["Missing_Context"] else "None"))
            st.caption(f"Model: {res['model']} · model risk {sm['Risk_Score']} / model action {sm['Recommended_HITL_Action']} · "
                       f"engine action {res['policy_action']} · total {res['total_latency']}s")
            if res["guardrail_events"]:
                st.markdown("#### 🛑 Guardrail events")
                for e in res["guardrail_events"]:
                    st.warning(f"**{e['guardrail']}:** {e['detail']}")
            with st.expander("Risk score breakdown"):
                st.dataframe(pd.DataFrame(res["risk"]["breakdown"]), hide_index=True, width="stretch")
            with st.expander("Agent execution trace"):
                for s in res["steps"]:
                    st.markdown(f"{ICON.get(s['status'], '•')} **[{s['role']}] {s['name']}** ({s['duration']}s) — {s['summary']}")

    # ----- HITL gate -----
    res = st.session_state.get("result")
    if res and res["status"] == "awaiting_human":
        st.divider()
        st.subheader("⚠️ Human-in-the-Loop decision gate")
        st.caption("Guardrail: autonomous execution is paused. No response action runs until an analyst decides.")
        dec = st.session_state.get("decision")
        if dec:
            st.success(f"Decision recorded: **{dec['action']}** by {dec['entry']['actor']} at {dec['entry']['ts']} "
                       f"(audit hash {dec['entry']['hash'][:12]}…)")
        else:
            st.text_input("Analyst comment (optional)", key="comment")
            b1, b2, b3 = st.columns(3)
            if b1.button("✅ Approve remediation", width="stretch"):
                log_decision("Approve"); st.rerun()
            if b2.button("🚨 Escalate", width="stretch"):
                log_decision("Escalate"); st.rerun()
            if b3.button("🗑️ Dismiss as false positive", width="stretch"):
                log_decision("Dismiss"); st.rerun()

# ───────────────────────── Tab 2: benchmark ─────────────────────────
with tab_bench:
    st.subheader("Open-weight model comparison")
    st.caption("Same alerts, same STOIC prompt, same evidence, same JSON output format for every model.")
    if not LIVE:
        st.info("Benchmark needs a real LLM API key (it is disabled in demo mode so no simulated numbers can end up in your report).")
    else:
        chosen = st.multiselect("Models", MODELS, default=MODELS)
        if st.button("▶ Run benchmark on all test cases", disabled=not chosen):
            bar = st.progress(0.0)
            df = benchmark.run_benchmark(chosen, CASES, lambda i, n, lbl: bar.progress(i / n, text=f"{i}/{n} · {lbl}"))
            bar.empty()
            st.session_state["bench"] = df
            try:
                config.RESULTS_DIR.mkdir(exist_ok=True)
                df.to_csv(config.RESULTS_DIR / "benchmark_raw.csv", index=False)
            except OSError:
                pass
        if "bench" in st.session_state:
            st.markdown("**Per-case results** (fill *explanation_quality_1to5* manually after reading outputs)")
            edited = st.data_editor(st.session_state["bench"], width="stretch", hide_index=True,
                                    disabled=[c for c in st.session_state["bench"].columns if c != "explanation_quality_1to5"])
            summ = benchmark.summarize(edited)
            st.markdown("**Summary by model**")
            st.dataframe(summ, width="stretch")
            st.download_button("⬇ Download raw results (CSV)", edited.to_csv(index=False), "benchmark_raw.csv", "text/csv")
            st.download_button("⬇ Download summary (CSV)", summ.to_csv(), "benchmark_summary.csv", "text/csv")

# ───────────────────────── Tab 3: audit ─────────────────────────
with tab_audit:
    st.subheader("Governance & audit log")
    ok, msg = audit.verify_chain()
    (st.success if ok else st.error)(msg)
    events = audit.read_events()
    if events:
        flat = [{"time": e["ts"], "event": e["event"], "alert": e["alert_id"], "actor": e["actor"],
                 "details": json.dumps(e["details"], ensure_ascii=False), "hash": e["hash"][:12]} for e in reversed(events)]
        st.dataframe(pd.DataFrame(flat), width="stretch", hide_index=True)
        st.download_button("⬇ Download audit log (JSONL)", "\n".join(json.dumps(e) for e in events), "audit.jsonl")
    else:
        st.info("No events yet. Run a workflow and take a HITL decision.")

# ───────────────────────── Tab 4: architecture & governance ─────────────────────────
with tab_gov:
    st.subheader("TO-BE agentic workflow")
    st.graphviz_chart("""
    digraph G { rankdir=LR; node [shape=box, style="rounded,filled", fontname="Helvetica", fillcolor="#1a1f2b", fontcolor="white", color="#555"];
      alert [label="Security alert\\n(SIEM/EDR)"];
      orch  [label="SOC Orchestrator [A]\\nconditional routing"];
      corr  [label="Alert Correlation\\n+ masking [A]"];
      guard [label="Injection filter [A]", fillcolor="#7a1f2b"];
      ti    [label="Threat Intel [A]"]; ac [label="Asset Context [A]"];
      risk  [label="Risk / Priority [A]"];
      sum   [label="Incident Summary\\n(open-weight LLM) [A]"];
      gov   [label="Governance check [A]\\nno action downgrade", fillcolor="#7a1f2b"];
      hitl  [label="Human SOC Analyst [H]", fillcolor="#1f5f7a"];
      esc   [label="Tier 2 / Incident Commander [E]", fillcolor="#7a4a1f"];
      alert -> orch -> corr -> guard -> ti -> ac -> risk -> sum -> gov -> hitl -> esc; }
    """)
    st.subheader("Risk → Guardrail → Governance requirement → Implementation (NIST AI RMF)")
    st.dataframe(pd.DataFrame([
        ["Unsafe autonomous action", "HITL gate; action can only get MORE cautious", "Govern 2.1 – human oversight roles defined", "orchestrator.py governance step + HITL buttons in app.py"],
        ["Privacy / confidential data leakage", "Mask e-mails, user IDs, secrets before LLM call", "Map 3.2 – privacy & data-sharing risks addressed", "guardrails.mask_payload()"],
        ["Hallucination", "Evidence-only prompt, schema validation, grounding check", "Measure 2.1 – accuracy & reliability evaluated", "guardrails.validate_output(), ungrounded_indicators(), Benchmark tab"],
        ["Prompt injection", "Pattern detection + neutralisation, JSON-only output, untrusted-data delimiters", "Govern 4.1 – adversarial / security risk policies", "guardrails.find_injection() / neutralise_injection(); test case 4"],
        ["Over-reliance on one model", "Deterministic risk engine cross-checks LLM score", "Manage – risk treatment & monitoring", "orchestrator flag model_vs_engine_disagreement"],
        ["Logging & auditability", "Hash-chained audit log of every workflow & human decision", "Govern – accountability & documentation", "audit.py, Audit Log tab"],
        ["Service failure", "Retry once, then rule-based fallback, routed conservatively", "Manage – incident response & recovery", "agents.incident_summary_agent(), outage toggle"],
    ], columns=["Risk", "Guardrail", "Governance requirement", "Implementation in PoC"]), hide_index=True, width="stretch")
    st.caption("Verify NIST sub-category numbers against the official AI RMF 1.0 text before final submission.")
