# 🛡️ Governed Agentic AI – SOC Alert Triage & Incident Investigation

AIB Hackathon · Stage 3 proof of concept (UI + orchestration + open-model benchmark + guardrails).

**Flow:** Security alert → SOC Orchestrator → Alert Correlation → Threat Intel → Asset Context → Risk/Prioritisation → Incident Summary (open-weight LLM) → Governance check → **Human SOC analyst (HITL)** → Escalation.

## Folder structure
```
soc-agentic-ai/
├── app.py                  # Streamlit UI (4 tabs: Triage, Benchmark, Audit, Architecture)
├── requirements.txt
├── README.md
├── .gitignore
├── .streamlit/
│   ├── config.toml         # dark theme
│   └── secrets.toml.example   # copy to secrets.toml and add your API key (never commit it)
├── data/
│   ├── alerts.json         # 5 test cases + ground truth (normal, ambiguous, high-risk, injection, incomplete)
│   ├── threat_intel.json   # local threat-intel "tool"
│   ├── assets.json         # local CMDB "tool"
│   └── models.json         # the 3 open-weight models to compare (edit IDs here)
└── soc/
    ├── config.py           # thresholds, STOIC prompt, scoring weights
    ├── agents.py           # the 5 agents
    ├── orchestrator.py     # routing, fallback, governance, HITL gate
    ├── guardrails.py       # masking, injection filter, schema + grounding checks
    ├── audit.py            # tamper-evident (hash-chained) audit log
    ├── llm.py              # OpenAI-compatible API client
    └── benchmark.py        # runs all cases x all models, computes metrics
```

## 1 · Run on your computer (Windows)
1. Install **Python 3.10+** from python.org (tick *"Add Python to PATH"*).
2. Put the folder on your Desktop, e.g. `C:\Users\<you>\Desktop\soc-agentic-ai`.
3. Open **Command Prompt** in that folder (type `cmd` in the folder's address bar) and run:
   ```
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   streamlit run app.py
   ```
   (Mac/Linux: `source .venv/bin/activate`.) The app opens at http://localhost:8501.
4. It works immediately in **Demo mode** (rule-based summary, no LLM). For real model runs:
   - Create a free account at **openrouter.ai**, make an API key (add a few dollars of credit; these small models cost fractions of a cent per call).
   - Copy `.streamlit/secrets.toml.example` → `.streamlit/secrets.toml` and paste the key.
   - Restart the app. The sidebar will show **LLM provider connected**.
5. **Check model IDs** at openrouter.ai/models. If one fails, edit `data/models.json`. Any OpenAI-compatible provider works (Groq, Together, local Ollama) – change `LLM_BASE_URL` and the IDs.

## 2 · Make it live with GitHub + Streamlit Community Cloud (free)
GitHub Pages only hosts static HTML, so it cannot run this Python app. Use GitHub for the code and Streamlit Community Cloud for hosting:
1. Create a new **public** repo on github.com (e.g. `soc-agentic-ai`).
2. In the project folder:
   ```
   git init
   git add .
   git commit -m "SOC agentic AI PoC"
   git branch -M main
   git remote add origin https://github.com/<your-username>/soc-agentic-ai.git
   git push -u origin main
   ```
   (`.gitignore` already keeps `secrets.toml` and logs out of GitHub.)
3. Go to **share.streamlit.io** → sign in with GitHub → **Create app** → pick the repo, branch `main`, file `app.py`.
4. Open **Advanced settings → Secrets** and paste:
   ```
   LLM_API_KEY = "your-key"
   LLM_BASE_URL = "https://openrouter.ai/api/v1"
   ```
5. Deploy. You get a public link like `https://<name>.streamlit.app` for your report/website. Put that link, plus the GitHub link, in your Stage 6 website.

Note: on the free cloud tier the audit log file resets when the app restarts. Download it from the Audit tab for evidence.

## 3 · What to demonstrate / screenshot (Stage 3 checklist)
- Trigger workflow from UI for case 1 (normal), 2 (ambiguous), 3 (high-risk), 4 (prompt injection), 5 (incomplete data).
- "Agent execution trace" expander and risk breakdown.
- Guardrail events (case 4 injection, "Action override" if a model proposes Dismiss).
- Toggle **Simulate LLM outage** → exception handling / fallback.
- HITL buttons → Audit Log tab (hash chain verified).
- Benchmark tab: run all 3 models, fill `explanation_quality_1to5` manually, download CSVs.
- Number and caption each screenshot.

## Honest limitations (put these in your report)
- Threat intel and CMDB are small local JSON files (stand-ins for MISP/VirusTotal/ServiceNow).
- Orchestration is a Python state machine, not n8n (see note given with this project).
- Hallucination metric is a proxy: indicators (IP/domain/hash) in the output that were not in the supplied evidence.
- 5 test cases is a small sample; results are indicative, not statistically strong.
