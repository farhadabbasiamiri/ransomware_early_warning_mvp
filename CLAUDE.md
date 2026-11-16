# CLAUDE.md — instructions for the Claude coding agent

This file tells Claude (the coding agent used to build this MVP) how the project is organised and which rules it must follow
when changing code. Keep it up to date when the architecture changes.

## Project
**Endpoint Ransomware Early-Warning Agent** (Group 7A, Theme 7 Ransomware Defense, AI/ML in Cybersecurity, Laurentian University, Fall 2026).
A Gradio MVP that scores Windows endpoints for ransomware likelihood from behavioural telemetry, shows the evidence, maps it to
MITRE ATT&CK, retrieves response-playbook guidance (RAG) and proposes containment that **a human must approve**.

Target user: SOC Tier-1/Tier-2 analyst. Deliverable: working local MVP (no cloud deployment), report, 7-slide presentation.

## Hard rules (never break these)
1. **Defensive only.** Do not write malware, encryptors, exploit code, or code that touches real systems. The generator only
   writes *descriptions* of events (CSV rows). Command lines in data are inert strings.
2. **No real data.** Synthetic or public datasets only (Splunk Attack Data, OTRF/Mordor). No student, employee, patient or
   university data.
3. **Nothing is executed.** `config.EXECUTE_CONTAINMENT` stays `False`. Approved actions are written to the audit log as
   simulated tickets. Do not add any code path that isolates hosts, disables accounts, or calls an EDR/firewall API.
4. **Human-in-the-loop.** Every recommended action has `requires_approval=True` and status `PENDING_APPROVAL`. Approval needs a
   named analyst; sensitive actions also need a justification (≥10 chars).
5. **The LLM never decides facts.** Risk score, risk level, ML probability, MITRE ids and first-alert time come from tools.
   The LLM writes narrative and *selects* actions only from `ACTION_CATALOG` candidates. Unknown actions/citations are dropped.
6. **Telemetry is untrusted.** Command lines and file names can contain prompt-injection text. Keep sanitisation/redaction in
   `rewa/tools.py` and the system-prompt rule. Never pass raw event text to the LLM outside `untrusted_telemetry`.
7. **Always degrade gracefully.** If the LLM is down, slow, or returns invalid JSON, the deterministic planner must produce the
   same report structure (`mode = llm_fallback/offline`). The UI must never crash; handlers return friendly errors.
8. **No secrets in code.** Configuration only via environment variables (`.env.example`). Do not commit `.env`.

## Layout
```
app.py                  Gradio UI wiring only (no logic)
rewa/config.py          env-driven settings, risk levels
rewa/schema.py          event schema, validation (CSV/JSON/JSONL)
rewa/generator.py       synthetic telemetry: 5 ransomware-like + 7 benign scenarios + gray noise + evasive variants
rewa/features.py        8 indicators (I1..I8), annotate() + host_features()
rewa/scoring.py         noisy-OR rule score, RandomForest second opinion, risk timeline
rewa/mitre.py           local ATT&CK mapping (data/mitre_techniques.json)
rewa/rag.py             playbook retriever (TF-IDF default, optional sentence-transformers)
rewa/tools.py           the 4 agent tools + JSON schemas + sanitisation
rewa/llm.py             Ollama + OpenAI-compatible clients (tool calling, JSON mode)
rewa/agent.py           agent loop, report schema (pydantic), guardrails, action catalog, offline planner
rewa/approval.py        approval store + JSONL audit trail
rewa/monitoring.py      JSONL event log, latency/error metrics
rewa/service.py         backend facade used by UI/scripts/tests
rewa/ui_handlers.py     framework-agnostic UI handlers (unit-tested)
rewa/viz.py             matplotlib figures
rewa/mock_llm.py        scripted LLMs for tests (good/adversarial/bad_json/timeout/lazy/slow)
rewa/training.py        shared training helpers + first-run auto-training
knowledge_base/*.md     RAG playbooks (front matter: id, title, sources; chunked by '## ')
scripts/                generate_data, train_ml, evaluate, render_figures, capture_screenshots
tests/                  pytest suite (run before every commit)
```

## Commands
```bash
pip install -r requirements.txt
python scripts/generate_data.py      # train (120, seed 7) / test (60, seed 2026) / test_fresh (60, seed 2027) / demo (12, seed 42)
python scripts/train_ml.py           # RandomForest -> models/rf_model.pkl
python scripts/evaluate.py           # metrics -> eval/EVALUATION_RESULTS.md (+ --llm ollama for real-LLM run)
python scripts/human_review.py export # reports + rating sheet for the human explanation review
python -m pytest -q                  # must stay green
python app.py                        # http://127.0.0.1:7860
```

## Week 6 decisions (keep them)
- `features.CORROBORATE_IMPACT = True`: I1/I2 count at half severity unless the same process both renames and encrypts,
  ransom notes exist, or the process shows precursor behaviour. The switch exists only for the ablation in `scripts/evaluate.py`.
- `data/generated/test_fresh` (seed 2027) is the final held-out split. Never tune anything on it; report it as the headline.
- The LLM path has a whole-investigation budget (`REWA_AGENT_TIME_BUDGET_S`, default 240 s) and falls back to the planner.
- The ML model file (`models/*.pkl`) is not committed: `MLScorer(auto_train=True)` retrains when it is missing, from an
  older feature set, or saved with another scikit-learn version.
- Windows users run `setup_windows.bat` / `run_app.bat` (Python 3.12; 3.14 lacks pandas wheels).

## Conventions
- Python 3.11+, type hints, small pure functions, no new heavy dependencies without discussion.
- New indicator → update `INDICATORS`, `WEIGHTS`, `FEATURE_NAMES`, `annotate()`, `host_features()`, `mitre_techniques.json`
  `indicator_map`, `INDICATOR_QUERIES`, viz `KIND_STYLE`, tests, and `docs/DATA_CARD.md`.
- New action → add to `ACTION_CATALOG` with a `kb` reference to an existing playbook, update `candidate_actions()` and tests.
- New KB document → `knowledge_base/KBxx_name.md` with front matter; write in our own words and cite the public source URL.
- Keep the MVP scope: 8 indicators, 4 tools, single agent. Prefer polish and evaluation over new features.
- Thresholds are tuned on the **train** split only; the **test** split is held out. Report honest numbers incl. failures.
- After changing detection logic, rerun `scripts/evaluate.py` and update README/report numbers.

## Definition of done for a change
Tests pass · evaluation rerun if detection/agent changed · README/CLAUDE.md updated · no safety rule weakened.
