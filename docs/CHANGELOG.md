# Changelog

## Week 6 (Nov 2-8, 2026) - evaluation, false positives and robustness
- **Detection:** impact corroboration. Mass renames (I1) and high-entropy writes (I2) count at half severity unless the same
  process does both, ransom notes appear, or the process shows precursor behaviour. Motivated by false positives on the
  train split (sync clients, encrypted vaults). False positives at threshold 45: train 9 → 6, original test 5 → 1,
  fresh test 5 → 3; no missed attacks. New ML feature `impact_corroborated`.
- **Evaluation:** a second held-out split `test_fresh` (seed 2027) generated after all tuning and evaluated once; it gives the
  headline numbers (precision 0.89, recall 1.00, F1 0.94). Before/after ablation table in `eval/EVALUATION_RESULTS.md`.
- **Human review:** `scripts/human_review.py export|summarize` for the course rubric (clear, evidence-based, actionable, safe).
- **Agent robustness:** 240 s budget for the whole LLM investigation with fallback to the planner, per-call timeouts capped by
  the budget, Ollama `keep_alive` (30 min), *Check LLM & load model* warm-up button, progress message in the UI.
- **Setup:** `setup_windows.bat` / `run_app.bat` (Python 3.12), `setup.sh` / `run_app.sh`; the ML model trains itself on first
  start and is retrained when it is missing, from an older feature set or another scikit-learn version; `.venv*/` and
  `models/*.pkl` are no longer committed.
- **Docs:** team names, troubleshooting table, updated README, data card, demo script, CLAUDE.md. 64 tests.

## Weeks 1-4 (Oct 1-28, 2026) - MVP
- Problem, target user, scope and safety boundaries; architecture diagram.
- Synthetic telemetry generator (5 ransomware-like + 7 benign scenarios, gray activity, evasive test variants), schema
  validation, data card.
- 8 behavioural indicators, noisy-OR risk score, cumulative risk timeline, RandomForest second opinion, MITRE ATT&CK mapping,
  9-playbook RAG knowledge base.
- LLM agent with 4 tools, pydantic-validated JSON incident report, guardrails, deterministic fallback, human approval with
  audit log, Gradio dashboard, monitoring, evaluation harness, 53 tests.
