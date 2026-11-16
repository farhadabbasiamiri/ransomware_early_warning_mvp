# Team contributions (Group 7A)

Keep this updated. The professor checks commit history; each member should commit their own module work.

| Member | Role | Owned modules / artifacts | Also contributed |
|---|---|---|---|
| Uttam Kumar Roy | Data Lead | `rewa/generator.py`, `rewa/schema.py`, `scripts/generate_data.py`, `docs/DATA_CARD.md`, public-data mapping notes | test cases for schema |
| M Ridhwan Gani Bishal | AI/RAG Lead | `rewa/features.py`, `rewa/scoring.py`, `rewa/mitre.py`, `rewa/rag.py`, `knowledge_base/`, `scripts/train_ml.py` | retrieval evaluation |
| Imtiyaz Hassan Ratul | Agent Lead | `rewa/agent.py`, `rewa/tools.py`, `rewa/llm.py`, `rewa/approval.py`, prompts, guardrails | mock-LLM tests |
| Fatema Tuz Zohora | App/Deployment Lead | `app.py`, `rewa/ui_handlers.py`, `rewa/viz.py`, `rewa/monitoring.py`, Dockerfile, screenshots | demo recording |
| Ayub Tanvir | Evaluation/Security Lead | `scripts/evaluate.py`, `scripts/human_review.py`, `tests/`, `eval/`, report, presentation, ethics section | threat model |

## Suggested commit plan (so history reflects shared work)
1. Each lead pushes their module on a feature branch (`feat/data`, `feat/rag`, `feat/agent`, `feat/ui`, `feat/eval`) and opens a PR.
2. Another member reviews each PR (review = contribution).
3. Merge to `main` after `pytest` passes.

## Week 6 additions
| Change | Owner |
|---|---|
| Impact corroboration in `rewa/features.py` + before/after ablation and fresh held-out split in `scripts/evaluate.py` | AI/RAG Lead with Evaluation Lead |
| Agent time budget, Ollama keep-alive and warm-up (`rewa/agent.py`, `rewa/llm.py`) | Agent Lead |
| Progress message and *Check LLM & load model* button (`app.py`, `rewa/ui_handlers.py`) | App/Deployment Lead |
| `setup_windows.bat`, `run_app.bat`, auto-training of the ML model (`rewa/training.py`) | App/Deployment Lead with Data Lead |
| Human review pack (`scripts/human_review.py`) | Evaluation/Security Lead |
