"""UI handler functions (framework-agnostic, unit-tested).

app.py wires these to Gradio components. Every handler catches errors and
returns a friendly message instead of crashing the dashboard.
"""
from __future__ import annotations

import json

import pandas as pd

from . import config, monitoring, viz
from .agent import ACTION_CATALOG
from .approval import ApprovalError
from .llm import make_llm
from .schema import SchemaError
from .service import EarlyWarningService, report_json, report_markdown

SVC = EarlyWarningService()

RANK_COLS = ["host", "risk_score", "risk_level", "ml_probability", "active_indicators", "top_indicators", "mitre"]


def _err(msg: str) -> str:
    return f"> ❌ **{msg}**"


# ------------------------------------------------------------------ fleet
def _fleet_outputs(header: str):
    r = SVC.ranking()
    n_alert = int((r.risk_score >= config.ALERT_THRESHOLD).sum())
    md = (f"{header}\n\n**{len(r)} hosts** · **{n_alert} at or above alert threshold ({config.ALERT_THRESHOLD:g})** · "
          f"ML second opinion: {'on' if SVC.ml.available else 'off (train with scripts/train_ml.py)'}")
    hosts = r["host"].tolist()
    return md, r[RANK_COLS], viz.ranking_chart(r), hosts, (hosts[0] if hosts else None)


def load_demo():
    try:
        rep = SVC.load_demo()
        return _fleet_outputs(f"✅ Loaded **demo dataset** (synthetic). {rep.as_markdown()}")
    except Exception as exc:  # noqa: BLE001
        return _err(f"Could not load demo data: {exc}"), pd.DataFrame(), None, [], None


def load_upload(path):
    if not path:
        return _err("Choose a .csv / .json / .jsonl file first."), pd.DataFrame(), None, [], None
    try:
        rep = SVC.load_file(path)
        return _fleet_outputs(f"✅ Loaded **{SVC.dataset_name}**. {rep.as_markdown()}")
    except SchemaError as exc:
        return _err(f"Upload rejected: {exc}"), pd.DataFrame(), None, [], None
    except Exception as exc:  # noqa: BLE001
        return _err(f"Unexpected error while loading file: {type(exc).__name__}"), pd.DataFrame(), None, [], None


# ------------------------------------------------------------------ investigation
EMPTY_INVESTIGATION = (None,) * 10


def investigate(host, mode, model, base_url):
    """Returns: report_md, timeline_fig, contrib_fig, evidence_df, mitre_df, actions_df, citations_md,
    trace_df, json_str, request_id, action_choices, approval_md"""
    if not SVC.loaded:
        return (_err("Load the demo dataset or upload telemetry first (tab 1)."), None, None, None, None, None, "", None, "", "", [], "")
    if not host:
        return (_err("Select a host."), None, None, None, None, None, "", None, "", "", [], "")
    try:
        llm = None
        mode = (mode or "offline").lower()
        if mode != "offline":
            llm = make_llm(mode, model or None, base_url or None)
        report, rid = SVC.investigate(host, mode=mode, llm=llm)
    except ValueError as exc:
        return (_err(str(exc)), None, None, None, None, None, "", None, "", "", [], "")
    except Exception as exc:  # noqa: BLE001
        monitoring.log_event("ui_error", where="investigate", status="error", error=str(exc)[:200])
        return (_err(f"Investigation failed: {type(exc).__name__}: {str(exc)[:150]}"), None, None, None, None, None, "", None, "", "", [], "")

    hs, tl = SVC.host_score(host)
    tfig = viz.host_timeline_chart(SVC.annotated_host(host), tl, host, hs.first_alert_ts)
    cfig = viz.contribution_chart([i.as_dict() for i in hs.indicators])
    evidence = pd.DataFrame([{"indicator": e.indicator_id, "evidence": e.statement, "citation": e.citation or ""}
                             for e in report.key_evidence])
    mitre_df = pd.DataFrame([{"technique": t["id"], "name": t["name"], "tactic": t["tactic"],
                              "triggered_by": ", ".join(t["triggered_by"]), "link": t["url"]} for t in report.mitre_techniques])
    actions_df = pd.DataFrame([{"#": n + 1, "action": a.action_id, "title": a.title, "sensitive": "⚠️ yes" if a.sensitive else "no",
                                "rationale": a.rationale, "playbook": ", ".join(a.playbook_citations), "status": a.status}
                               for n, a in enumerate(report.recommended_actions)])
    cites = "\n".join(f"- **[{c['chunk_id']}]** {c['title']} — *{c['section']}* (similarity {c['score']})  \n  <sub>{c['sources']}</sub>"
                      for c in report.citations) or "_No playbook passages retrieved._"
    trace = pd.DataFrame([{"step": t.get("step"), "by": t.get("by"), "tool": t.get("tool") or "(llm reply)", "status": t.get("status"),
                           "ms": t.get("duration_ms"), "args": json.dumps(t.get("args", {}))[:80], "result": t.get("output_preview", "")}
                          for t in report.agent_trace])
    choices = action_labels(report.recommended_actions)
    appr = approval_header(report, rid)
    return (report_markdown(report), tfig, cfig, evidence, mitre_df, actions_df, cites, trace, report_json(report), rid, choices, appr)


def action_labels(actions) -> list[str]:
    return [f"{a.action_id} · {'⚠️ ' if a.sensitive else ''}{a.title}" for a in actions]


def approval_header(report, rid) -> str:
    if not report.recommended_actions:
        return f"**{report.host}** — no actions proposed (risk {report.risk_level}). Nothing to approve."
    n_s = sum(a.sensitive for a in report.recommended_actions)
    return (f"### Approval request `{rid}` — {report.host} ({report.risk_level}, {report.risk_score:.1f}/100)\n"
            f"{len(report.recommended_actions)} proposed action(s), **{n_s} sensitive** (⚠️). Tick the actions you approve. "
            "Unticked actions are recorded as rejected. **Nothing is executed** — approved actions become simulated tickets in the audit log.")


# ------------------------------------------------------------------ approval
def decide(rid, selected, analyst, justification, approve: bool = True):
    if not rid:
        return _err("No pending approval request — run an investigation first."), audit_table(), rid
    ids = [s.split(" · ")[0] for s in (selected or [])] if approve else []
    try:
        recs = SVC.approvals.decide(rid, ids, analyst, justification)
    except ApprovalError as exc:
        return _err(str(exc)), audit_table(), rid
    ok = [r for r in recs if r["decision"] == "APPROVED"]
    md = (f"✅ Decision recorded for `{rid}` by **{recs[0]['analyst']}**: {len(ok)} approved, {len(recs) - len(ok)} rejected. "
          + ("Approved actions were logged as **simulated tickets — nothing was executed**." if ok else "All proposed actions rejected."))
    return md, audit_table(), ""


def audit_table() -> pd.DataFrame:
    h = SVC.approvals.history(100)
    cols = ["ts", "request_id", "host", "risk_level", "action_id", "action", "sensitive", "decision", "analyst", "justification", "execution"]
    return pd.DataFrame(h)[cols] if h else pd.DataFrame(columns=cols)


# ------------------------------------------------------------------ evaluation / system
def evaluation_view():
    md_path = config.EVAL_DIR / "EVALUATION_RESULTS.md"
    md = md_path.read_text(encoding="utf-8") if md_path.exists() else "_No evaluation yet. Run `python scripts/evaluate.py`._"
    figs = [str(config.EVAL_DIR / "figures" / f) for f in ("confusion_rules_test.png", "confusion_ml_test.png",
                                                          "score_by_scenario_test.png", "threshold_sweep_test.png", "lead_time_test.png")]
    from pathlib import Path

    return (md,) + tuple(f if Path(f).exists() else None for f in figs)


def check_llm(provider, model, base_url) -> str:
    """Health check + warm-up: loading a 7B model the first time can take 30-90 s on a laptop,
    so we do it here (before the demo) instead of inside the first investigation."""
    ok, msg = SVC.llm_status(provider, model or None, base_url or None)
    if ok and (provider or "").lower() not in ("", "offline"):
        llm = make_llm(provider, model or None, base_url or None)
        if llm is not None:
            wok, wmsg = llm.warmup()
            msg += f" · {wmsg}"
            ok = ok and wok
    tip = "" if ok else ("\n\nThe agent will automatically fall back to the deterministic planner. To enable the LLM: "
                         f"start Ollama and run `ollama pull {model or config.LLM_MODEL}`.")
    return ("✅ " if ok else "⚠️ ") + msg + tip


def system_view():
    st = SVC.status()
    md = "\n".join(f"- **{k}**: `{v}`" for k, v in st.items())
    m = monitoring.metrics()
    mdf = pd.DataFrame([{"component": k, **v} for k, v in sorted(m.items())]) if m else pd.DataFrame(columns=["component", "count"])
    recent = monitoring.recent(40)
    rdf = pd.DataFrame(recent)[::-1] if recent else pd.DataFrame(columns=["ts", "kind"])
    return md, mdf, rdf


ABOUT_MD = f"""
### Endpoint Ransomware Early-Warning Agent (Group 7A)
**Problem.** Ransomware does most of its damage before the final encryption alert. Precursors — encoded PowerShell from Office,
privilege abuse, security-service tampering, shadow-copy deletion — appear minutes earlier. **Target user:** SOC Tier-1/2 analysts.

**Pipeline.** Telemetry (CSV/JSON) → schema validation → 8 behavioural indicators → explainable noisy-OR risk score + RandomForest
second opinion → **LLM agent** (4 tools: score, timeline, MITRE, playbook RAG) → structured JSON incident report → **human approval**.

**Safety boundaries.**
- Synthetic / public data only. No real user, student or university data. No live malware: the generator only writes event rows.
- The agent **never executes** containment (`EXECUTE_CONTAINMENT = {config.EXECUTE_CONTAINMENT}`); approvals create simulated tickets.
- Actions come from a vetted catalog; unknown/destructive suggestions are dropped; every action needs a named analyst's approval.
- Telemetry is treated as untrusted: instruction-like text is redacted before reaching the LLM (prompt-injection defence).
- Scores, levels and MITRE ids come from deterministic tools, never from the LLM.

**Indicators:** I1 mass rename · I2 high-entropy overwrite · I3 ransom notes · I4 shadow/backup deletion · I5 boot-recovery inhibition ·
I6 security/backup service tampering · I7 privilege escalation · I8 suspicious execution & discovery.

Laurentian University · AI/ML in Cybersecurity · Fall 2026 · Defensive use only.
"""
