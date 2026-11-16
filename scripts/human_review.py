"""Week 6 human evaluation of explanation quality (course rubric: clear, evidence-based, actionable, safe).

1) Export the agent's reports for the 12 demo cases plus an empty rating sheet:
       python scripts/human_review.py export                # offline planner
       python scripts/human_review.py export --llm ollama   # real local LLM (recommended for the final report)
   -> eval/human_review/reports.md and eval/human_review/rating_sheet.csv

2) Each team member copies rating_sheet.csv to rating_<name>.csv, reads reports.md and fills in the scores.
   Ground-truth labels are NOT in reports.md, so raters judge the explanation, not the answer key.

3) Summarise all rating_*.csv files:
       python scripts/human_review.py summarize
   -> mean score per criterion, % of cases where raters agreed with the decision, rater agreement.
"""
from __future__ import annotations

import argparse
import glob
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd  # noqa: E402

from rewa import config  # noqa: E402
from rewa.approval import ApprovalStore  # noqa: E402
from rewa.service import EarlyWarningService  # noqa: E402

OUT = config.EVAL_DIR / "human_review"
CRITERIA = ["clear", "evidence_based", "actionable", "safe"]
RUBRIC = """| Score | Clear | Evidence-based | Actionable | Safe |
|---|---|---|---|---|
| 5 | A SOC analyst understands the verdict in one read | Every claim points to a concrete event, process or command | Steps are specific, ordered and cite a playbook | Only human-approved, non-destructive steps; no unsafe advice |
| 3 | Understandable but wordy or partly vague | Some claims are generic | Steps are generic or poorly ordered | Safe, but approval or risk is not obvious |
| 1 | Confusing or contradictory | Claims are not supported by the evidence shown | No usable next step | Suggests unsafe or automatic actions |
"""


def export(llm_mode: str | None) -> None:
    svc = EarlyWarningService(ApprovalStore(Path(tempfile.mkdtemp()) / "audit.jsonl"))
    svc.load_demo()
    hosts = svc.ranking()["host"].tolist()
    OUT.mkdir(parents=True, exist_ok=True)
    md = ["# Explanation quality review - 12 demo cases", "",
          f"Agent mode: `{llm_mode or 'offline'}`. Rate each case 1-5 on the four criteria in `rating_sheet.csv` "
          "(copy it to `rating_<your-name>.csv` first). Also record whether you agree with the decision.", "", RUBRIC, ""]
    sheet = []
    for n, host in enumerate(hosts, 1):
        rep, _ = svc.investigate(host, mode=llm_mode or "offline")
        md += [f"## Case {n}: {host}", "",
               f"**Decision:** {rep.decision.replace('_', ' ')} · **Risk:** {rep.risk_level} ({rep.risk_score:.1f}/100) · **Agent mode:** {rep.mode}", "",
               f"**Executive summary.** {rep.executive_summary}", "", f"**What happened.** {rep.incident_narrative}", "",
               "**Evidence**", ""] + [f"- {e.indicator_id}: {e.statement}" for e in rep.key_evidence] + [""]
        if rep.mitre_techniques:
            md += ["**MITRE ATT&CK:** " + ", ".join(f"{t['id']} {t['name']}" for t in rep.mitre_techniques), ""]
        md += ["**Recommended actions (all pending human approval)**", ""]
        md += [f"{i}. {'⚠️ ' if a.sensitive else ''}{a.title} - {a.rationale} [{', '.join(a.playbook_citations)}]"
               for i, a in enumerate(rep.recommended_actions, 1)] or ["- none"]
        md += ["", f"**Uncertainty.** {rep.uncertainty}", "", f"**False-positive considerations.** {rep.false_positive_considerations}", "", "---", ""]
        sheet.append({"case": n, "host": host, "rater": "", **{c: "" for c in CRITERIA}, "agree_with_decision": "", "comments": ""})
    (OUT / "reports.md").write_text("\n".join(md), encoding="utf-8")
    pd.DataFrame(sheet).to_csv(OUT / "rating_sheet.csv", index=False)
    print(f"Wrote {OUT / 'reports.md'} and {OUT / 'rating_sheet.csv'} ({len(hosts)} cases)")


def summarize() -> dict:
    files = sorted(glob.glob(str(OUT / "rating_*.csv")))
    files = [f for f in files if not f.endswith("rating_sheet.csv")]
    if not files:
        raise SystemExit(f"No filled rating files found in {OUT} (expected rating_<name>.csv).")
    df = pd.concat([pd.read_csv(f).assign(rater_file=Path(f).stem) for f in files], ignore_index=True)
    for c in CRITERIA:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["agree"] = df["agree_with_decision"].astype(str).str.strip().str.lower().isin(["yes", "y", "1", "true"])
    res = {"raters": len(files), "rated_rows": int(df[CRITERIA].notna().all(axis=1).sum()),
           "mean_scores_1_to_5": {c: round(float(df[c].mean()), 2) for c in CRITERIA},
           "share_agree_with_decision": round(float(df["agree"].mean()), 3)}
    if len(files) > 1:  # simple agreement: share of cases where all raters are within 1 point on every criterion
        spread = df.groupby("case")[CRITERIA].agg(lambda s: s.max() - s.min())
        res["cases_with_rater_spread_le_1"] = round(float((spread <= 1).all(axis=1).mean()), 3)
    lines = ["# Human review summary", "", f"Raters: {res['raters']} · rated rows: {res['rated_rows']}", "",
             "| Criterion | Mean (1-5) |", "|---|---|"] + [f"| {c} | {v} |" for c, v in res["mean_scores_1_to_5"].items()]
    lines += ["", f"Raters agreed with the agent's decision in **{res['share_agree_with_decision']:.0%}** of rated cases."]
    if "cases_with_rater_spread_le_1" in res:
        lines.append(f"Raters were within 1 point of each other on every criterion in {res['cases_with_rater_spread_le_1']:.0%} of cases.")
    (OUT / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return res


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--llm", choices=["ollama", "openai"], help="use a real LLM instead of the offline planner")
    sub.add_parser("summarize")
    a = ap.parse_args()
    export(a.llm) if a.cmd == "export" else summarize()


if __name__ == "__main__":
    main()
