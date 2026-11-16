"""Application service: the single backend facade used by the Gradio UI,
scripts and tests. Keeps the UI thin and the logic testable."""
from __future__ import annotations

import json
import threading

import pandas as pd

from . import config
from .agent import HostInvestigationAgent, IncidentReport
from .approval import ApprovalStore
from .features import annotate
from .llm import make_llm
from .monitoring import log_event, timed
from .schema import ValidationReport, load_events_file, normalize_events
from .scoring import MLScorer, ranking_table, score_host_df


class EarlyWarningService:
    def __init__(self, approval_store: ApprovalStore | None = None):
        self.ml = MLScorer(auto_train=True)
        self.approvals = approval_store or ApprovalStore()
        self.events: pd.DataFrame | None = None
        self.annotated: pd.DataFrame | None = None
        self._scores: dict = {}
        self.current_host: str | None = None
        self.dataset_name = ""
        self.validation: ValidationReport | None = None
        self._retrievals: list[dict] = []
        self._lock = threading.Lock()

    # ---------------- data ----------------
    def load_dataframe(self, df: pd.DataFrame, name: str = "uploaded") -> ValidationReport:
        with timed("ingest", dataset=name):
            ev, rep = normalize_events(df, max_rows=config.MAX_UPLOAD_ROWS)
            self._set(ev, name, rep)
        return rep

    def load_file(self, path: str) -> ValidationReport:
        with timed("ingest", dataset=str(path).split("/")[-1]):
            ev, rep = load_events_file(path, max_rows=config.MAX_UPLOAD_ROWS)
            self._set(ev, str(path).replace("\\", "/").split("/")[-1], rep)
        return rep

    def load_demo(self) -> ValidationReport:
        p = config.DEMO_DIR / "events.csv"
        if not p.exists():
            from .generator import generate_dataset

            config.DEMO_DIR.mkdir(parents=True, exist_ok=True)
            ev, lab = generate_dataset(12, seed=42, ransomware_ratio=0.5)
            ev.drop(columns=["phase"]).to_csv(p, index=False)
            lab.to_csv(config.DEMO_DIR / "labels.csv", index=False)
        return self.load_file(str(p))

    def _set(self, ev, name, rep):
        with self._lock:
            self.events, self.dataset_name, self.validation = ev, name, rep
            self.annotated = annotate(ev)
            self._scores = {}
            self.current_host = None
        log_event("dataset_loaded", dataset=name, rows=len(ev), hosts=int(ev["host"].nunique()), status="ok")

    @property
    def loaded(self) -> bool:
        return self.events is not None

    def hosts(self) -> list[str]:
        return self.ranking()["host"].tolist() if self.loaded else []

    # ---------------- scoring ----------------
    def annotated_host(self, host: str) -> pd.DataFrame:
        if not self.loaded:
            raise ValueError("No telemetry loaded.")
        d = self.annotated[self.annotated["host"] == host]
        if len(d) == 0:
            raise ValueError(f"Unknown host '{host}'.")
        return d

    def host_score(self, host: str):
        if host not in self._scores or self._scores[host][1] is None:
            self._scores[host] = score_host_df(self.annotated_host(host), self.ml, with_timeline=True)
        return self._scores[host]

    def ranking(self) -> pd.DataFrame:
        if not self.loaded:
            return pd.DataFrame()
        with timed("score_fleet", dataset=self.dataset_name):
            for h, g in self.annotated.groupby("host", sort=False):
                if h not in self._scores:
                    self._scores[h] = score_host_df(g, self.ml, with_timeline=False)
        return ranking_table(self._scores)

    # ---------------- agent ----------------
    def investigate(self, host: str, mode: str | None = None, llm=None) -> tuple[IncidentReport, str]:
        agent = HostInvestigationAgent(self, llm=llm, mode=mode)
        report = agent.investigate(host)
        self.host_score(host)  # make sure first-alert time is populated for UI
        rid = self.approvals.create_request(report)
        return report, rid

    def record_retrieval(self, hits):
        self._retrievals.extend(hits)

    def reset_retrievals(self):
        self._retrievals = []

    # ---------------- status ----------------
    def llm_status(self, provider: str | None = None, model: str | None = None, base_url: str | None = None) -> tuple[bool, str]:
        llm = make_llm(provider, model, base_url)
        if llm is None:
            return True, "Offline deterministic planner (no LLM)."
        return llm.health()

    def status(self) -> dict:
        return {"dataset": self.dataset_name, "rows": 0 if not self.loaded else len(self.events),
                "hosts": 0 if not self.loaded else int(self.events["host"].nunique()),
                "ml_model": f"RandomForest - {self.ml.status}" if self.ml.available else f"off - {self.ml.status}",
                "embedding_backend": config.EMBEDDING_BACKEND, "llm_provider": config.LLM_PROVIDER, "llm_model": config.LLM_MODEL,
                "alert_threshold": config.ALERT_THRESHOLD, "execute_containment": config.EXECUTE_CONTAINMENT}


def report_markdown(r: IncidentReport) -> str:
    badge = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟩"}.get(r.risk_level, "⬜")
    ml = "n/a" if r.ml_probability is None else f"{r.ml_probability:.2f}"
    lines = [
        f"### {badge} {r.host} — {r.risk_level} ({r.risk_score:.1f}/100) → decision: **{r.decision.replace('_', ' ')}**",
        f"ML second opinion: **{ml}**{' ⚠️ disagrees with rules – review carefully' if r.model_disagreement else ''} · "
        f"first alert: **{r.first_alert_utc or '—'}** · agent mode: `{r.mode}` · model: `{r.model}`",
        "", "**Executive summary.** " + r.executive_summary, "", "**What happened.** " + r.incident_narrative, "",
        "**Uncertainty.** " + r.uncertainty, "", "**False-positive considerations.** " + r.false_positive_considerations,
    ]
    if r.safety["guardrail_notes"]:
        lines += ["", "<details><summary>Guardrail notes</summary>\n"] + [f"- {n}" for n in r.safety["guardrail_notes"]] + ["</details>"]
    return "\n".join(lines)


def report_json(r: IncidentReport) -> str:
    return json.dumps(r.model_dump(), indent=2, default=str)
