"""Human-in-the-loop approval checkpoint and audit trail.

The agent can only PROPOSE actions. An analyst must approve or reject each
one with their name and a justification. Approved actions are recorded as
simulated tickets - this MVP never executes containment (config.EXECUTE_CONTAINMENT
is False and there is no code path that touches a real system).
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone

from . import config
from .monitoring import log_event


class ApprovalError(ValueError):
    pass


class ApprovalStore:
    def __init__(self, path=None):
        self.path = path or (config.LOG_DIR / "approvals_audit.jsonl")
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create_request(self, report) -> str:
        rid = f"APR-{uuid.uuid4().hex[:8].upper()}"
        with self._lock:
            self._pending[rid] = {
                "request_id": rid, "host": report.host, "risk_score": report.risk_score, "risk_level": report.risk_level,
                "created_at": _now(), "actions": {a.action_id: a.model_dump() for a in report.recommended_actions},
            }
        log_event("approval_requested", request_id=rid, host=report.host, n_actions=len(report.recommended_actions))
        return rid

    def pending(self, rid: str) -> dict | None:
        return self._pending.get(rid)

    def decide(self, rid: str, approved_ids: list[str], analyst: str, justification: str) -> list[dict]:
        """Approve the selected actions, reject the rest. Returns audit records."""
        analyst = (analyst or "").strip()
        justification = (justification or "").strip()
        with self._lock:
            req = self._pending.get(rid)
            if not req:
                raise ApprovalError("No pending approval request. Run an investigation first (or it was already decided).")
            if len(analyst) < 2:
                raise ApprovalError("Analyst name is required for the audit trail.")
            unknown = [a for a in approved_ids if a not in req["actions"]]
            if unknown:
                raise ApprovalError(f"Cannot approve actions that were not proposed: {unknown}")
            if any(req["actions"][a]["sensitive"] for a in approved_ids) and len(justification) < 10:
                raise ApprovalError("A justification (≥10 characters) is required when approving sensitive actions.")
            records = []
            for aid, act in req["actions"].items():
                ok = aid in approved_ids
                records.append({
                    "ts": _now(), "request_id": rid, "host": req["host"], "risk_score": req["risk_score"],
                    "risk_level": req["risk_level"], "action_id": aid, "action": act["title"], "sensitive": act["sensitive"],
                    "decision": "APPROVED" if ok else "REJECTED", "analyst": analyst[:80], "justification": justification[:500],
                    "execution": "SIMULATED - ticket created for responder, nothing executed" if ok else "n/a",
                })
            del self._pending[rid]
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
        log_event("approval_decided", request_id=rid, approved=len(approved_ids), rejected=len(records) - len(approved_ids), analyst=analyst[:80])
        return records

    def history(self, n: int = 200) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-n:]
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out[::-1]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
