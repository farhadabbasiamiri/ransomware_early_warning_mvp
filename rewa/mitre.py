"""Map behavioural indicators to MITRE ATT&CK techniques (local, offline)."""
from __future__ import annotations

import json
from functools import lru_cache

from . import config


@lru_cache(maxsize=1)
def _db() -> dict:
    return json.loads((config.DATA_DIR / "mitre_techniques.json").read_text(encoding="utf-8"))


def technique(tid: str) -> dict | None:
    t = _db()["techniques"].get(tid)
    return {"id": tid, **t} if t else None


def techniques_for(indicator_id: str) -> list[dict]:
    return [technique(t) for t in _db()["indicator_map"].get(indicator_id, []) if technique(t)]


def map_indicators(indicator_ids: list[str], evidence: dict[str, list[str]] | None = None) -> list[dict]:
    """Return de-duplicated techniques with the indicators that triggered them.

    Sub-technique specificity for I8 is evidence-driven so we don't claim
    techniques we have no evidence for (e.g. only map T1482 if nltest seen).
    """
    evidence = evidence or {}
    out: dict[str, dict] = {}
    for iid in indicator_ids:
        ev = " ".join(evidence.get(iid, [])).lower()
        for t in techniques_for(iid):
            if iid == "I8":
                rules = {
                    "T1059.001": "powershell" in ev or "shell" in ev,
                    "T1027": "encoded" in ev,
                    "T1204.002": "office app spawned" in ev,
                    "T1083": "discovery burst" in ev,
                    "T1135": "discovery burst" in ev and ("net view" in ev or "net share" in ev),
                    "T1482": "nltest" in ev,
                }
                if not rules.get(t["id"], True) and evidence:
                    continue
            if iid == "I7" and t["id"] == "T1068" and evidence and "integrity" not in ev:
                continue
            entry = out.setdefault(t["id"], {**t, "triggered_by": []})
            entry["triggered_by"].append(iid)
    return list(out.values())  # keeps order of indicator importance (input order)
