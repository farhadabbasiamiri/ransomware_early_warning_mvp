"""Shared training helpers used by scripts/train_ml.py and by the app's first-run auto-training."""
from __future__ import annotations

import pandas as pd

from . import config


def ensure_split(split: str = "train") -> None:
    """Generate the deterministic synthetic split if it is missing (fresh clone)."""
    out = config.GENERATED_DIR / split
    if (out / "events.csv").exists():
        return
    from .generator import generate_dataset

    params = {"train": dict(n_hosts=120, seed=7, hard_mode=False), "test": dict(n_hosts=60, seed=2026, hard_mode=True),
              "test_fresh": dict(n_hosts=60, seed=2027, hard_mode=True)}[split]
    ev, lab = generate_dataset(**params)
    out.mkdir(parents=True, exist_ok=True)
    ev.drop(columns=["phase"]).to_csv(out / "events.csv", index=False)
    ev[["timestamp", "host", "event_type", "process_name", "command_line", "phase"]].to_csv(out / "event_labels.csv", index=False)
    lab.to_csv(out / "labels.csv", index=False)


def feature_table(split: str) -> pd.DataFrame:
    from .schema import load_events_file
    from .scoring import score_all

    ensure_split(split)
    ev, _ = load_events_file(str(config.GENERATED_DIR / split / "events.csv"))
    lab = pd.read_csv(config.GENERATED_DIR / split / "labels.csv")
    scores = score_all(ev)
    rows = [{"host": h, "rule_score": hs.risk_score, **hs.features} for h, (hs, _) in scores.items()]
    return pd.DataFrame(rows).merge(lab[["host", "scenario", "is_ransomware"]], on="host")


def train_default_model(out_path=None):
    from .monitoring import log_event
    from .scoring import MLScorer

    tr = feature_table("train")
    model, imp = MLScorer.train(tr, tr["is_ransomware"], out_path)
    log_event("ml_trained", hosts=len(tr), status="ok")
    return model, imp, tr
