"""Risk scoring: explainable rule-based score (primary) + ML second opinion.

Rule score = 100 * (1 - Π_i (1 - w_i * s_i))   (noisy-OR over indicators)
  - bounded 0..100, monotonic, and each indicator's contribution is visible.
ML = RandomForest over the 14 numeric features, trained on the synthetic
training split only; shown as a second opinion, never used alone to act.
"""
from __future__ import annotations

import json
import pickle
from dataclasses import dataclass

import numpy as np
import pandas as pd

from . import config
from .features import FEATURE_NAMES, IndicatorResult, annotate, host_features
from .mitre import techniques_for


@dataclass
class HostScore:
    host: str
    risk_score: float
    risk_level: str
    ml_probability: float | None
    indicators: list[IndicatorResult]
    features: dict
    n_events: int
    first_event: str
    last_event: str
    first_alert_ts: str = ""

    @property
    def active(self) -> list[IndicatorResult]:
        return sorted([i for i in self.indicators if i.severity > 0], key=lambda i: -i.contribution)

    @property
    def disagreement(self) -> bool:
        if self.ml_probability is None:
            return False
        return abs(self.ml_probability * 100 - self.risk_score) >= 50

    def summary_row(self) -> dict:
        act = self.active
        return {
            "host": self.host,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "ml_probability": None if self.ml_probability is None else round(self.ml_probability, 3),
            "active_indicators": len(act),
            "top_indicators": "; ".join(f"{i.id} {i.name}" for i in act[:3]),
            "mitre": ", ".join(sorted({t["id"] for i in act for t in techniques_for(i.id)})),
            "first_alert": self.first_alert_ts,
            "events": self.n_events,
        }

    def as_dict(self) -> dict:
        return {
            "host": self.host, "risk_score": round(self.risk_score, 1), "risk_level": self.risk_level,
            "ml_probability": None if self.ml_probability is None else round(self.ml_probability, 3),
            "model_disagreement": self.disagreement, "alert_threshold": config.ALERT_THRESHOLD,
            "n_events": self.n_events, "time_range": [self.first_event, self.last_event],
            "first_alert_ts": self.first_alert_ts,
            "indicators": [i.as_dict() for i in self.indicators], "features": self.features,
        }


def rule_score(indicators: list[IndicatorResult]) -> float:
    p = 1.0
    for ind in indicators:
        p *= 1.0 - min(1.0, max(0.0, ind.weight * ind.severity))
    return round(100.0 * (1.0 - p), 2)


class MLScorer:
    """RandomForest second opinion. Robust to missing, outdated or incompatible model files:
    the saved bundle records the feature list and scikit-learn version, and with auto_train=True
    a stale model is retrained from the synthetic train split (about 5 s) instead of crashing."""

    def __init__(self, path=None, auto_train: bool = False):
        self.path = path or (config.MODEL_DIR / "rf_model.pkl")
        self.model = None
        self.status = "not trained"
        if self.path.exists():
            self.model, self.status = self._load()
        if self.model is None and auto_train:
            try:
                from .training import train_default_model

                train_default_model(self.path)
                self.model, self.status = self._load()
                self.status = "trained automatically on first run"
            except Exception as exc:  # noqa: BLE001 - ML is optional; rules still work
                self.model, self.status = None, f"auto-training failed ({type(exc).__name__})"

    def _load(self):
        try:
            with open(self.path, "rb") as fh:
                obj = pickle.load(fh)  # only ever a local file written by MLScorer.train
        except Exception as exc:  # noqa: BLE001
            return None, f"unreadable model file ({type(exc).__name__})"
        model = obj.get("model") if isinstance(obj, dict) else obj
        feats = obj.get("features") if isinstance(obj, dict) else None
        if getattr(model, "n_features_in_", None) != len(FEATURE_NAMES) or (feats is not None and feats != FEATURE_NAMES):
            return None, "model trained on an older feature set"
        try:
            import sklearn

            if isinstance(obj, dict) and obj.get("sklearn") and obj["sklearn"] != sklearn.__version__:
                return None, f"model saved with scikit-learn {obj['sklearn']}, running {sklearn.__version__}"
        except ImportError:
            return None, "scikit-learn not installed"
        return model, "loaded"

    @property
    def available(self) -> bool:
        return self.model is not None

    def predict(self, feats: dict) -> float | None:
        if not self.model:
            return None
        try:
            x = np.array([[feats[k] for k in FEATURE_NAMES]])
            return float(self.model.predict_proba(x)[0, 1])
        except Exception:  # noqa: BLE001 - never let the second opinion break scoring
            return None

    @staticmethod
    def train(X: pd.DataFrame, y: pd.Series, out_path=None, seed: int = 7):
        import sklearn
        from sklearn.ensemble import RandomForestClassifier

        model = RandomForestClassifier(n_estimators=300, max_depth=5, min_samples_leaf=2, class_weight="balanced", random_state=seed)
        model.fit(X[FEATURE_NAMES].to_numpy(), y.to_numpy())
        out_path = out_path or (config.MODEL_DIR / "rf_model.pkl")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as fh:
            pickle.dump({"model": model, "features": list(FEATURE_NAMES), "sklearn": sklearn.__version__}, fh)
        imp = dict(sorted(zip(FEATURE_NAMES, model.feature_importances_.round(4).tolist()), key=lambda kv: -kv[1]))
        (out_path.parent / "rf_feature_importance.json").write_text(json.dumps(imp, indent=2))
        return model, imp


def score_host_df(annotated: pd.DataFrame, ml: MLScorer | None = None, with_timeline: bool = False) -> tuple[HostScore, pd.DataFrame | None]:
    host = str(annotated["host"].iloc[0])
    feats, inds = host_features(annotated)
    score = rule_score(inds)
    hs = HostScore(host, score, config.risk_level(score), ml.predict(feats) if ml else None, inds, feats, len(annotated),
                   annotated["ts"].min().strftime("%Y-%m-%d %H:%M:%S UTC"), annotated["ts"].max().strftime("%Y-%m-%d %H:%M:%S UTC"))
    tl = None
    if with_timeline:
        tl = risk_timeline(annotated)
        hit = tl[tl["risk_score"] >= config.ALERT_THRESHOLD]
        if len(hit):
            hs.first_alert_ts = hit["ts"].iloc[0].strftime("%Y-%m-%d %H:%M:%S UTC")
    return hs, tl


FLAG_COLS = ["f_rename_unusual", "f_high_entropy", "f_note", "f_backup_strong", "f_backup_weak", "f_recovery", "f_svc_tamper",
             "f_priv", "f_elev_temp", "f_office_shell", "f_enc_ps", "f_temp_exec", "f_discovery"]


def risk_timeline(a: pd.DataFrame, max_points: int = 120) -> pd.DataFrame:
    """Cumulative risk score over time, evaluated at every suspicious event
    (where the score can change) plus regular checkpoints."""
    a = a.sort_values("ts")
    flagged = a[a[FLAG_COLS].any(axis=1)]["ts"]
    regular = pd.date_range(a["ts"].min(), a["ts"].max(), periods=min(30, max(2, len(a))))
    pts = pd.Series(pd.concat([flagged, pd.Series(regular)]).sort_values().unique())
    if len(pts) > max_points:  # keep all early points, thin the dense impact phase
        idx = np.unique(np.concatenate([np.arange(0, min(len(pts), max_points // 2)),
                                        np.linspace(0, len(pts) - 1, max_points // 2).astype(int)]))
        pts = pts.iloc[idx]
    sus = a[a[FLAG_COLS].any(axis=1)]
    rows = []
    for t in pts:
        sub = sus[sus["ts"] <= t]
        if len(sub) == 0:
            rows.append({"ts": t, "risk_score": 0.0})
            continue
        _, inds = host_features(sub)
        rows.append({"ts": t, "risk_score": rule_score(inds)})
    return pd.DataFrame(rows)


def score_all(events: pd.DataFrame, ml: MLScorer | None = None, with_timeline: bool = False) -> dict[str, tuple[HostScore, pd.DataFrame | None]]:
    a = annotate(events)
    return {h: score_host_df(g, ml, with_timeline) for h, g in a.groupby("host", sort=False)}


def ranking_table(scores: dict) -> pd.DataFrame:
    rows = [hs.summary_row() for hs, _ in scores.values()]
    return pd.DataFrame(rows).sort_values(["risk_score", "host"], ascending=[False, True]).reset_index(drop=True)
