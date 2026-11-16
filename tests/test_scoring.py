import pandas as pd

from rewa import config
from rewa.features import IndicatorResult
from rewa.scoring import rule_score


def _inds(sevs):
    return [IndicatorResult(f"I{i+1}", "x", s, w) for i, (s, w) in enumerate(sevs)]


def test_rule_score_bounds_and_monotonic():
    assert rule_score(_inds([(0, 0.6)] * 8)) == 0
    assert rule_score(_inds([(1, 1.0)])) == 100
    a = rule_score(_inds([(0.5, 0.6), (0, 0.5)]))
    b = rule_score(_inds([(0.5, 0.6), (0.5, 0.5)]))
    assert 0 < a < b < 100


def test_risk_levels():
    assert config.risk_level(99) == "CRITICAL" and config.risk_level(50) == "HIGH"
    assert config.risk_level(30) == "MEDIUM" and config.risk_level(3) == "LOW"


def test_demo_ranking_and_timeline(demo_service, demo_labels):
    r = demo_service.ranking()
    m = r.merge(demo_labels, on="host")
    assert m[m.is_ransomware == 1].risk_score.min() > config.ALERT_THRESHOLD
    top = r.host.iloc[0]
    hs, tl = demo_service.host_score(top)
    assert hs.first_alert_ts and (tl.risk_score.diff().dropna() >= -1e-9).all()  # cumulative score never decreases


def test_precursor_only_host_alerts_without_encryption(demo_service, demo_labels):
    h = demo_labels[demo_labels.scenario == "rw_precursor_only"].host.iloc[0]
    hs, _ = demo_service.host_score(h)
    assert hs.risk_level in ("HIGH", "CRITICAL") and not any(i.id in ("I1", "I2", "I3") for i in hs.active)
