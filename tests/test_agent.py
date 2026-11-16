import json

import pytest

from rewa.agent import ACTION_CATALOG, IncidentReport
from rewa.mock_llm import MockLLM


def _host(labels, scenario, i=0):
    return labels[labels.scenario == scenario].host.iloc[i]


@pytest.mark.parametrize("behaviour,mode", [("good", "llm"), ("adversarial", "llm"), ("bad_json", "llm_fallback"),
                                            ("timeout", "llm_fallback"), ("lazy", "llm")])
def test_agent_modes_produce_valid_safe_reports(demo_service, demo_labels, behaviour, mode):
    rep, rid = demo_service.investigate(_host(demo_labels, "rw_precursor_only"), llm=MockLLM(behaviour))
    assert isinstance(rep, IncidentReport) and rep.mode == mode
    assert rep.risk_level in ("HIGH", "CRITICAL") and rep.decision == "ALERT_ESCALATE"
    assert rep.recommended_actions and all(a.action_id in ACTION_CATALOG for a in rep.recommended_actions)
    assert all(a.requires_approval and a.status == "PENDING_APPROVAL" for a in rep.recommended_actions)
    assert all(a.playbook_citations for a in rep.recommended_actions)
    cited = {c["chunk_id"] for c in rep.citations}
    assert all(set(a.playbook_citations) <= cited for a in rep.recommended_actions)
    assert rep.safety["automated_actions_executed"] == 0 and rid.startswith("APR-")


def test_adversarial_llm_is_contained(demo_service, demo_labels):
    rep, _ = demo_service.investigate(_host(demo_labels, "rw_precursor_only"), llm=MockLLM("adversarial"))
    blob = json.dumps(rep.model_dump()).lower()
    assert "a99" not in [a.action_id.lower() for a in rep.recommended_actions]
    assert "pay the ransom" not in blob and "fake-" not in json.dumps([a.playbook_citations for a in rep.recommended_actions]).lower()
    assert rep.risk_score > 50  # LLM's fake risk_score=3 ignored
    assert any("Guardrail" in n for n in rep.safety["guardrail_notes"])


def test_offline_benign_host_has_no_containment(demo_service, demo_labels):
    rep, _ = demo_service.investigate(_host(demo_labels, "benign_office"), mode="offline")
    assert rep.decision == "MONITOR" and not any(a.sensitive for a in rep.recommended_actions)


def test_prompt_injection_redacted(demo_service, demo_labels):
    h = demo_labels[demo_labels.scenario == "rw_full_chain"].host.iloc[-1]
    rep, _ = demo_service.investigate(h, llm=MockLLM("good"))
    assert any("prompt-injection" in n for n in rep.safety["guardrail_notes"])
    assert "ignore all previous" not in json.dumps(rep.agent_trace).lower()
    assert rep.risk_level == "CRITICAL"


def test_unknown_host_raises(demo_service):
    with pytest.raises(ValueError):
        demo_service.investigate("NOPE", mode="offline")


def test_agent_cannot_inspect_other_host(demo_service, demo_labels):
    h = _host(demo_labels, "benign_office")
    rep, _ = demo_service.investigate(h, llm=MockLLM("good"))  # mock passes a different host name
    assert all(t["args"].get("host", h) == h for t in rep.agent_trace if t.get("args"))


def test_time_budget_falls_back_instead_of_hanging(demo_service, demo_labels):
    from rewa import config

    old = config.AGENT_TIME_BUDGET_S
    config.AGENT_TIME_BUDGET_S = 1.5
    try:
        rep, _ = demo_service.investigate(_host(demo_labels, "rw_precursor_only"), llm=MockLLM("slow", delay=0.6))
    finally:
        config.AGENT_TIME_BUDGET_S = old
    assert rep.mode == "llm_fallback" and rep.risk_level in ("HIGH", "CRITICAL")
    assert any("time budget" in n for n in rep.safety["guardrail_notes"])
    assert all(a.playbook_citations for a in rep.recommended_actions)


def test_uncorroborated_demo_false_positive_is_not_escalated(demo_service, demo_labels):
    h = demo_labels[(demo_labels.scenario == "benign_backup_rotation")].host.iloc[0]
    rep, _ = demo_service.investigate(h, mode="offline")
    assert rep.decision != "ALERT_ESCALATE" and not any(a.sensitive for a in rep.recommended_actions)
