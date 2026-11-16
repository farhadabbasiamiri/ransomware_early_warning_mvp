import pytest

from rewa.approval import ApprovalError


def test_approval_flow(demo_service, demo_labels):
    h = demo_labels[demo_labels.scenario == "rw_fast_encryptor"].host.iloc[0]
    rep, rid = demo_service.investigate(h, mode="offline")
    sens = [a.action_id for a in rep.recommended_actions if a.sensitive]
    with pytest.raises(ApprovalError):
        demo_service.approvals.decide(rid, sens, "", "long enough reason")
    with pytest.raises(ApprovalError):
        demo_service.approvals.decide(rid, sens, "Bob", "short")
    with pytest.raises(ApprovalError):
        demo_service.approvals.decide(rid, ["A99"], "Bob", "long enough reason")
    recs = demo_service.approvals.decide(rid, sens[:2], "Bob Analyst", "Backup deletion by unsigned binary confirmed")
    assert {r["decision"] for r in recs} == {"APPROVED", "REJECTED"}
    assert all("nothing executed" in r["execution"] for r in recs if r["decision"] == "APPROVED")
    with pytest.raises(ApprovalError):  # cannot decide twice
        demo_service.approvals.decide(rid, [], "Bob", "")
    assert demo_service.approvals.history()[0]["request_id"] == rid


def test_reject_all_needs_no_justification(demo_service, demo_labels):
    rep, rid = demo_service.investigate(demo_labels.host.iloc[0], mode="offline")
    recs = demo_service.approvals.decide(rid, [], "Carol", "")
    assert all(r["decision"] == "REJECTED" for r in recs)
