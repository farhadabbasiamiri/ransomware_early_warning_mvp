"""Scripted LLM stand-ins for testing the agent loop without a model server.

Behaviours:
  good        - calls tools like a competent model, returns a valid report
  adversarial - proposes an unknown destructive action, a fake citation,
                evidence for an inactive indicator and an unsafe rationale
  bad_json    - returns invalid JSON for the report (tests retry + fallback)
  timeout     - raises LLMError immediately (tests offline fallback)
  lazy        - never calls tools (tests the required-tool guardrail)
  slow        - behaves like "good" but sleeps `delay` seconds per call (tests the time budget)
"""
from __future__ import annotations

import json

from .llm import BaseLLM, LLMError, OllamaLLM


class MockLLM(BaseLLM):
    provider = "mock"

    def __init__(self, behaviour: str = "good", delay: float = 0.0):
        super().__init__(model=f"mock-{behaviour}", base_url="http://mock")
        self.behaviour = behaviour
        self.delay = delay
        self.calls = 0

    def health(self):
        return True, "mock"

    tool_result_message = staticmethod(OllamaLLM.tool_result_message)
    assistant_message = staticmethod(OllamaLLM.assistant_message)

    def _chat(self, messages, tools, json_mode):
        self.calls += 1
        if self.behaviour == "slow":
            import time

            time.sleep(self.delay)
        if self.behaviour == "timeout":
            raise LLMError("mock timeout")
        if tools:  # investigation loop
            if self.behaviour == "lazy":
                return {"content": "DONE", "tool_calls": []}
            done = [m.get("tool_name") for m in messages if m.get("role") == "tool"]
            last = next((json.loads(m["content"]) for m in reversed(messages) if m.get("tool_name") == "score_host_behavior"), None)
            if "score_host_behavior" not in done:
                return _call("score_host_behavior", {"host": "ignored-agent-pins-host"})
            if "get_host_timeline" not in done:
                return _call("get_host_timeline", {"max_events": 20})
            ids = [i["id"] for i in (last or {}).get("active_indicators", [])]
            if "map_to_mitre" not in done and ids:
                return _call("map_to_mitre", {"indicator_ids": ids})
            if done.count("search_playbooks") < min(2, max(1, len(ids))):
                q = ["isolate host containment ransomware", "shadow copy deletion backups"][done.count("search_playbooks")]
                return _call("search_playbooks", {"query": q, "k": 3})
            return {"content": "DONE", "tool_calls": []}
        # report step
        if self.behaviour == "bad_json":
            return {"content": "Sure! Here is the report: {not valid json", "tool_calls": []}
        user = messages[-1]["content"]
        cands = json.loads(user.split("candidate action ids: ")[1].split(".")[0].replace("'", '"'))
        chunks = json.loads(user.split("playbook chunk ids: ")[1].split(".")[0].replace("'", '"'))
        rep = {
            "executive_summary": "Host shows ransomware early-warning behaviour; containment is recommended pending analyst approval.",
            "incident_narrative": "Suspicious execution was followed by backup deletion and file encryption activity.",
            "key_evidence": [{"indicator_id": "I4", "statement": "Shadow copies deleted by a non-backup process.", "citation": chunks[0] if chunks else None}],
            "recommended_actions": [{"action_id": c, "rationale": "Playbook-aligned step.", "playbook_citations": chunks[:1]} for c in cands[:4]],
            "uncertainty": "Synthetic thresholds; no network context.",
            "false_positive_considerations": "Check for backup software or maintenance windows.",
        }
        if self.behaviour == "adversarial":
            rep["recommended_actions"] += [
                {"action_id": "A99", "rationale": "Wipe the disk and format the disk now.", "playbook_citations": ["KB99-9"]},
                {"action_id": cands[0] if cands else "A11", "rationale": "Pay the ransom to recover quickly.", "playbook_citations": ["FAKE-1"]},
            ]
            rep["key_evidence"].append({"indicator_id": "I5" if "I5" not in user else "I9", "statement": "Invented evidence.", "citation": "FAKE-2"})
            rep["risk_score"] = 3.0  # should be ignored: extra keys are not trusted
        return {"content": json.dumps(rep), "tool_calls": []}


def _call(name, args):
    return {"content": "", "tool_calls": [{"id": f"m-{name}", "name": name, "arguments": args}]}
