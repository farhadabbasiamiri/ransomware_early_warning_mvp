"""Tests the real HTTP clients against local fake Ollama / OpenAI servers."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from rewa.llm import LLMError, OllamaLLM, OpenAICompatLLM


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/api/tags":
            self._send({"models": [{"name": "qwen2.5:7b-instruct"}]})
        elif self.path == "/v1/models":
            self._send({"data": [{"id": "local"}]})
        else:
            self._send({}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Handler.last = body
        if self.path == "/api/generate":  # warm-up / model load
            self._send({"model": body.get("model"), "done": True})
        elif self.path == "/api/chat":
            if body.get("tools"):
                self._send({"message": {"role": "assistant", "content": "",
                                        "tool_calls": [{"function": {"name": "score_host_behavior", "arguments": {"host": "H1"}}}]}})
            else:
                self._send({"message": {"role": "assistant", "content": "{\"executive_summary\": \"x\"}"}})
        elif self.path == "/v1/chat/completions":
            self._send({"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "search_playbooks", "arguments": "{\"query\": \"q\"}"}}]}}]})
        else:
            self._send({"error": "x"}, 500)


@pytest.fixture(scope="module")
def server():
    s = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_port}"
    s.shutdown()


def test_ollama_tool_call_parsing(server):
    llm = OllamaLLM("qwen2.5:7b-instruct", server)
    assert llm.health()[0]
    out = llm.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function", "function": {"name": "x"}}])
    assert out["tool_calls"][0]["name"] == "score_host_behavior" and out["tool_calls"][0]["arguments"] == {"host": "H1"}
    assert Handler.last["stream"] is False and Handler.last["tools"]


def test_ollama_json_mode(server):
    out = OllamaLLM("qwen2.5:7b-instruct", server).chat([{"role": "user", "content": "r"}], json_mode=True)
    assert Handler.last["format"] == "json" and json.loads(out["content"])["executive_summary"] == "x"


def test_ollama_missing_model_health(server):
    ok, msg = OllamaLLM("llama3.1:8b", server).health()
    assert not ok and "ollama pull" in msg


def test_openai_compatible_parsing(server):
    llm = OpenAICompatLLM("local", server)
    assert llm.health()[0]
    out = llm.chat([{"role": "user", "content": "hi"}], tools=[{"type": "function", "function": {"name": "x"}}])
    assert out["tool_calls"][0] == {"id": "c1", "name": "search_playbooks", "arguments": {"query": "q"}}


def test_unreachable_server_raises_llmerror():
    llm = OllamaLLM("m", "http://127.0.0.1:9", timeout=1)
    assert not llm.health()[0]
    with pytest.raises(LLMError):
        llm.chat([{"role": "user", "content": "x"}])


def test_ollama_keep_alive_and_warmup(server):
    llm = OllamaLLM("qwen2.5:7b-instruct", server)
    llm.chat([{"role": "user", "content": "hi"}])
    assert Handler.last["keep_alive"] and Handler.last["options"]["num_ctx"] > 0
    ok, msg = llm.warmup()
    assert ok and "loaded" in msg and Handler.last["prompt"] == "" and Handler.last["keep_alive"]


def test_per_call_timeout_is_capped_by_budget(server):
    llm = OllamaLLM("qwen2.5:7b-instruct", server, timeout=90)
    llm.chat([{"role": "user", "content": "hi"}], timeout=5)
    assert llm._call_timeout == 5


def test_warmup_failure_is_reported():
    ok, msg = OllamaLLM("m", "http://127.0.0.1:9", timeout=1).warmup()
    assert not ok and "failed" in msg


# ---- full agent over HTTP: OllamaLLM client -> fake Ollama server that answers like a tool-calling model ----
class AgentHandler(BaseHTTPRequestHandler):
    bodies: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        b = json.dumps({"models": [{"name": "qwen2.5:7b-instruct"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        from rewa.mock_llm import MockLLM

        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        AgentHandler.bodies.append(body)
        out = MockLLM("good")._chat(body["messages"], body.get("tools"), body.get("format") == "json")
        msg = {"role": "assistant", "content": out["content"],
               "tool_calls": [{"function": {"name": c["name"], "arguments": c["arguments"]}} for c in out["tool_calls"]]}
        b = json.dumps({"message": msg, "done": True}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def test_agent_end_to_end_over_ollama_http(demo_service, demo_labels):
    s = HTTPServer(("127.0.0.1", 0), AgentHandler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        host = demo_labels[demo_labels.scenario == "rw_precursor_only"].host.iloc[0]
        rep, _ = demo_service.investigate(host, llm=OllamaLLM("qwen2.5:7b-instruct", f"http://127.0.0.1:{s.server_port}"))
    finally:
        s.shutdown()
    assert rep.mode == "llm" and rep.risk_level == "CRITICAL"
    assert [t["tool"] for t in rep.agent_trace if t.get("by") == "llm" and t.get("tool")][:4] == [
        "score_host_behavior", "get_host_timeline", "map_to_mitre", "search_playbooks"]
    assert all(b.get("keep_alive") for b in AgentHandler.bodies)
    assert any(b.get("format") == "json" for b in AgentHandler.bodies)  # report step used JSON mode
