"""LLM clients: Ollama (native tool calling) and OpenAI-compatible (LM Studio,
vLLM, hosted APIs). Both expose the same `chat()` returning a normalised
message: {"content": str, "tool_calls": [{"id", "name", "arguments": dict}]}.
"""
from __future__ import annotations

import json
import re
import time

import requests

from . import config
from .monitoring import log_event


class LLMError(RuntimeError):
    pass


def _extract_json_tool_call(text: str) -> list[dict]:
    """Fallback for models without native tool calling: accept
    {"tool": "name", "arguments": {...}} written in the message text."""
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        return []
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    name = obj.get("tool") or obj.get("name") or obj.get("function")
    if isinstance(name, str) and isinstance(obj.get("arguments", {}), dict):
        return [{"id": "json-0", "name": name, "arguments": obj.get("arguments", {})}]
    return []


class BaseLLM:
    provider = "base"

    def __init__(self, model: str | None = None, base_url: str | None = None, timeout: float | None = None):
        self.model = model or config.LLM_MODEL
        self.base_url = (base_url or config.LLM_BASE_URL).rstrip("/")
        self.timeout = timeout or config.LLM_TIMEOUT_S
        self._call_timeout = self.timeout

    def health(self) -> tuple[bool, str]:
        raise NotImplementedError

    def warmup(self) -> tuple[bool, str]:
        """Load the model into memory ahead of the first investigation (optional)."""
        return True, "warm-up not needed"

    def chat(self, messages: list[dict], tools: list[dict] | None = None, json_mode: bool = False,
             timeout: float | None = None) -> dict:
        t0 = time.perf_counter()
        self._call_timeout = max(1.0, min(self.timeout, timeout)) if timeout else self.timeout
        try:
            out = self._chat(messages, tools, json_mode)
            log_event("llm_call", provider=self.provider, model=self.model, status="ok",
                      latency_ms=round((time.perf_counter() - t0) * 1000, 1), tool_calls=len(out["tool_calls"]))
            return out
        except requests.Timeout as exc:
            log_event("llm_call", provider=self.provider, model=self.model, status="error", error="timeout",
                      latency_ms=round((time.perf_counter() - t0) * 1000, 1))
            raise LLMError(f"LLM timed out after {self._call_timeout:.0f}s") from exc
        except (requests.RequestException, KeyError, ValueError) as exc:
            log_event("llm_call", provider=self.provider, model=self.model, status="error", error=str(exc)[:200],
                      latency_ms=round((time.perf_counter() - t0) * 1000, 1))
            raise LLMError(f"LLM request failed: {type(exc).__name__}: {str(exc)[:200]}") from exc


class OllamaLLM(BaseLLM):
    provider = "ollama"

    def health(self) -> tuple[bool, str]:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            r.raise_for_status()
            names = [m.get("name", "") for m in r.json().get("models", [])]
            if not any(n == self.model or n.split(":")[0] == self.model.split(":")[0] for n in names):
                return False, f"Ollama reachable but model '{self.model}' not pulled (run: ollama pull {self.model})"
            return True, f"Ollama OK - model {self.model}"
        except Exception as exc:
            return False, f"Ollama not reachable at {self.base_url} ({type(exc).__name__})"

    def _chat(self, messages, tools, json_mode):
        body = {"model": self.model, "messages": messages, "stream": False, "keep_alive": config.LLM_KEEP_ALIVE,
                "options": {"temperature": config.LLM_TEMPERATURE, "num_ctx": config.LLM_NUM_CTX}}
        if tools:
            body["tools"] = tools
        if json_mode:
            body["format"] = "json"
        r = requests.post(f"{self.base_url}/api/chat", json=body, timeout=self._call_timeout)
        r.raise_for_status()
        msg = r.json()["message"]
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                args = json.loads(args or "{}")
            calls.append({"id": tc.get("id", f"call-{i}"), "name": fn.get("name", ""), "arguments": args})
        if tools and not calls:
            calls = _extract_json_tool_call(msg.get("content", "")) if '"tool"' in (msg.get("content") or "") else []
        return {"content": msg.get("content") or "", "tool_calls": calls}

    def warmup(self) -> tuple[bool, str]:
        """Ollama loads a model when it receives an empty prompt; keep_alive keeps it loaded.
        The first load of a 7B model on a laptop can take 30-90 s, so we do it before the demo."""
        t0 = time.perf_counter()
        try:
            r = requests.post(f"{self.base_url}/api/generate", json={"model": self.model, "prompt": "", "keep_alive": config.LLM_KEEP_ALIVE},
                              timeout=max(self.timeout, 300))
            r.raise_for_status()
            secs = time.perf_counter() - t0
            log_event("llm_warmup", provider=self.provider, model=self.model, status="ok", latency_ms=round(secs * 1000, 1))
            return True, f"model loaded in memory ({secs:.0f} s), kept for {config.LLM_KEEP_ALIVE}"
        except Exception as exc:  # noqa: BLE001
            log_event("llm_warmup", provider=self.provider, model=self.model, status="error", error=str(exc)[:200])
            return False, f"warm-up failed ({type(exc).__name__})"

    @staticmethod
    def tool_result_message(call: dict, result: dict) -> dict:
        return {"role": "tool", "tool_name": call["name"], "content": json.dumps(result, default=str)}

    @staticmethod
    def assistant_message(out: dict) -> dict:
        return {"role": "assistant", "content": out["content"],
                "tool_calls": [{"function": {"name": c["name"], "arguments": c["arguments"]}} for c in out["tool_calls"]]}


class OpenAICompatLLM(BaseLLM):
    provider = "openai"

    def _headers(self):
        return {"Authorization": f"Bearer {config.LLM_API_KEY}"} if config.LLM_API_KEY else {}

    def health(self) -> tuple[bool, str]:
        try:
            r = requests.get(f"{self.base_url}/v1/models", headers=self._headers(), timeout=3)
            r.raise_for_status()
            return True, f"OpenAI-compatible server OK - model {self.model}"
        except Exception as exc:
            return False, f"OpenAI-compatible server not reachable at {self.base_url} ({type(exc).__name__})"

    def _chat(self, messages, tools, json_mode):
        body = {"model": self.model, "messages": messages, "temperature": config.LLM_TEMPERATURE}
        if tools:
            body["tools"] = tools
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        r = requests.post(f"{self.base_url}/v1/chat/completions", json=body, headers=self._headers(), timeout=self._call_timeout)
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        calls = [{"id": tc.get("id", f"call-{i}"), "name": tc["function"]["name"],
                  "arguments": json.loads(tc["function"].get("arguments") or "{}")}
                 for i, tc in enumerate(msg.get("tool_calls") or [])]
        return {"content": msg.get("content") or "", "tool_calls": calls}

    @staticmethod
    def tool_result_message(call: dict, result: dict) -> dict:
        return {"role": "tool", "tool_call_id": call["id"], "content": json.dumps(result, default=str)}

    @staticmethod
    def assistant_message(out: dict) -> dict:
        m = {"role": "assistant", "content": out["content"] or None}
        if out["tool_calls"]:
            m["tool_calls"] = [{"id": c["id"], "type": "function",
                                "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])}} for c in out["tool_calls"]]
        return m


def make_llm(provider: str | None = None, model: str | None = None, base_url: str | None = None) -> BaseLLM | None:
    provider = (provider or config.LLM_PROVIDER).lower()
    if provider == "ollama":
        return OllamaLLM(model, base_url)
    if provider in ("openai", "lmstudio", "openai-compatible"):
        return OpenAICompatLLM(model, base_url or "http://localhost:1234")
    return None  # offline
