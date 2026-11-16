"""Lightweight monitoring: structured JSONL logs + in-memory metrics.

Logged: tool calls (name, latency, status), LLM calls (latency, provider,
errors), agent runs, approval decisions. Raw command lines / file paths are
NOT written to the monitoring log to limit sensitive data exposure.
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

_lock = threading.Lock()
_recent: deque = deque(maxlen=500)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def log_event(kind: str, **fields) -> dict:
    rec = {"ts": _now(), "kind": kind, **fields}
    with _lock:
        _recent.append(rec)
        try:
            config.LOG_DIR.mkdir(parents=True, exist_ok=True)
            with open(config.LOG_DIR / "rewa_events.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
        except OSError:
            pass  # logging must never break the app
    return rec


@contextmanager
def timed(kind: str, **fields):
    t0 = time.perf_counter()
    status = {"status": "ok"}
    try:
        yield status
    except Exception as exc:
        status["status"] = "error"
        status["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        raise
    finally:
        log_event(kind, latency_ms=round((time.perf_counter() - t0) * 1000, 1), **fields, **status)


def recent(n: int = 50, kind: str | None = None) -> list[dict]:
    with _lock:
        items = [r for r in _recent if kind is None or r["kind"] == kind]
    return items[-n:]


def metrics() -> dict:
    with _lock:
        items = list(_recent)
    out: dict = {}
    for r in items:
        k = r["kind"] if r["kind"] != "tool_call" else f"tool:{r.get('tool')}"
        m = out.setdefault(k, {"count": 0, "errors": 0, "latency_ms": []})
        m["count"] += 1
        m["errors"] += int(r.get("status") == "error")
        if "latency_ms" in r:
            m["latency_ms"].append(r["latency_ms"])
    for m in out.values():
        lat = sorted(m.pop("latency_ms"))
        m["p50_ms"] = lat[len(lat) // 2] if lat else None
        m["max_ms"] = lat[-1] if lat else None
    return out
