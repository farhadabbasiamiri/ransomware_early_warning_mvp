"""UI handler tests + app.py wiring test with a recording Gradio stub
(verifies every event handler returns exactly as many values as wired outputs)."""
import importlib
import sys
import types

import pandas as pd

from rewa import ui_handlers as H


def test_handlers_end_to_end(demo_labels):
    md, df, fig, hosts, first = H.load_demo()
    assert "Loaded" in md and len(df) == 12 and first == df.host.iloc[0]
    out = H.investigate(first, "offline", "", "")
    assert len(out) == 12 and "CRITICAL" in out[0] and out[9].startswith("APR-") and out[10]
    md2, audit, rid = H.decide(out[9], out[10][:1], "", "", True)
    assert "❌" in md2 and rid == out[9]  # analyst name missing -> still pending
    md3, audit, rid = H.decide(out[9], out[10][:2], "Uttam", "Shadow copies deleted by unknown binary", True)
    assert "✅" in md3 and rid == "" and len(audit) > 0


def test_handlers_errors(tmp_path):
    assert "❌" in H.load_upload(None)[0]
    p = tmp_path / "bad.csv"
    p.write_text("a,b\n1,2")
    assert "rejected" in H.load_upload(str(p))[0]
    assert "❌" in H.investigate("", "offline", "", "")[0]
    assert "❌" in H.decide("", [], "x", "y")[0]
    assert "⚠️" in H.check_llm("ollama", "x", "http://127.0.0.1:9") or "✅" in H.check_llm("ollama", "x", "http://127.0.0.1:9")
    assert len(H.system_view()) == 3 and len(H.evaluation_view()) == 6


class _C:
    """Records any Gradio component / layout call."""
    registry = []

    def __init__(self, *a, **k):
        self.kw = k

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def click(self, fn, inputs=None, outputs=None, **k):
        _C.registry.append((fn, inputs, outputs))

    load = click

    def __call__(self, *a, **k):  # gr.Progress() instances are called with (fraction, desc=...)
        return None

    def queue(self, **k):
        return self

    def launch(self, **k):
        pass


def _stub():
    g = types.ModuleType("gradio")
    for n in ["Blocks", "Tab", "Row", "Column", "Accordion", "Markdown", "Button", "File", "Plot", "Dataframe", "Dropdown",
              "Textbox", "CheckboxGroup", "Code", "Image", "State", "Progress"]:
        setattr(g, n, _C)
    g.themes = types.SimpleNamespace(Soft=lambda **k: None)
    g.update = lambda **k: ("update", k)
    return g


def test_app_wiring(monkeypatch):
    monkeypatch.setitem(sys.modules, "gradio", _stub())
    sys.modules.pop("app", None)
    app = importlib.import_module("app")
    _C.registry.clear()
    app.build()
    assert len(_C.registry) >= 10
    H.load_demo()
    host = H.SVC.hosts()[0]
    dummy = {"host": host, "mode": "offline"}
    for fn, inputs, outputs in _C.registry:
        n_in = 0 if inputs is None else (1 if isinstance(inputs, _C) else len(inputs))
        args = {0: (), 1: (None,), 4: (host, "offline", "", "")}.get(n_in, ("",) * n_in)
        res = fn(*args)
        n_out = 1 if isinstance(outputs, _C) else len(outputs)
        got = 1 if not isinstance(res, tuple) else len(res)
        assert got == n_out, f"{fn} returns {got} values for {n_out} outputs"
