"""Gradio dashboard - Endpoint Ransomware Early-Warning Agent (Group 7A).

Run:  python app.py      then open http://127.0.0.1:7860
All logic lives in rewa/ui_handlers.py (unit-tested); this file only wires UI.
Compatible with Gradio 4.44+ and 5.x.
"""
from __future__ import annotations

import os

import gradio as gr

from rewa import config
from rewa import ui_handlers as H

CSS = """
.gradio-container {max-width: 1400px !important}
#title h1 {margin-bottom: 0}
.safety-banner {background:#fff7ed;border-left:4px solid #e0612b;padding:8px 12px;border-radius:6px;font-size:0.92em}
"""


def _fleet(out):
    md, df, fig, hosts, first = out
    return md, df, fig, gr.update(choices=hosts, value=first)


def _investigate(host, mode, model, url, progress=gr.Progress()):
    if (mode or "").lower() != "offline":
        progress(0.05, desc="Agent investigating with the LLM - up to a few minutes on a laptop CPU")
    (md, tfig, cfig, ev, mitre, acts, cites, trace, js, rid, choices, appr) = H.investigate(host, mode, model, url)
    return (md, tfig, cfig, ev, mitre, acts, cites, trace, js, rid,
            gr.update(choices=choices, value=[]), appr)


def build() -> gr.Blocks:
    with gr.Blocks(title="Ransomware Early-Warning Agent", theme=gr.themes.Soft(primary_hue="orange"), css=CSS) as demo:
        gr.Markdown("# 🛡️ Endpoint Ransomware Early-Warning Agent", elem_id="title")
        gr.Markdown("Scores hosts for ransomware likelihood, explains the evidence, maps it to MITRE ATT&CK, retrieves response "
                    "playbook guidance and proposes **human-approved** containment. Defensive use only · synthetic data.",
                    elem_classes="safety-banner")
        rid_state = gr.State("")

        # ---------------- Tab 1 ----------------
        with gr.Tab("1 · Fleet risk ranking"):
            with gr.Row():
                with gr.Column(scale=1):
                    btn_demo = gr.Button("▶ Load demo dataset (12 synthetic hosts)", variant="primary")
                    upload = gr.File(label="…or upload endpoint telemetry (.csv / .json / .jsonl)", file_types=[".csv", ".json", ".jsonl"],
                                     type="filepath")
                    btn_upload = gr.Button("Load uploaded file")
                    gr.Markdown("Required columns: `timestamp, host, event_type`. Optional: `user, process_name, parent_process, "
                                "command_line, file_path, old_extension, new_extension, entropy, service_name, privilege, integrity_level`. "
                                "See `docs/DATA_CARD.md`.")
                with gr.Column(scale=2):
                    load_md = gr.Markdown()
            rank_plot = gr.Plot(label="Risk ranking")
            rank_df = gr.Dataframe(label="Hosts ranked by ransomware likelihood", interactive=False, wrap=True)

        # ---------------- Tab 2 ----------------
        with gr.Tab("2 · Investigate host (agent)"):
            with gr.Row():
                host_dd = gr.Dropdown(label="Host", choices=[], interactive=True, scale=2)
                mode_dd = gr.Dropdown(["ollama", "openai", "offline"], value=config.LLM_PROVIDER, label="Agent mode", scale=1,
                                      info="ollama/openai = LLM agent; offline = deterministic planner")
                model_tb = gr.Textbox(value=config.LLM_MODEL, label="Model", scale=1)
                url_tb = gr.Textbox(value=config.LLM_BASE_URL, label="LLM base URL", scale=1)
            with gr.Row():
                btn_check = gr.Button("Check LLM & load model", size="sm")
                btn_run = gr.Button("🔎 Run agent investigation", variant="primary")
            gr.Markdown(f"<sub>LLM mode: click *Check LLM & load model* first (the first load takes 30-90 s). "
                        f"An investigation stops after {config.AGENT_TIME_BUDGET_S:.0f} s and finishes with the deterministic planner. "
                        "For a fast demo use `qwen2.5:3b` or *offline* mode (about 1 s).</sub>")
            llm_md = gr.Markdown()
            report_md = gr.Markdown()
            timeline_plot = gr.Plot(label="Behaviour timeline and cumulative risk")
            with gr.Row():
                contrib_plot = gr.Plot(label="Indicator contributions")
                evidence_df = gr.Dataframe(label="Evidence (from tools)", interactive=False, wrap=True)
            mitre_df = gr.Dataframe(label="MITRE ATT&CK mapping", interactive=False, wrap=True)
            actions_df = gr.Dataframe(label="Recommended containment (pending human approval → tab 3)", interactive=False, wrap=True)
            with gr.Accordion("Playbook passages retrieved (RAG citations)", open=False):
                cites_md = gr.Markdown()
            with gr.Accordion("Agent trace — every tool call the agent made", open=True):
                trace_df = gr.Dataframe(interactive=False, wrap=True)
            with gr.Accordion("Structured JSON incident report", open=False):
                json_code = gr.Code(language="json")

        # ---------------- Tab 3 ----------------
        with gr.Tab("3 · Human approval"):
            appr_md = gr.Markdown("_Run an investigation first._")
            actions_cb = gr.CheckboxGroup(label="Proposed actions (⚠️ = sensitive: affects users/systems)", choices=[])
            with gr.Row():
                analyst_tb = gr.Textbox(label="Analyst name (required)")
                just_tb = gr.Textbox(label="Justification (required for sensitive actions)", lines=2)
            with gr.Row():
                btn_approve = gr.Button("✅ Approve selected (simulate tickets)", variant="primary")
                btn_reject = gr.Button("✖ Reject all")
            decision_md = gr.Markdown()
            audit_df = gr.Dataframe(label="Audit log (newest first)", interactive=False, wrap=True, value=H.audit_table())

        # ---------------- Tab 4 ----------------
        with gr.Tab("4 · Evaluation"):
            btn_eval = gr.Button("Refresh results (run `python scripts/evaluate.py` to recompute)", size="sm")
            with gr.Row():
                f1 = gr.Image(label="Rules confusion matrix", type="filepath")
                f2 = gr.Image(label="ML confusion matrix", type="filepath")
                f5 = gr.Image(label="Early-warning lead time", type="filepath")
            with gr.Row():
                f3 = gr.Image(label="Scores by scenario", type="filepath")
                f4 = gr.Image(label="Threshold sweep", type="filepath")
            eval_md = gr.Markdown()

        # ---------------- Tab 5 ----------------
        with gr.Tab("5 · System & monitoring"):
            btn_sys = gr.Button("Refresh", size="sm")
            sys_md = gr.Markdown()
            metrics_df = gr.Dataframe(label="Latency / error metrics (this session)", interactive=False)
            logs_df = gr.Dataframe(label="Recent events (logs/rewa_events.jsonl)", interactive=False, wrap=True)

        with gr.Tab("About & safety"):
            gr.Markdown(H.ABOUT_MD)

        # ---------------- wiring ----------------
        fleet_out = [load_md, rank_df, rank_plot, host_dd]
        btn_demo.click(lambda: _fleet(H.load_demo()), outputs=fleet_out)
        btn_upload.click(lambda p: _fleet(H.load_upload(p)), inputs=upload, outputs=fleet_out)
        btn_check.click(H.check_llm, inputs=[mode_dd, model_tb, url_tb], outputs=llm_md)
        btn_run.click(_investigate, inputs=[host_dd, mode_dd, model_tb, url_tb],
                      outputs=[report_md, timeline_plot, contrib_plot, evidence_df, mitre_df, actions_df, cites_md, trace_df, json_code,
                               rid_state, actions_cb, appr_md])
        btn_approve.click(lambda r, s, a, j: H.decide(r, s, a, j, True), inputs=[rid_state, actions_cb, analyst_tb, just_tb],
                          outputs=[decision_md, audit_df, rid_state])
        btn_reject.click(lambda r, s, a, j: H.decide(r, s, a, j, False), inputs=[rid_state, actions_cb, analyst_tb, just_tb],
                         outputs=[decision_md, audit_df, rid_state])
        btn_eval.click(H.evaluation_view, outputs=[eval_md, f1, f2, f3, f4, f5])
        btn_sys.click(H.system_view, outputs=[sys_md, metrics_df, logs_df])
        demo.load(lambda: _fleet(H.load_demo()), outputs=fleet_out)
        demo.load(H.evaluation_view, outputs=[eval_md, f1, f2, f3, f4, f5])
    return demo


if __name__ == "__main__":
    build().queue(default_concurrency_limit=2).launch(
        server_name=os.getenv("GRADIO_SERVER_NAME", "127.0.0.1"), server_port=int(os.getenv("GRADIO_SERVER_PORT", "7860")),
        show_error=True)
