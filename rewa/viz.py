"""Matplotlib figures for the dashboard and the report (no extra deps)."""
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from . import config  # noqa: E402

LEVEL_COLORS = {"CRITICAL": "#b42318", "HIGH": "#e0612b", "MEDIUM": "#d4a017", "LOW": "#3b7d4f"}
KIND_STYLE = {  # flag column -> (label, color, y)
    "f_discovery": ("Discovery", "#6b7280", 1), "f_office_shell": ("Office→shell", "#7c3aed", 2), "f_enc_ps": ("Encoded PS", "#7c3aed", 2),
    "f_temp_exec": ("Temp exec", "#7c3aed", 2), "f_priv": ("Privilege", "#2563eb", 3), "f_elev_temp": ("Elevated temp", "#2563eb", 3),
    "f_svc_tamper": ("Service tamper", "#0891b2", 4), "f_backup_strong": ("Backup deletion", "#dc2626", 5),
    "f_backup_weak": ("Snapshot rotation", "#f59e0b", 5), "f_recovery": ("Recovery inhibit", "#dc2626", 5),
    "f_high_entropy": ("High-entropy write", "#991b1b", 6), "f_rename_unusual": ("Mass rename", "#991b1b", 6), "f_note": ("Ransom note", "#111827", 7),
}
LANES = {1: "Discovery", 2: "Execution", 3: "Privilege", 4: "Defense evasion", 5: "Inhibit recovery", 6: "Encryption", 7: "Ransom note"}


def _style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis="x", alpha=0.25)


def ranking_chart(table: pd.DataFrame, top: int = 15):
    t = table.head(top).iloc[::-1]
    fig, ax = plt.subplots(figsize=(8, max(3, 0.38 * len(t) + 1)))
    ax.barh(t["host"], t["risk_score"], color=[LEVEL_COLORS.get(l, "#999") for l in t["risk_level"]])
    ax.axvline(config.ALERT_THRESHOLD, ls="--", color="#444", lw=1)
    ax.text(config.ALERT_THRESHOLD + 1, -0.6, f"alert threshold {config.ALERT_THRESHOLD:g}", fontsize=8, color="#444")
    thr = config.ALERT_THRESHOLD
    for y, (s, l) in enumerate(zip(t["risk_score"], t["risk_level"])):
        tx = thr + 1.5 if thr - 12 < s < thr else s + 1  # keep labels clear of the threshold line
        ax.text(tx, y, f"{s:.1f} {l}" if s < 100 else f"100 {l}", va="center", fontsize=8)
    ax.set_xlim(0, 112)
    ax.set_xlabel("Ransomware likelihood score (0-100)")
    ax.set_title("Host risk ranking", loc="left", fontsize=11, fontweight="bold")
    _style(ax)
    fig.tight_layout()
    return fig


def host_timeline_chart(annotated: pd.DataFrame, risk_tl: pd.DataFrame | None, host: str, first_alert: str = "",
                        encryption_start: str | None = None):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 5.6), sharex=True, gridspec_kw={"height_ratios": [1.3, 1]})
    for col, (label, color, y) in KIND_STYLE.items():
        d = annotated[annotated[col]]
        if len(d):
            ax1.scatter(d["ts"], [y] * len(d), s=14, color=color, alpha=0.75, label=f"{label} ({len(d)})")
    ax1.set_yticks(list(LANES), list(LANES.values()), fontsize=8)
    ax1.set_ylim(0.4, 7.6)
    ax1.set_title(f"{host} - suspicious behaviour timeline", loc="left", fontsize=11, fontweight="bold")
    if ax1.get_legend_handles_labels()[0]:
        ax1.legend(fontsize=7, ncol=3, loc="upper left", frameon=False)
    _style(ax1)
    if risk_tl is not None and len(risk_tl):
        ax2.step(risk_tl["ts"], risk_tl["risk_score"], where="post", color="#b42318", lw=2)
        ax2.fill_between(risk_tl["ts"], risk_tl["risk_score"], step="post", color="#b42318", alpha=0.08)
    ax2.axhline(config.ALERT_THRESHOLD, ls="--", color="#444", lw=1)
    for mark, color, txt, ty in ((first_alert, "#e0612b", "first alert", 103), (encryption_start, "#111827", "encryption starts", 8)):
        if mark:
            ts = pd.to_datetime(mark.replace(" UTC", ""), utc=True)
            for ax in (ax1, ax2):
                ax.axvline(ts, color=color, lw=1.2, ls=":")
            ax2.text(ts, ty, f" {txt}", color=color, fontsize=8)
    ax2.set_ylim(0, 110)
    ax2.set_ylabel("Cumulative risk")
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax2.set_xlabel("Time (UTC)")
    _style(ax2)
    fig.tight_layout()
    return fig


def contribution_chart(indicators: list[dict]):
    d = [i for i in indicators]
    fig, ax = plt.subplots(figsize=(6, 3.2))
    names = [f"{i['id']} {i['name'][:28]}" for i in d][::-1]
    vals = [i["contribution"] for i in d][::-1]
    ax.barh(names, vals, color=["#b42318" if v >= 0.3 else "#e0612b" if v > 0 else "#d1d5db" for v in vals])
    ax.set_xlim(0, 0.7)
    ax.set_xlabel("Contribution (weight × severity)")
    ax.tick_params(axis="y", labelsize=8)
    ax.set_title("Indicator contributions", loc="left", fontsize=10, fontweight="bold")
    _style(ax)
    fig.tight_layout()
    return fig


def confusion_chart(tp, fp, fn, tn, title="Confusion matrix"):
    import numpy as np

    m = np.array([[tp, fn], [fp, tn]])
    fig, ax = plt.subplots(figsize=(3.6, 3.2))
    ax.imshow(m, cmap="Reds", vmin=0)
    for (i, j), v in np.ndenumerate(m):
        ax.text(j, i, str(v), ha="center", va="center", fontsize=14, color="white" if v > m.max() / 2 else "black")
    ax.set_xticks([0, 1], ["Alert", "No alert"])
    ax.set_yticks([0, 1], ["Ransomware", "Benign"])
    ax.set_title(title, fontsize=10, fontweight="bold")
    fig.tight_layout()
    return fig
