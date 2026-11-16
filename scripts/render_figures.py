"""Render real backend outputs (same figures the dashboard shows) for docs/report."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd  # noqa: E402

from rewa import config, viz  # noqa: E402
from rewa.service import EarlyWarningService, report_json  # noqa: E402

out = config.ROOT_DIR / "docs" / "figures"
out.mkdir(parents=True, exist_ok=True)
s = EarlyWarningService()
s.load_demo()
lab = pd.read_csv(config.DEMO_DIR / "labels.csv")
r = s.ranking()
viz.ranking_chart(r).savefig(out / "fleet_ranking.png", dpi=150)
for sc in ["rw_full_chain", "rw_precursor_only", "benign_backup_rotation"]:
    h = lab[lab.scenario == sc].host.iloc[0]
    hs, tl = s.host_score(h)
    enc = lab[lab.host == h].encryption_start_ts.iloc[0]
    viz.host_timeline_chart(s.annotated_host(h), tl, h, hs.first_alert_ts, enc if isinstance(enc, str) and enc else None).savefig(
        out / f"timeline_{sc}.png", dpi=150)
    viz.contribution_chart([i.as_dict() for i in hs.indicators]).savefig(out / f"contrib_{sc}.png", dpi=150)
h = lab[lab.scenario == "rw_precursor_only"].host.iloc[0]
rep, _ = s.investigate(h, mode="offline")
(config.ROOT_DIR / "docs" / "sample_incident_report.json").write_text(report_json(rep))
print("ok", list(out.iterdir()))
