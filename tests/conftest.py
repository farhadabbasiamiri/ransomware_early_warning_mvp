import sys
import tempfile
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rewa import config  # noqa: E402

config.LOG_DIR = Path(tempfile.mkdtemp())  # keep test logs out of the repo


def ev(**kw):
    base = {"timestamp": "2026-10-05T10:00:00+00:00", "host": "H1", "user": "alice", "event_type": "process_start", "event_id": 1,
            "process_name": "", "parent_process": "", "command_line": "", "file_path": "", "old_extension": "", "new_extension": "",
            "entropy": 0.0, "service_name": "", "privilege": "", "integrity_level": "Medium"}
    base.update(kw)
    return base


def frame(rows):
    from rewa.schema import normalize_events

    return normalize_events(pd.DataFrame(rows))[0]


@pytest.fixture(scope="session")
def demo_service():
    from rewa.approval import ApprovalStore
    from rewa.service import EarlyWarningService

    s = EarlyWarningService(ApprovalStore(Path(tempfile.mkdtemp()) / "a.jsonl"))
    s.load_demo()
    return s


@pytest.fixture(scope="session")
def demo_labels():
    return pd.read_csv(config.DEMO_DIR / "labels.csv")
