import pandas as pd
import pytest

from conftest import ev
from rewa.schema import SchemaError, load_events_file, normalize_events


def test_mixed_iso_timestamps_are_all_parsed():
    rows = [ev(timestamp="2026-10-05T10:00:00+00:00"), ev(timestamp="2026-10-05T10:00:01.123456+00:00")]
    df, rep = normalize_events(pd.DataFrame(rows))
    assert len(df) == 2 and rep.dropped == 0


def test_missing_required_column():
    with pytest.raises(SchemaError, match="Missing required"):
        normalize_events(pd.DataFrame([{"host": "H1", "event_type": "logon"}]))


def test_bad_rows_dropped_with_warning():
    rows = [ev(), ev(timestamp="garbage"), ev(event_type="not_a_type"), ev(host="")]
    df, rep = normalize_events(pd.DataFrame(rows))
    assert len(df) == 1 and rep.dropped == 3 and rep.warnings


def test_entropy_clipped_and_strings_bounded():
    df, _ = normalize_events(pd.DataFrame([ev(entropy=99, command_line="x" * 5000)]))
    assert df.entropy.iloc[0] == 8 and len(df.command_line.iloc[0]) == 2000


def test_empty_and_unsupported_files(tmp_path):
    (tmp_path / "e.csv").write_text("")
    (tmp_path / "x.exe").write_text("MZ")
    for f in ("e.csv", "x.exe"):
        with pytest.raises(SchemaError):
            load_events_file(str(tmp_path / f))


def test_jsonl_supported(tmp_path):
    p = tmp_path / "a.jsonl"
    pd.DataFrame([ev(), ev()]).to_json(p, orient="records", lines=True)
    df, _ = load_events_file(str(p))
    assert len(df) == 2
