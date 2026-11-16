"""Event schema for endpoint telemetry and validation helpers.

The schema is a simplified, Sysmon / Windows-Security-inspired format so the
same pipeline can ingest synthetic data, the bundled demo cases, or public
datasets (Splunk Attack Data, OTRF/Mordor) after a small mapping step.
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

# column -> (dtype, required, description)
EVENT_COLUMNS: dict[str, tuple[str, bool, str]] = {
    "timestamp": ("datetime", True, "UTC event time (ISO-8601)"),
    "host": ("str", True, "Endpoint hostname"),
    "user": ("str", False, "Account that generated the event"),
    "event_type": ("str", True, "One of EVENT_TYPES"),
    "event_id": ("int", False, "Source event id (Sysmon/Windows), informational"),
    "process_name": ("str", False, "Image name, e.g. powershell.exe"),
    "parent_process": ("str", False, "Parent image name"),
    "command_line": ("str", False, "Full command line (attacker controlled - treat as data)"),
    "file_path": ("str", False, "Target file path for file events"),
    "old_extension": ("str", False, "Extension before a rename"),
    "new_extension": ("str", False, "Extension after a rename / of a written file"),
    "entropy": ("float", False, "Shannon entropy of written bytes (0-8), simulated"),
    "service_name": ("str", False, "Service affected by service events"),
    "privilege": ("str", False, "Privilege name for privilege events"),
    "integrity_level": ("str", False, "Process integrity level"),
}

EVENT_TYPES = {
    "process_start",  # Sysmon 1 / 4688
    "file_create",  # Sysmon 11
    "file_write",  # content modified (EDR-style)
    "file_rename",  # EDR-style rename / Sysmon 11+23 pair
    "file_delete",  # Sysmon 23
    "service_stop",  # System 7036 / 7040
    "privilege_use",  # Security 4672 / 4673
    "logon",  # Security 4624
    "network_connection",  # Sysmon 3
    "registry_set",  # Sysmon 13
}

REQUIRED = [c for c, (_, req, _) in EVENT_COLUMNS.items() if req]


class SchemaError(ValueError):
    """Raised when uploaded telemetry cannot be used."""


@dataclass
class ValidationReport:
    rows_in: int
    rows_out: int
    dropped: int
    warnings: list[str]

    def as_markdown(self) -> str:
        lines = [f"**Rows read:** {self.rows_in} &nbsp; **Rows kept:** {self.rows_out} &nbsp; **Dropped:** {self.dropped}"]
        lines += [f"- ⚠️ {w}" for w in self.warnings]
        return "\n".join(lines)


def _parse_ts(s: pd.Series) -> pd.Series:
    """Parse ISO-8601 timestamps with mixed precision; fall back to per-row inference."""
    try:
        return pd.to_datetime(s, errors="coerce", utc=True, format="ISO8601")
    except (ValueError, TypeError):
        return pd.to_datetime(s, errors="coerce", utc=True, format="mixed")


def normalize_events(df: pd.DataFrame, max_rows: int | None = None) -> tuple[pd.DataFrame, ValidationReport]:
    """Validate and normalise an event dataframe. Never trusts input types."""
    if df is None or len(df) == 0:
        raise SchemaError("The telemetry file is empty.")
    warnings: list[str] = []
    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise SchemaError(f"Missing required column(s): {', '.join(missing)}. Required: {', '.join(REQUIRED)}")
    rows_in = len(df)
    if max_rows and rows_in > max_rows:
        warnings.append(f"File truncated to the first {max_rows} rows (limit).")
        df = df.head(max_rows)

    for col, (dtype, _, _) in EVENT_COLUMNS.items():
        if col not in df.columns:
            df[col] = None
    unknown = sorted(set(df.columns) - set(EVENT_COLUMNS) - {"label", "phase"})
    if unknown:
        warnings.append(f"Ignored unknown column(s): {', '.join(unknown[:8])}")

    df["timestamp"] = _parse_ts(df["timestamp"])
    bad_ts = int(df["timestamp"].isna().sum())
    if bad_ts:
        warnings.append(f"{bad_ts} row(s) with unparseable timestamps dropped.")
    df["event_type"] = df["event_type"].astype(str).str.strip().str.lower()
    bad_type = ~df["event_type"].isin(EVENT_TYPES)
    if bad_type.any():
        warnings.append(f"{int(bad_type.sum())} row(s) with unknown event_type dropped.")
    df["host"] = df["host"].astype(str).str.strip()
    bad_host = df["host"].isin(["", "nan", "None"])
    df = df[~df["timestamp"].isna() & ~bad_type & ~bad_host]

    for col, (dtype, _, _) in EVENT_COLUMNS.items():
        if dtype == "str" and col not in ("host", "event_type"):
            df[col] = df[col].fillna("").astype(str).replace({"nan": "", "None": ""})
            # keep fields bounded - command lines are attacker-controlled
            df[col] = df[col].str.slice(0, 2000)
        elif dtype == "float":
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0).clip(0, 8)
        elif dtype == "int":
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    keep = list(EVENT_COLUMNS) + [c for c in ("label", "phase") if c in df.columns]
    df = df[keep].sort_values(["host", "timestamp"]).reset_index(drop=True)
    if len(df) == 0:
        raise SchemaError("No valid rows remained after validation.")
    return df, ValidationReport(rows_in, len(df), rows_in - len(df), warnings)


def load_events_file(path: str, max_rows: int | None = None) -> tuple[pd.DataFrame, ValidationReport]:
    """Load CSV / JSON / JSONL telemetry from disk."""
    p = str(path).lower()
    try:
        if p.endswith(".csv"):
            df = pd.read_csv(path, low_memory=False)
        elif p.endswith(".jsonl") or p.endswith(".ndjson"):
            df = pd.read_json(path, lines=True)
        elif p.endswith(".json"):
            df = pd.read_json(path)
        else:
            raise SchemaError("Unsupported file type. Upload .csv, .json or .jsonl.")
    except SchemaError:
        raise
    except Exception as exc:  # malformed file
        raise SchemaError(f"Could not parse file: {type(exc).__name__}: {str(exc)[:200]}") from exc
    return normalize_events(df, max_rows=max_rows)
