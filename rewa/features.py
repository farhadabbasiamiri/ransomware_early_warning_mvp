"""Behavioural feature extraction: 8 ransomware early-warning indicators.

Two stages so time-series scoring stays cheap:
  1. annotate(events)  -> adds boolean/numeric flag columns once per event
  2. host_features(annotated_host_df) -> numeric features + per-indicator
     severity (0..1) and human-readable evidence.
"""
from __future__ import annotations

import re
import warnings

warnings.filterwarnings("ignore", message="This pattern is interpreted as a regular expression")
from dataclasses import dataclass, field

import pandas as pd

COMMON_EXT = {
    "txt", "csv", "log", "xml", "html", "htm", "sql", "json", "md", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "pdf",
    "jpg", "jpeg", "png", "gif", "bmp", "mp4", "mp3", "wav", "zip", "7z", "rar", "gz", "tar", "exe", "dll", "pdb", "obj",
    "lib", "msi", "ps1", "bat", "cmd", "py", "js", "ts", "java", "c", "cpp", "h", "cs", "ini", "cfg", "yaml", "yml",
    "bak", "tmp", "lnk", "url", "eml", "msg", "pst", "ost", "odt", "ods", "rtf", "svg", "ico", "db", "sqlite",
}
ARCHIVE_EXT = {"zip", "7z", "rar", "gz", "tar", "bz2", "xz", "cab", "iso", "vhd", "vhdx"}
USER_PATH = re.compile(r"\\users\\[^\\]+\\", re.I)
NOTE_RE = re.compile(r"(decrypt|restore|recover|ransom|unlock|how[_\- ]?to|read[_\- ]?me[_\- ]?(now|first|for|to)|!!)", re.I)
NOTE_EXT = {"txt", "html", "htm", "hta", "rtf", "url"}
BACKUP_DEL_STRONG = re.compile(
    r"(vssadmin(\.exe)?\s+delete\s+shadows\s+/all|vssadmin(\.exe)?\s+resize\s+shadowstorage|wmic(\.exe)?\s+shadowcopy\s+delete|"
    r"win32_shadowcopy.*delete|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup))", re.I)
BACKUP_DEL_ANY = re.compile(r"(vssadmin(\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|win32_shadowcopy.*delete|wbadmin(\.exe)?\s+delete)", re.I)
RECOVERY_RE = re.compile(r"(bcdedit(\.exe)?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|reagentc(\.exe)?\s+/disable)", re.I)
SEC_SVC_RE = re.compile(r"(windefend|sense|mpssvc|wscsvc|sophos|mcafee|symantec|crowdstrike|csfalcon|sentinel|veeam|backup|"
                        r"vss\b|\"vss\"|sql|exchange|wbengine|sdrsvc|acronis)", re.I)
SVC_CMD_RE = re.compile(r"(net(\.exe)?\s+stop|sc(\.exe)?\s+(stop|config)|taskkill|stop-service|set-service)", re.I)
SENSITIVE_PRIVS = {"sedebugprivilege", "setakeownershipprivilege", "seimpersonateprivilege", "seloaddriverprivilege", "setcbprivilege",
                   "sebackupprivilege", "serestoreprivilege"}
SYSTEM_ACCOUNTS = {"system", "local service", "network service", "nt authority\\system"}
ADMIN_ACCOUNT_RE = re.compile(r"^(it-admin|admin|.*-adm|adm-.*)$", re.I)  # documented allowlist assumption
ENC_PS_RE = re.compile(r"powershell(\.exe)?.*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.I)
OFFICE = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "mspub.exe", "onenote.exe"}
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
MGMT_PARENTS = {"ccmexec.exe", "intunemanagementextension.exe", "senseir.exe", "ltsvc.exe"}
TEMP_EXEC_RE = re.compile(r"\\(appdata\\local\\temp|temp|users\\public|programdata)\\[^\\]+\.(exe|dll|scr)", re.I)
DISCOVERY_RE = re.compile(r"(whoami\s+/all|net\s+view|nltest|net\s+group|net\s+share|ipconfig\s+/all|systeminfo|arp\s+-a|adfind)", re.I)

INDICATORS = {
    "I1": "Mass file rename to unusual extension",
    "I2": "High-entropy overwrite of user files",
    "I3": "Ransom-note-like file creation",
    "I4": "Shadow copy / backup deletion",
    "I5": "Boot recovery inhibition",
    "I6": "Security / backup service tampering",
    "I7": "Suspicious privilege escalation",
    "I8": "Suspicious execution chain & discovery",
}
# Week 6 improvement switch (kept for the before/after ablation in scripts/evaluate.py)
CORROBORATE_IMPACT = True

WEIGHTS = {"I1": 0.60, "I2": 0.50, "I3": 0.65, "I4": 0.60, "I5": 0.45, "I6": 0.35, "I7": 0.25, "I8": 0.35}

FEATURE_NAMES = [
    "rename_peak_per_min", "rename_10min_max", "entropy_10min_max", "note_dirs", "backup_del_strong", "backup_del_weak",
    "recovery_inhibit", "sec_services_stopped", "sensitive_priv_events", "elevated_temp_exec", "office_to_shell",
    "encoded_ps", "temp_exec", "discovery_cmds", "impact_corroborated",
]


def _lower(s: pd.Series) -> pd.Series:
    return s.fillna("").astype(str).str.lower()


def annotate(df: pd.DataFrame) -> pd.DataFrame:
    """Add per-event flag columns used by the indicators (vectorised)."""
    d = df.copy()
    et = d["event_type"]
    cmd = d["command_line"].fillna("").astype(str)
    proc, parent, user = _lower(d["process_name"]), _lower(d["parent_process"]), _lower(d["user"])
    newx, oldx = _lower(d["new_extension"]), _lower(d["old_extension"])
    path = d["file_path"].fillna("").astype(str)
    is_sys = user.isin(SYSTEM_ACCOUNTS)

    d["f_rename_unusual"] = (et == "file_rename") & (newx != oldx) & ~newx.isin(COMMON_EXT) & (newx != "")
    d["f_high_entropy"] = (et == "file_write") & (d["entropy"].astype(float) >= 7.9) & ~newx.isin(ARCHIVE_EXT) & path.str.contains(USER_PATH)
    fname = path.str.split("\\").str[-1]
    d["f_note"] = (et == "file_create") & fname.str.contains(NOTE_RE) & newx.isin(NOTE_EXT)
    d["f_dir"] = path.str.rsplit("\\", n=1).str[0]
    ps = et == "process_start"
    backup_parent = parent.str.contains("backup|veeam|acronis|wbengine", regex=True)
    strong = ps & cmd.str.contains(BACKUP_DEL_STRONG)
    anydel = ps & cmd.str.contains(BACKUP_DEL_ANY)
    d["f_backup_strong"] = strong | (anydel & ~(is_sys & backup_parent))
    d["f_backup_weak"] = anydel & ~d["f_backup_strong"]
    d["f_recovery"] = ps & cmd.str.contains(RECOVERY_RE)
    # Service tampering: user-initiated stop/disable commands that target security/backup/db services
    d["f_svc_tamper"] = ps & cmd.str.contains(SVC_CMD_RE) & cmd.str.contains(SEC_SVC_RE)
    d["f_svc_target"] = cmd.str.extract(r"(?:stop|config)\s+\"?([A-Za-z0-9_\-]+)", flags=re.I)[0].fillna("")
    priv = _lower(d["privilege"])
    d["f_priv"] = (et == "privilege_use") & priv.isin(SENSITIVE_PRIVS) & ~is_sys & ~user.str.match(ADMIN_ACCOUNT_RE)
    d["f_elev_temp"] = ps & _lower(d["integrity_level"]).isin(["high", "system"]) & cmd.str.contains(TEMP_EXEC_RE) & ~is_sys
    d["f_office_shell"] = ps & parent.isin(OFFICE) & proc.isin(SHELLS)
    d["f_enc_ps"] = ps & cmd.str.contains(ENC_PS_RE) & ~(is_sys & parent.isin(MGMT_PARENTS))
    d["f_enc_ps_mgmt"] = ps & cmd.str.contains(ENC_PS_RE) & is_sys & parent.isin(MGMT_PARENTS)
    d["f_temp_exec"] = ps & cmd.str.contains(TEMP_EXEC_RE)
    d["f_discovery"] = ps & cmd.str.contains(DISCOVERY_RE)
    d["ts"] = pd.to_datetime(d["timestamp"], utc=True)
    return d


def _max_in_window(ts: pd.Series, seconds: int) -> int:
    """Max number of events within any sliding window of `seconds`."""
    if len(ts) == 0:
        return 0
    s = ts.sort_values()
    v = (s - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds().to_numpy()  # unit-safe (ns/us)
    j, best = 0, 0
    for i in range(len(v)):
        while v[i] - v[j] > seconds:
            j += 1
        best = max(best, i - j + 1)
    return best


@dataclass
class IndicatorResult:
    id: str
    name: str
    severity: float
    weight: float
    evidence: list[str] = field(default_factory=list)
    first_seen: str = ""
    count: int = 0

    @property
    def contribution(self) -> float:
        return round(self.weight * self.severity, 4)

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "severity": round(self.severity, 3), "weight": self.weight,
                "contribution": self.contribution, "count": self.count, "first_seen": self.first_seen,
                "evidence": self.evidence}


def _first(d: pd.DataFrame) -> str:
    return d["ts"].min().strftime("%Y-%m-%d %H:%M:%S UTC") if len(d) else ""


def _examples(d: pd.DataFrame, col: str, n: int = 2) -> list[str]:
    vals = [str(x)[:160] for x in d[col].dropna().unique()[:n] if str(x)]
    return vals


def host_features(a: pd.DataFrame) -> tuple[dict, list[IndicatorResult]]:
    """Compute numeric features and indicator results for ONE host (annotated)."""
    f: dict[str, float] = {}
    res: list[IndicatorResult] = []

    # I1 mass rename
    rn = a[a["f_rename_unusual"]]
    f["rename_peak_per_min"] = _max_in_window(rn["ts"], 60)
    f["rename_10min_max"] = _max_in_window(rn["ts"], 600)
    sev = 0.0
    if f["rename_peak_per_min"] >= 5:
        sev = min(1.0, 0.4 + (f["rename_peak_per_min"] - 5) / 40)
    if f["rename_10min_max"] >= 10:
        sev = max(sev, min(1.0, 0.35 + f["rename_10min_max"] / 100))
    ev = []
    if len(rn):
        top = rn["new_extension"].value_counts()
        ev.append(f"{len(rn)} files renamed to unusual extension(s) {', '.join('.' + x for x in top.index[:3])}; "
                  f"peak {int(f['rename_peak_per_min'])}/min, max {int(f['rename_10min_max'])} in 10 min")
        ev += [f"e.g. {p}" for p in _examples(rn, "file_path", 1)]
    res.append(IndicatorResult("I1", INDICATORS["I1"], sev, WEIGHTS["I1"], ev, _first(rn), len(rn)))

    # I2 high entropy overwrite
    he = a[a["f_high_entropy"]]
    f["entropy_10min_max"] = _max_in_window(he.drop_duplicates("file_path")["ts"], 600)
    n = f["entropy_10min_max"]
    sev = 0.0 if n < 5 else min(1.0, 0.4 + n / 60)
    ev = [f"{he['file_path'].nunique()} user files overwritten with near-random content (entropy ≥ 7.9); max {int(n)} in 10 min "
          f"by {', '.join(he['process_name'].value_counts().index[:2])}"] if len(he) else []
    res.append(IndicatorResult("I2", INDICATORS["I2"], sev, WEIGHTS["I2"], ev, _first(he), int(he["file_path"].nunique())))

    # I3 ransom notes
    nt = a[a["f_note"]]
    f["note_dirs"] = int(nt["f_dir"].nunique())
    sev = 0.0 if f["note_dirs"] == 0 else (0.5 if f["note_dirs"] < 3 else 1.0)
    ev = [f"Note-like file(s) {', '.join(nt['file_path'].str.split(chr(92)).str[-1].unique()[:2])} created in {f['note_dirs']} folder(s)"] if len(nt) else []
    res.append(IndicatorResult("I3", INDICATORS["I3"], sev, WEIGHTS["I3"], ev, _first(nt), len(nt)))

    # I4 backup deletion
    bs, bw = a[a["f_backup_strong"]], a[a["f_backup_weak"]]
    f["backup_del_strong"], f["backup_del_weak"] = len(bs), len(bw)
    sev = 1.0 if len(bs) else (0.3 if len(bw) else 0.0)
    ev = [f"`{c}` (parent {p})" for c, p in bs[["command_line", "parent_process"]].drop_duplicates().head(3).itertuples(index=False)]
    if len(bw) and not len(bs):
        ev.append(f"{len(bw)} targeted shadow deletion(s) by {', '.join(bw['parent_process'].unique()[:2])} as SYSTEM (looks like backup rotation)")
    res.append(IndicatorResult("I4", INDICATORS["I4"], sev, WEIGHTS["I4"], ev, _first(bs if len(bs) else bw), len(bs) + len(bw)))

    # I5 recovery inhibition
    rc = a[a["f_recovery"]]
    f["recovery_inhibit"] = len(rc)
    ev = [f"`{c}`" for c in rc["command_line"].unique()[:3]]
    res.append(IndicatorResult("I5", INDICATORS["I5"], 1.0 if len(rc) else 0.0, WEIGHTS["I5"], ev, _first(rc), len(rc)))

    # I6 service tampering
    st = a[a["f_svc_tamper"]]
    targets = sorted(set(t for t in st["f_svc_target"] if t))
    f["sec_services_stopped"] = len(targets)
    k = len(targets)
    sev = 0.0 if k == 0 else (0.4 if k == 1 else (0.7 if k == 2 else 1.0))
    ev = [f"Stop/disable commands against {k} security/backup/database service(s): {', '.join(targets[:6])}"] if k else []
    res.append(IndicatorResult("I6", INDICATORS["I6"], sev, WEIGHTS["I6"], ev, _first(st), len(st)))

    # I7 privilege escalation
    pv, el = a[a["f_priv"]], a[a["f_elev_temp"]]
    f["sensitive_priv_events"], f["elevated_temp_exec"] = len(pv), len(el)
    kp = pv["privilege"].nunique()
    sev = 0.0 if kp == 0 else (0.4 if kp == 1 else 0.7)
    if len(el):
        sev = min(1.0, max(sev, 0.4) + 0.3)
    ev = []
    if len(pv):
        ev.append(f"{', '.join(pv['privilege'].unique()[:3])} used by {', '.join(pv['process_name'].unique()[:2])} (user {pv['user'].iloc[0]})")
    if len(el):
        ev.append(f"{len(el)} process(es) from a user-writable path running at High/System integrity")
    res.append(IndicatorResult("I7", INDICATORS["I7"], sev, WEIGHTS["I7"], ev, _first(pd.concat([pv, el])), len(pv) + len(el)))

    # I8 suspicious execution & discovery
    osh, enc, tmp, dis = a[a["f_office_shell"]], a[a["f_enc_ps"]], a[a["f_temp_exec"]], a[a["f_discovery"]]
    f["office_to_shell"], f["encoded_ps"], f["temp_exec"] = len(osh), len(enc), len(tmp)
    f["discovery_cmds"] = _max_in_window(dis["ts"], 900)
    sev = 0.5 * bool(len(osh)) + 0.35 * bool(len(enc)) + 0.3 * bool(len(tmp)) + 0.3 * (f["discovery_cmds"] >= 3)
    sev += 0.1 * bool(a["f_enc_ps_mgmt"].any())
    sev = min(1.0, sev)
    ev = []
    if len(osh):
        ev.append(f"Office app spawned a shell: {osh['parent_process'].iloc[0]} → {osh['process_name'].iloc[0]}")
    if len(enc):
        ev.append(f"Encoded PowerShell command line ({len(enc)}x)")
    if len(tmp):
        ev.append(f"Execution from user-writable path: {', '.join(tmp['process_name'].unique()[:2])}")
    if f["discovery_cmds"] >= 3:
        ev.append(f"Discovery burst: {int(f['discovery_cmds'])} recon commands in 15 min: "
                  f"{', '.join(c[:40] for c in dis['command_line'].str.replace('cmd.exe /c ', '', regex=False).unique()[:5])}")
    if a["f_enc_ps_mgmt"].any() and not len(enc):
        ev.append("Encoded PowerShell only from a management agent running as SYSTEM (likely benign)")
    first_df = pd.concat([osh, enc, tmp, dis])
    res.append(IndicatorResult("I8", INDICATORS["I8"], sev, WEIGHTS["I8"], ev, _first(first_df), len(first_df)))

    # ---- Week 6: corroboration of the impact signals I1/I2 ----
    # An encryptor renames AND overwrites files with the same process, drops ransom notes, or is
    # the same process seen in earlier suspicious behaviour (Temp execution, privilege use, launching
    # backup-deletion / service-stop / discovery commands). Benign sync clients, archivers and
    # encrypted-vault apps usually produce only ONE of these signals, so an uncorroborated I1/I2
    # counts at half severity. Motivated by false positives on the TRAIN split (see EVALUATION).
    def _procs(d: pd.DataFrame, col: str = "process_name") -> set[str]:
        return set(d[col].fillna("").astype(str).str.lower()) - {""}

    rn_p, he_p = _procs(rn), _procs(he)
    precursor_cmds = a[a["f_backup_strong"] | a["f_recovery"] | a["f_svc_tamper"] | a["f_discovery"]]
    pre_p = _procs(pv) | _procs(el) | _procs(tmp) | _procs(enc) | _procs(precursor_cmds, "parent_process")
    notes = f["note_dirs"] > 0
    corroborated = {"I1": bool(rn_p & he_p) or notes or bool(rn_p & pre_p),
                    "I2": bool(he_p & rn_p) or notes or bool(he_p & pre_p)}
    for ind in res[:2]:  # I1, I2
        if ind.severity <= 0 or not CORROBORATE_IMPACT:
            continue
        procs = sorted(rn_p if ind.id == "I1" else he_p)
        if corroborated[ind.id]:
            ind.evidence.append(f"Corroborated: {', '.join(procs[:2])} also "
                                + ("renamed and encrypted files" if rn_p & he_p else
                                   "created ransom notes" if notes else "showed other suspicious behaviour"))
        else:
            ind.severity = round(ind.severity * 0.5, 4)
            ind.evidence.append(f"Not corroborated (severity halved): {', '.join(procs[:2])} shows no other ransomware "
                                "behaviour; likely a sync, backup or encryption tool - verify with the owner")
    active_impact = [i for i in res[:2] if i.severity > 0]
    f["impact_corroborated"] = float(any(corroborated[i.id] for i in active_impact)) if active_impact else 0.0
    if not CORROBORATE_IMPACT:
        f["impact_corroborated"] = 0.0

    return {k: float(f[k]) for k in FEATURE_NAMES}, res
