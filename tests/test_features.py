from datetime import datetime, timedelta, timezone

from conftest import ev, frame
from rewa.features import annotate, host_features

T0 = datetime(2026, 10, 5, 10, tzinfo=timezone.utc)


def ts(s):
    return (T0 + timedelta(seconds=s)).isoformat()


def sev(rows, corroborate=True):
    from rewa import features

    features.CORROBORATE_IMPACT = corroborate
    try:
        _, inds = host_features(annotate(frame(rows)))
    finally:
        features.CORROBORATE_IMPACT = True
    return {i.id: i.severity for i in inds}


def test_mass_rename_unusual_extension_fires():
    rows = [ev(timestamp=ts(i), event_type="file_rename", file_path=f"C:\\Users\\a\\Documents\\f{i}.docx.lockx",
               old_extension="docx", new_extension="lockx") for i in range(40)]
    assert sev(rows, corroborate=False)["I1"] >= 0.9  # raw threshold logic (corroboration tested below)


def test_bulk_rename_same_extension_does_not_fire():
    rows = [ev(timestamp=ts(i), event_type="file_rename", old_extension="jpg", new_extension="jpg") for i in range(300)]
    assert sev(rows)["I1"] == 0


def test_build_renames_to_known_extensions_do_not_fire():
    rows = [ev(timestamp=ts(i), event_type="file_rename", old_extension="tmp", new_extension="dll") for i in range(300)]
    assert sev(rows)["I1"] == 0


def test_high_entropy_user_files_vs_archive():
    enc = [ev(timestamp=ts(i), event_type="file_write", file_path=f"C:\\Users\\a\\Documents\\r{i}.txt", new_extension="txt", entropy=7.95)
           for i in range(20)]
    arc = [ev(timestamp=ts(i), event_type="file_write", file_path="C:\\Users\\a\\Documents\\a.7z", new_extension="7z", entropy=7.99)
           for i in range(20)]
    assert sev(enc, corroborate=False)["I2"] > 0.5 and sev(arc)["I2"] == 0


def test_ransom_notes_in_three_dirs():
    rows = [ev(timestamp=ts(i), event_type="file_create", file_path=f"C:\\Users\\a\\D{i}\\HOW_TO_DECRYPT.html", new_extension="html")
            for i in range(3)]
    assert sev(rows)["I3"] == 1.0


def test_readme_md_is_not_a_ransom_note():
    assert sev([ev(event_type="file_create", file_path="C:\\src\\README.md", new_extension="md")])["I3"] == 0


def test_shadow_deletion_strong_vs_backup_rotation():
    strong = [ev(command_line="vssadmin.exe delete shadows /all /quiet", parent_process="evil.exe")]
    rot = [ev(user="SYSTEM", parent_process="BackupAgent.exe", command_line="vssadmin.exe delete shadows /shadow={abc} /quiet")]
    assert sev(strong)["I4"] == 1.0 and sev(rot)["I4"] == 0.3


def test_wmic_and_powershell_shadow_deletion():
    assert sev([ev(command_line="wmic.exe shadowcopy delete /nointeractive")])["I4"] == 1.0
    assert sev([ev(command_line="powershell -c \"Get-WmiObject Win32_ShadowCopy | % { $_.Delete() }\"")])["I4"] == 1.0


def test_bcdedit_recovery_vs_enum():
    assert sev([ev(command_line="bcdedit /set {default} recoveryenabled no")])["I5"] == 1.0
    assert sev([ev(command_line="bcdedit /enum")])["I5"] == 0


def test_service_tampering_security_vs_patching():
    sec = [ev(timestamp=ts(i), command_line=f"net stop \"{s}\"") for i, s in enumerate(["WinDefend", "VeeamBackupSvc", "SQLWriter"])]
    patch = [ev(timestamp=ts(i), command_line=f"net stop {s}") for i, s in enumerate(["wuauserv", "Spooler", "BITS"])]
    assert sev(sec)["I6"] == 1.0 and sev(patch)["I6"] == 0


def test_privilege_by_user_vs_system():
    user = [ev(event_type="privilege_use", privilege="SeDebugPrivilege", process_name="x.exe")]
    system = [ev(event_type="privilege_use", privilege="SeDebugPrivilege", user="SYSTEM")]
    assert sev(user)["I7"] > 0 and sev(system)["I7"] == 0


def test_office_spawning_encoded_powershell():
    rows = [ev(process_name="powershell.exe", parent_process="winword.exe", command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA==")]
    assert sev(rows)["I8"] >= 0.8


def test_management_agent_encoded_ps_is_low():
    rows = [ev(user="SYSTEM", process_name="powershell.exe", parent_process="CcmExec.exe",
               command_line="powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUA")]
    assert sev(rows)["I8"] <= 0.1


# ---- Week 6: impact corroboration ----
def _impact(rows):
    _, inds = host_features(annotate(frame(rows)))
    return {i.id: i for i in inds}


def _renames(proc, n=40, ext="lockx"):
    return [ev(timestamp=ts(i), event_type="file_rename", process_name=proc, file_path=f"C:\\Users\\a\\Documents\\f{i}.docx.{ext}",
               old_extension="docx", new_extension=ext) for i in range(n)]


def _writes(proc, n=20):
    return [ev(timestamp=ts(i), event_type="file_write", process_name=proc, file_path=f"C:\\Users\\a\\Documents\\r{i}.txt",
               new_extension="txt", entropy=7.95) for i in range(n)]


def test_sync_client_renames_alone_are_halved():
    r = _impact(_renames("SyncClient.exe", ext="sync-conflict"))["I1"]
    assert 0 < r.severity <= 0.5 and "Not corroborated" in r.evidence[-1]


def test_vault_writes_alone_are_halved():
    r = _impact(_writes("VaultApp.exe"))["I2"]
    assert 0 < r.severity <= 0.5 and "Not corroborated" in r.evidence[-1]


def test_same_process_rename_and_encrypt_is_full_severity():
    res = _impact(_renames("x.exe") + _writes("x.exe"))
    assert res["I1"].severity >= 0.9 and res["I2"].severity > 0.5 and "Corroborated" in res["I1"].evidence[-1]


def test_impact_process_seen_in_precursors_is_corroborated():
    pre = [ev(process_name="evil.exe", command_line="\"C:\\Users\\a\\AppData\\Local\\Temp\\evil.exe\"")]
    res = _impact(pre + _writes("evil.exe"))
    assert res["I2"].severity > 0.5


def test_ablation_switch_restores_old_behaviour():
    from rewa import features

    features.CORROBORATE_IMPACT = False
    try:
        assert _impact(_renames("SyncClient.exe", ext="sync-conflict"))["I1"].severity >= 0.9
    finally:
        features.CORROBORATE_IMPACT = True
