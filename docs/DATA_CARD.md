# Data card: synthetic endpoint telemetry (REWA)

## Summary
| Item | Value |
|---|---|
| Name | REWA synthetic endpoint ransomware telemetry v1.0 |
| Type | Synthetic, event-level Windows endpoint telemetry (Sysmon / Windows Security inspired), host-level labels |
| Generator | `rewa/generator.py`, CLI `scripts/generate_data.py` (deterministic seeds) |
| Splits | **train** 120 hosts (seed 7, 40% ransomware-like, 25% of benign with gray activity) · **test** 60 hosts (seed 2026, *hard mode*: evasive variants, 45% gray; inspected during Week 6 error analysis) · **test_fresh** 60 hosts (seed 2027, hard mode; generated after all tuning and evaluated once - the headline numbers) · **demo** 12 hosts (seed 42, 50/50, includes a prompt-injection case) |
| Size | ~89k (train), ~49k (test), ~47k (test_fresh), ~10k (demo) events |
| Personal data | None. Host and user names are randomly composed (e.g. `WS-FIN-008`, `sam.smith`). |
| Malware | None. Rows *describe* behaviours; nothing is executed. The download URL in the encoded PowerShell uses TEST-NET 198.51.100.0/24. |
| License | MIT (project) |

## Why synthetic?
The course safety rules forbid real operational data and live malware. Public sets (Splunk Attack Data, OTRF/Mordor) contain
individual technique recordings but rarely complete, *labelled* host timelines that mix benign hard negatives with full ransomware
kill chains and a ground-truth encryption start time, which we need to measure **early-warning lead time**. The generator
produces exactly that, and the schema allows public data to be mapped in later (see "Using public data").

## Schema (`rewa/schema.py`)
| Column | Type | Req. | Description |
|---|---|---|---|
| timestamp | ISO-8601 UTC | ✔ | event time (mixed precision supported) |
| host | str | ✔ | endpoint hostname |
| event_type | enum | ✔ | process_start, file_create, file_write, file_rename, file_delete, service_stop, privilege_use, logon, network_connection, registry_set |
| user | str | | account |
| event_id | int | | source id (Sysmon 1/3/11/23, Security 4624/4672/4673, System 7036) |
| process_name, parent_process | str | | image names |
| command_line | str | | full command line, **attacker-controlled**, truncated to 2000 chars |
| file_path, old_extension, new_extension | str | | file events |
| entropy | float 0-8 | | Shannon entropy of written bytes (simulated) |
| service_name, privilege, integrity_level | str | | service / privilege events |

Labels (`labels.csv`): `host, scenario, is_ransomware, first_malicious_ts, encryption_start_ts, user, variant`.
Event phases (`event_labels.csv`): benign, initial_access, discovery, privilege_escalation, defense_evasion, inhibit_recovery, impact (not shown to the detector).

## Scenarios
**Ransomware-like (label 1)**
| Scenario | Behaviour | MITRE |
|---|---|---|
| rw_full_chain | Office → encoded PowerShell → dropped binary in Temp → discovery → privilege use → stop AV/backup/SQL → vssadmin/wmic + wbadmin + bcdedit → mass encryption + notes | T1204.002, T1059.001, T1027, T1083/T1135/T1482, T1134, T1562.001, T1489, T1490, T1486 |
| rw_fast_encryptor | binary from Public folder → shadow deletion → very fast encryption (150-400 files/min) | T1490, T1486 |
| rw_slow_encryptor | throttled encryption (0.6-4 files/min); test variants drop notes, precursors, backup deletion, or use a non-temp folder | T1486 (± T1490, T1489) |
| rw_inplace_no_rename | encrypts in place without changing extensions; WMI/PowerShell shadow deletion | T1486, T1490, T1134 |
| rw_precursor_only | full precursor chain, stopped before encryption (true early-warning case) | T1059.001, T1134, T1562.001, T1489, T1490 |

**Benign (label 0), mostly hard negatives**
office work · backup agent rotating one shadow copy as SYSTEM · bulk photo rename (same extension) · 7-Zip archive (high entropy) ·
IT patching (admin stops non-security services, uses privileges, `bcdedit /enum`) · developer build (hundreds of tmp→dll renames) ·
SCCM/Intune encoded PowerShell as SYSTEM.
**Gray activity** added to some benign hosts: helpdesk recon commands, UAC-elevated installer from Temp, power-user `-enc` script,
DBA stopping SQL services, sync-client conflict renames (`.sync-conflict`), encrypted-vault writes (high entropy).

## Known limitations / biases
- Behaviour parameters (rates, entropies, delays) are our assumptions, not measured from real fleets. Real telemetry is noisier.
- Entropy is simulated; many real EDRs do not provide it.
- One host = one user; no lateral movement or network-share encryption.
- Detection rules and generator were written by the same team, which inflates scores (we mitigate with a held-out *hard* test
  split, gray activity and evasive variants that were added after the rules were written).

## Using public data
Map Sysmon EVTX/JSON from Splunk Attack Data or OTRF Security-Datasets: Sysmon 1 → `process_start` (Image, ParentImage,
CommandLine, User, IntegrityLevel), 11 → `file_create`, 23 → `file_delete`, Security 4672/4673 → `privilege_use` (PrivilegeList),
System 7036 → `service_stop`. Renames and entropy usually need EDR data; when absent, I1/I2 simply do not fire.
