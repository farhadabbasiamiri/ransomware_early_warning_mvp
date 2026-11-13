---
id: KB03
title: Responding to shadow copy and backup deletion (Inhibit System Recovery)
sources: MITRE ATT&CK T1490 https://attack.mitre.org/techniques/T1490/ ; CISA #StopRansomware Guide Part 1 (backups) https://www.cisa.gov/stopransomware/ransomware-guide ; CCCS ITSAP.40.002 Tips for backing up your information
---
# Shadow copy and backup deletion

## Why it matters
Commands such as `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, PowerShell deletion of Win32_ShadowCopy objects, `wbadmin delete catalog` and `bcdedit ... recoveryenabled no` remove local recovery options. Ransomware operators run them minutes before encryption. When seen from a non-backup process, treat the host as being in the final stage before impact.

## Immediate actions
Escalate to the incident lead and request approval to isolate the host. Verify that offline or immutable backups of the host and its reachable file shares exist and are intact. Temporarily suspend backup deletion or retention jobs that could overwrite good restore points. Check the backup server itself for the same indicators.

## Distinguishing benign activity
Legitimate backup software sometimes rotates snapshots by deleting a specific shadow copy (`/shadow={id}`) while running as SYSTEM under the backup agent. The Volume Shadow Copy service also stops on its own after being idle. These patterns should be confirmed with the backup administrator rather than escalated as incidents.

## Preventive controls
Keep at least one backup copy offline or immutable, restrict who can run vssadmin, wmic and wbadmin, alert on their use outside approved tools, and test restoration regularly.
