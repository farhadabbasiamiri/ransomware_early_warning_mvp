---
id: KB09
title: False positive triage for ransomware early-warning alerts
sources: Project analyst guidance derived from MITRE ATT&CK detection notes https://attack.mitre.org/ and vendor-neutral SOC practice
---
# False positive triage

## Common benign look-alikes
- Bulk renaming of photos or documents that keeps the same extension (I1 should not fire; if it does, check the extension list).
- Compression tools (7-Zip, WinRAR) writing high-entropy archive files.
- Software builds producing hundreds of temporary files renamed to .dll/.obj/.pdb.
- Backup agents rotating a single shadow copy as SYSTEM; the VSS service stopping when idle.
- IT administrators stopping non-security services during an approved patch window.
- Endpoint management agents running encoded PowerShell as SYSTEM.

## How to decide
Check the parent process, account, change calendar and asset owner. Benign activity normally shows only one indicator, comes from a known tool, and lacks the combination of backup deletion, service tampering and mass encryption. When in doubt, keep the alert open, monitor the host, and ask the owner rather than isolating a business-critical machine.

## Tuning
Record confirmed false positives with the reason. Add narrowly scoped allowlist entries (specific parent process plus account plus command pattern), never broad exclusions such as all PowerShell.
