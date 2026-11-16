---
id: KB01
title: Initial triage and scoping of a suspected ransomware host
sources: CISA #StopRansomware Guide Part 2 (May 2023) https://www.cisa.gov/stopransomware/ransomware-guide ; NIST SP 800-61r3 https://csrc.nist.gov/pubs/sp/800/61/r3/final
---
# Initial triage and scoping

## Confirm the signal before acting
Treat an early-warning alert as a hypothesis. Review the evidence the detector produced: which indicators fired, when they first appeared, which process and account produced them. Ransomware precursors (shadow copy deletion, security service tampering, encoded PowerShell launched from an Office application) are high-value signals even before any file is encrypted. A single weak signal from a known management or backup tool is usually benign and should be verified with the asset owner.

## Determine scope
Identify which hosts show the same process name, hash, parent process, command line or user account in the same time window. Ransomware operators typically stage on several machines before triggering encryption, so check file servers and hosts that the affected user can reach. Record every affected system in the incident ticket with the time of first suspicious activity.

## Prioritise by business impact
Rank affected systems by criticality (domain controllers, file servers, backup servers, systems with regulated data first). Escalate immediately to the incident response lead when a host scores CRITICAL or when backup deletion is observed, because the attacker is likely preparing to encrypt.

## Document as you go
Start a timeline from the first malicious event. Note every decision, who approved it and when. Good documentation supports later reporting obligations, insurance claims and lessons-learned reviews.
