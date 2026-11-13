---
id: KB07
title: Evidence preservation during ransomware response
sources: CISA #StopRansomware Guide Part 2 (May 2023) https://www.cisa.gov/stopransomware/ransomware-guide ; NIST SP 800-61r3 https://csrc.nist.gov/pubs/sp/800/61/r3/final
---
# Evidence preservation

## Collect before you clean
Where possible, capture a memory image and a disk image of affected systems before re-imaging, and export relevant logs (EDR telemetry, Windows Security/System logs, Sysmon, proxy and firewall logs). Keep copies of the ransom note, suspicious binaries (in a password-protected archive, never executed) and encoded scripts. CISA notes that responders and law enforcement may ask for items such as malware samples, executed PowerShell scripts and attacker contact details.

## Chain of custody
Record who collected each artifact, when, from which system and how it was stored. Hash collected files. Store evidence on a system the attacker cannot reach.

## Preserve logs centrally
Ransomware often clears local logs. Confirm that endpoint telemetry has been forwarded to a central SIEM and extend retention for the incident period.
