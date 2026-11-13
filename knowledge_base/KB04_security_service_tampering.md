---
id: KB04
title: Security tool and service tampering (Service Stop, Impair Defenses)
sources: MITRE ATT&CK T1489 https://attack.mitre.org/techniques/T1489/ ; MITRE ATT&CK T1562.001 https://attack.mitre.org/techniques/T1562/001/
---
# Security and backup service tampering

## What the behaviour looks like
Before encrypting, ransomware commonly stops antivirus/EDR agents, backup agents, database engines and mail stores using `net stop`, `sc stop`, `sc config ... start= disabled` or `taskkill`. Stopping databases releases file locks so the data files can be encrypted; stopping security tools removes protection and logging.

## Response guidance
Confirm whether a change ticket covers the service stop. If not, treat the host as compromised: request approval to isolate it, restore the security agent from a trusted management console, and check whether tamper-protection settings were changed. Review which account issued the commands; an unexpected account using administrative privileges suggests credential compromise.

## Benign look-alikes
IT staff stop services such as Windows Update, Print Spooler or IIS during patching. Those services are not security or backup controls and are usually tied to a maintenance window. Use the change calendar and the admin account allowlist to separate maintenance from tampering.
