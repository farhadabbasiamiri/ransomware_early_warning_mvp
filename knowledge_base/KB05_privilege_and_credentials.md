---
id: KB05
title: Suspicious privilege escalation and credential containment
sources: MITRE ATT&CK T1134 https://attack.mitre.org/techniques/T1134/ ; T1068 https://attack.mitre.org/techniques/T1068/ ; CISA #StopRansomware Guide https://www.cisa.gov/stopransomware/ransomware-guide
---
# Privilege escalation and credentials

## Signals
Sensitive privileges such as SeDebugPrivilege, SeTakeOwnershipPrivilege, SeImpersonatePrivilege or SeLoadDriverPrivilege used by a standard user process, or a binary launched from a Temp/AppData folder running at High or System integrity, indicate that an attacker is gaining the rights needed to tamper with defences and encrypt widely.

## Response guidance
With approval, reset the affected user's credentials and revoke sessions and tokens. Review privileged groups (local administrators, domain admins) for recent changes. If domain-level credentials may be exposed, involve the identity team: CISA's guidance notes that attackers often harvest credentials to spread, so password resets for privileged and service accounts may be needed after containment.

## Preventive controls
Apply least privilege, remove local admin rights from standard users, use separate admin accounts, enable multi-factor authentication for remote and privileged access, and keep endpoints patched to reduce exploitable escalation paths.
