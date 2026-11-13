---
id: KB06
title: Suspicious execution chain - Office spawning PowerShell, encoded commands, discovery
sources: MITRE ATT&CK T1059.001, T1027, T1204.002, T1083, T1135, T1482 https://attack.mitre.org/ ; CCCS Ransomware Playbook ITSM.00.099 https://www.cyber.gc.ca/en/guidance/ransomware-playbook-itsm00099
---
# Initial execution, PowerShell and discovery

## Signals
A document application (Word, Excel, Outlook) launching PowerShell or cmd, PowerShell run with `-enc`/`-EncodedCommand` and hidden windows, executables started from Temp, AppData or Public folders, and bursts of reconnaissance commands (`whoami /all`, `net view`, `nltest /domain_trusts`, `net group "domain admins"`) are common early stages of a ransomware intrusion. Phishing remains one of the most frequent initial access vectors noted by the Canadian Cyber Centre.

## Response guidance
Capture the full command line and decode encoded PowerShell in an isolated analysis environment (never execute it). Identify the originating email or download and search mailboxes for the same message. With approval, block the sender, URL and dropped file hash. Because these are early signals, acting now can stop the attack before backup deletion and encryption.

## Benign look-alikes
Endpoint management agents (for example SCCM/ConfigMgr or Intune running as SYSTEM) legitimately run encoded PowerShell. Verify the parent process and account before escalating.
