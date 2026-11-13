---
id: KB02
title: Isolation and containment of an endpoint showing ransomware behaviour
sources: CISA #StopRansomware Guide Part 2 (May 2023) https://www.cisa.gov/stopransomware/ransomware-guide ; Canadian Centre for Cyber Security Ransomware Playbook ITSM.00.099 https://www.cyber.gc.ca/en/guidance/ransomware-playbook-itsm00099
---
# Isolation and containment

## Isolate affected systems quickly
CISA's checklist puts isolation of impacted systems first. Prefer network isolation through the EDR console (host containment), or removing the host from the network / placing it in a quarantine VLAN. If the host cannot be disconnected, powering it down is a last resort because it destroys volatile memory evidence. All isolation actions affect users and must be approved by the on-call incident handler.

## Contain the account
If the activity runs under a user account, consider disabling or forcing a credential reset for that account and revoking its active sessions. If privilege escalation was observed, also review recently used administrative accounts. Coordinate with the identity team so legitimate service accounts are not disabled by mistake.

## Block the execution chain
Block the suspicious binary (by hash or path) and its parent script through application control or EDR policy. Block outbound connections to any command-and-control address observed in the telemetry at the firewall or proxy.

## What not to do
Do not run destructive clean-up (deleting files, re-imaging) before evidence is preserved. Do not pay or contact the attacker without executive, legal and law-enforcement guidance; both CISA and the Canadian Cyber Centre advise against paying because payment does not guarantee recovery. The early-warning agent only recommends containment; a human performs it.
