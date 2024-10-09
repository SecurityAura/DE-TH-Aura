# *WBAdmin.exe - Sensitive File Dump or Collection*

## Query Information

Encountered during an Akira Ransomware incident from Summer 2024, the threat actor installed the Windows Server Backup optional feature, used wbadmin.exe to create a backup of NTDS.dit alongside the SECURITY and SYSTEM hives and uninstalled the feature afterwards.

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1003.003 | OS Credential Dumping: NTDS | https://attack.mitre.org/techniques/T1003/003/ |

#### Description

This rule detects the use of wbadmin.exe with the "start" and "backup" parameters and the presence of sensitive filenames:

- NTDS.dit
- SYSTEM (for the SYSTEM Registry Hive)
- SECURITY (for the SECURITY Registry Hive)
- SAM (for the SAM Registry Hive)

In this particular incident, only the NTDS.dit, SYSTEM and SECURITY Hives were targeted by the threat actor.

#### Risk

A threat actor is attempting to obtain copies of the ntds.dit (Active Directory database) and the SECURITY + SYSTEM + SAM Registry Hives which would allow it to dump the content of ntds.dit and recover information such as password hashes.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### References
- https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_wbadmin_dump_sensitive_files/?query=wbadmin
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin

## Defender XDR
```KQL
DeviceProcessEvents
| where FileName =~ "wbadmin.exe"
| where ProcessCommandLine has_all ("start","backup")
| where ProcessCommandLine has_any ("ntds.dit","SYSTEM","SECURITY","SAM")
```
## Sentinel
```KQL
DeviceProcessEvents
| where FileName =~ "wbadmin.exe"
| where ProcessCommandLine has_all ("start","backup")
| where ProcessCommandLine has_any ("ntds.dit","SYSTEM","SECURITY","SAM")
```
