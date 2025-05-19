# *ESENTUTL Used to Copy a File*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/31 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1006 | Direct Volume Access | https://attack.mitre.org/techniques/T1006 |
| T1003.003 | OS Credential Dumping: NTDS | https://attack.mitre.org/techniques/T1003/003 |

#### Description

This query returns events where ESENTUTL was used to copy a file.

Another one when it comes to using built-in Windows tools and features to extract or make accessible files which can contain credentials/secrets by threat actors, such as NTDS.dit, SAM, SECURITY or SYSTEM Registry Hives.

esentutl.exe may be used in some environment by SysAdmins trying to interact (repair, recover, etc.) databases built with the Extensible Storage Engine (ESE) format. However, using it for copy operations (/y) should be quite rare. Even more so if the /vss switch, to perform the copy using the Volume Shadow Copy service is used.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875594(v=ws.11)

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "esentutl.exe"
| where ProcessCommandLine has "/y"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "esentutl.exe"
| where ProcessCommandLine has "/y"
```
