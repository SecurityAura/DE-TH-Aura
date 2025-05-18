# *Windows Remote Management Command Targeting a Remote Endpoint*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/20 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1047 | Windows Management Instrumentation | https://attack.mitre.org/techniques/T1047/ |
| T1021.006 | Remote Services: Windows Remote Management | https://attack.mitre.org/techniques/T1021/006/ |

#### Description

DISCLAIMER - I sadly also have to post this very quickly today. I'll come back later to update this page with more information/details. For now, see the description from this query's "sister" query (Day 50):

https://github.com/SecurityAura/DE-TH-Aura/blob/main/100DaysOfKQL/Day%2050%20-%20Windows%20Remote%20Management%20Command%20Targeting%20a%20Remote%20Endpoint.md

This query belows look for traces of command/process execution on an endpoint that was the TARGET of Windows Remote Management commands. Summary for now:

- wmic.exe leads to WmiPrvSE.exe launching the command on the target
- PowerShell Remoting leads to WSMProvHost.exe launching the command on the target
- winrs.exe leads to winrshost.exe launching the command on the target

Going to add queries to trace back the logon associated with the remote command execution as well.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query (for now)

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("wmiprvse.exe", "wsmprovhost.exe", "winrshost.exe")
```
