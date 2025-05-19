# *SoftPerfect Network Scanner Usage*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/02 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1046 | Network Service Discovery | https://attack.mitre.org/techniques/T1046/ |

#### Description

This query returns events where SoftPerfect Network Scanner (netscan.exe) is used.

That tool needs no introduction and there's literally nothing to say about it other than, just make sure that if you have a hit for it, make sure that it's actually used legitimately.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents, DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents (union) ###
```KQL
union DeviceEvents, DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents
| where FileName =~ "netscan.exe"
    or ProcessVersionInfoCompanyName has "SoftPerfect"
    or InitiatingProcessFileName =~ "netscan.exe"
    or InitiatingProcessVersionInfoCompanyName has "SoftPerfect"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents, DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents (union) ###
```KQL
union DeviceEvents, DeviceFileEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents
| where FileName =~ "netscan.exe"
    or ProcessVersionInfoCompanyName has "SoftPerfect"
    or InitiatingProcessFileName =~ "netscan.exe"
    or InitiatingProcessVersionInfoCompanyName has "SoftPerfect"
```
