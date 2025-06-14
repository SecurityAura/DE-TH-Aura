# *Events Involving Folder or Path with Trailing Space*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/06/14 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1036 | Masquerading | https://attack.mitre.org/techniques/T1036/ |

#### Description

This query looks for file, image load and process events involving a path where a folder has a trailing space. A simple regex that looks for any folder with a trailing space in the path is all we need here. Be careful as depending on the number of systems you're running this against, and the timeframe, it could use a lot of resources. If needed, you can split it in three (3) distinct queries, one for each table.

Threat actors and/or malware can create folders with a trailing space to blend in and/or avoid detection as an extra degree of attention may be required to spot these odd paths when reviewing data. Some static detections using partial or full paths could also be avoided that.

All the credits for this query idea goes to @Wietze (on Twitter/X) who shared this via his #HuntingTipOfTheDay. See his tweet for more ways this technique can be abused!

https://x.com/Wietze/status/1933495425907999055

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
### Defender for Endpoint (MDE) via DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents ###
```KQL
union DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents
| where FolderPath matches regex @"\\[^\\]*\s\\|\\[^\\]*\s$"
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents ###
```KQL
union DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents
| where FolderPath matches regex @"\\[^\\]*\s\\|\\[^\\]*\s$"
```
