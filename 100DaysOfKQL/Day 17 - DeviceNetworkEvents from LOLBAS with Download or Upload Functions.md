# *DeviceNetworkEvents from LOLBAS with Download or Upload Functions*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/17 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |
| 2025/05/25 | Added MITRE ATT&CK |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1105 | Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105/ |

#### Description

This query returns network events for LOLBAS, from the LOLBAS Project, that can be used to Download and/or Upload data, such as files.

This can be achieved through the newly (well, 2022 news) published CSV feed. See the tweet below:

https://x.com/Wietze/status/1576950693789077506

Back then, Nathan McNulty (@NathanMcNulty) had already shared a first iteration of a KQL query that could be used to find network events from LOLBAS:

https://x.com/NathanMcNulty/status/1577184175765213185

The version I'm proposing below comes with two (2) adjustements:

- We're only interested in LOLBAS that have Download and/or Upload capabilities, since not all LOLBAS do but they would still be returned because they are processes that can make network connection
- We filter on LOLBAS whose process command line indicate they're trying to reach out to http/https URLs and/or UNC paths

The second point is based on the review of how each LOLBAS can be used for Download/Upload (their example). And most, if not all of them, either use an http/https URL (protocol handler) in the command line or a UNC path. Though it is possible that other protocol/file handlers could be used.

This query is best used for hunting, since there are going to be way too many results and not enough fine-tuning to make it into a detection.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://lolbas-project.github.io/

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 1 query

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let LOLBINS = (
    externaldata ( Filename:string, Description:string, Author:string, Date:datetime, Command:string, CommandDescription:string, CommandUsecase:string, CommandCategory:string ) [ "https://lolbas-project.github.io/api/lolbas.csv" ]
    with (format=csv, ignoreFirstRecord=true)
    | where CommandCategory in ("Download","Upload")
    | distinct Filename);
let ExcludedDomainUrlStrings = dynamic([
    "ADD DOMAINS TO EXCLUDE HERE"
]);
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (LOLBINS)
// We're filtering out msedge.exe and msedgewebview2.exe for obvious reasons, but if you want them to be included in the results, comment out that filter.
| where InitiatingProcessFileName !in~ ("msedge.exe","msedgewebview2.exe")
| where InitiatingProcessCommandLine has_any ("http","https",@"\\")
// We're excluding common/known good domains that may be in command lines, such as your SharePoint and/or OneDrive sites. Even FQDNs and the likes. If you're not interested in that filtering, comment that filter.
| where not (InitiatingProcessCommandLine has_any (ExcludedDomainUrlStrings))
// We're only targeting network connections to the Internet (Public IP). Though if you want to look for internal download/upload of data through these LOLBAS, comment that filter.
| where RemoteIPType == "Public"
| project-reorder TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
let LOLBINS = (
    externaldata ( Filename:string, Description:string, Author:string, Date:datetime, Command:string, CommandDescription:string, CommandUsecase:string, CommandCategory:string ) [ "https://lolbas-project.github.io/api/lolbas.csv" ]
    with (format=csv, ignoreFirstRecord=true)
    | where CommandCategory in ("Download","Upload")
    | distinct Filename);
let ExcludedDomainUrlStrings = dynamic([
    "ADD DOMAINS TO EXCLUDE HERE"
]);
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (LOLBINS)
// We're filtering out msedge.exe and msedgewebview2.exe for obvious reasons, but if you want them to be included in the results, comment out that filter.
| where InitiatingProcessFileName !in~ ("msedge.exe","msedgewebview2.exe")
| where InitiatingProcessCommandLine has_any ("http","https",@"\\")
// We're excluding common/known good domains that may be in command lines, such as your SharePoint and/or OneDrive sites. Even FQDNs and the likes. If you're not interested in that filtering, comment that filter.
| where not (InitiatingProcessCommandLine has_any (ExcludedDomainUrlStrings))
// We're only targeting network connections to the Internet (Public IP). Though if you want to look for internal download/upload of data through these LOLBAS, comment that filter.
| where RemoteIPType == "Public"
| project-reorder TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort
```
