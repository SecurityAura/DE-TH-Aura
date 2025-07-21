# *ExternalData - Network Connection to LOTS Project Domain*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/07/21 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

#### Description

As of 2025/07/21 the reworked LOTS Project CSV is still a WIP, but this is a basic query to leverage it without any filters (conditions).

I'll put out more queries once I have reworked the CSV.

All credits for the original LOTS-Project goes to the one and only @mrd0x, on top of all the contributors who submitted domains/sites over the years.

https://lots-project.com/

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

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceNetworkEvents ###
```KQL
let LOTS = externaldata(Website: string, Tags: string, ServiceProvider: string, Created: date, LastUpdate: date, Credits: string)
[@"https://raw.githubusercontent.com/SecurityAura/DE-TH-Aura/refs/heads/main/Data%20Sources/LOTS-Project-Rework.csv"]
with (format=csv)
| extend Website = iff (Website startswith "*.", trim_start(@'\*\.', Website), Website)
| distinct Website;
DeviceNetworkEvents
| extend Domain = case( ActionType in ("ConnectionSuccess","ConnectionFailed"), RemoteUrl,
                        ActionType == "HttpConnectionInspected", tostring(parse_json(AdditionalFields).host),
                        ActionType == "DnsConnectionInspected", tostring(parse_json(AdditionalFields).query),
                        "")
| where Domain has_any (LOTS)
| project-reorder Timestamp, DeviceName, ActionType, Domain
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceNetworkEvents ###
```KQL
let LOTS = externaldata(Website: string, Tags: string, ServiceProvider: string, Created: date, LastUpdate: date, Credits: string)
[@"https://raw.githubusercontent.com/SecurityAura/DE-TH-Aura/refs/heads/main/Data%20Sources/LOTS-Project-Rework.csv"]
with (format=csv)
| extend Website = iff (Website startswith "*.", trim_start(@'\*\.', Website), Website)
| distinct Website;
DeviceNetworkEvents
| extend Domain = case( ActionType in ("ConnectionSuccess","ConnectionFailed"), RemoteUrl,
                        ActionType == "HttpConnectionInspected", AdditionalFields.host,
                        ActionType == "DnsConnectionInspected", AdditionalFields.query,
                        "")
| where Domain has_any (LOTS)
| project-reorder TimeGenerated, DeviceName, ActionType, Domain
```
