# *Summarized Defender for Endpoint AntivirusDetection By Endpoint*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/01 | Initial version (part of #100DaysOfKQL) |
| 2025/05/19 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |


#### Description

This query returns a summarized list of AntivirusDetections events by DeviceName, with highlighted (read: interesting) properties to look at.

This is more of an ... investigative kind of query as well when you want to get an idea of how many threats were detected in X days in an environment and maybe even identify the devices with the most detection.

It's also a good example for the bag_pack() KQL function, showing how you can create an arbitrary dynamic object with properties (fields) of your choosing. There are many more fields that can be added and/or formatted directly this query's bag_pack(). Hopefully it'll serve as a good base for you to start playing with it!

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://learn.microsoft.com/en-us/kusto/query/pack-function?view=microsoft-sentinel

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "AntivirusDetection"
| extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName)
| extend DetectedObject = strcat(FolderPath,"\\",FileName)
| extend ThreatDetails = bag_pack(
    "ThreatName", ThreatName,
    "DetectedObject", DetectedObject,
    "DetectedObjectOrigin", FileOriginUrl,
    "InitiatingProcess", InitiatingProcessFolderPath,
    "InitiatingProcessCommandLine", InitiatingProcessCommandLine
)
| summarize ["Threats"]=make_set(ThreatDetails),
            ["ThreatsCount"]=dcount(tostring(ThreatDetails))
            by DeviceName
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "AntivirusDetection"
| extend ThreatName = tostring(parse_json(AdditionalFields).ThreatName)
| extend DetectedObject = strcat(FolderPath,"\\",FileName)
| extend ThreatDetails = bag_pack(
    "ThreatName", ThreatName,
    "DetectedObject", DetectedObject,
    "DetectedObjectOrigin", FileOriginUrl,
    "InitiatingProcess", InitiatingProcessFolderPath,
    "InitiatingProcessCommandLine", InitiatingProcessCommandLine
)
| summarize ["Threats"]=make_set(ThreatDetails),
            ["ThreatsCount"]=dcount(tostring(ThreatDetails))
            by DeviceName
```
