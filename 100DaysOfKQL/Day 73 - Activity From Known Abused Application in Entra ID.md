# *Activity From Known Abused Application in Entra ID*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/15| Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query.

This query returns events from known abused application in Azure/Entra ID.

PS: For more immediate context, this query uses LETHAL-FORENSICS's Microsoft-Analyzer-Suite Application Blacklist to look for events involving a known abused application in Azure (e.g.: eM Client, PERFECTDATA, etc.). I suggest you keep the Severity filter on if you want to use this as a detection for now.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://github.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/tree/main (https://x.com/LETHAL_DFIR)

### Queries Overview ###

- Microsoft Sentinel - 2 queries
- Microsoft Defender for Cloud Apps (MCAS) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Cloud Apps via CloudAppEvents ###
```KQL
let AbusedApps = 
    externaldata ( AppDisplayName: string, AppId: string, Severity:string)
    ["https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/Application-Blacklist.csv"]
    with (format=csv, ignoreFirstRecord=true);
CloudAppEvents
| extend AppId = tostring(parse_json(RawEventData).AppId)
| join kind=leftouter AbusedApps on AppId
// Keep that filter on if you want to target these known abused applications and use this query as a detection
| where Severity == "Red"
```
## Microsoft Sentinel ##
### Microsoft Defender for Cloud Apps via CloudAppEvents ###
```KQL
let AbusedApps = 
    externaldata ( AppDisplayName: string, AppId: string, Severity:string)
    ["https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/Application-Blacklist.csv"]
    with (format=csv, ignoreFirstRecord=true);
CloudAppEvents
| extend AppId = tostring(parse_json(RawEventData).AppId)
| join kind=leftouter AbusedApps on AppId
// Keep that filter on if you want to target these known abused applications and use this query as a detection
| where Severity == "Red"
```
### OfficeActivity ###
```KQL
let AbusedApps = 
    externaldata ( AppDisplayName: string, AppId: string, Severity:string)
    ["https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/Application-Blacklist.csv"]
    with (format=csv, ignoreFirstRecord=true);
OfficeActivity
| join kind=leftouter AbusedApps on AppId
// Keep that filter on if you want to target these known abused applications and use this query as a detection
| where Severity == "Red"
```
### SigninLogs and AADNonInteractiveUserSignInLogs ###
```KQL
let AbusedApps = 
    externaldata ( AppDisplayName: string, AppId: string, Severity:string)
    ["https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/Application-Blacklist.csv"]
    with (format=csv, ignoreFirstRecord=true);
// Taken from Matt Zorich (@reprise99) awesome website: https://learnsentinel.blog/2021/08/30/azure-sentinel-and-the-story-of-a-very-persistent-attacker/
let SuccessCodes = dynamic([0, 50055, 50057, 50155, 50105, 50133, 50005, 50076, 50079, 50173, 50158, 50072, 50074, 53003, 53000, 53001, 50129]);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where ResultType in (SuccessCodes)
| join kind=leftouter AbusedApps on AppId
// Keep that filter on if you want to target these known abused applications and use this query as a detection
| where Severity == "Red"
```
