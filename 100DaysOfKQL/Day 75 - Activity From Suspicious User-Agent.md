# *Activity From Suspicious User-Agent*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/17 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| N/A | N/A | N/A |

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query.

This query returns events from suspicious user-agent in Entra ID/Microsoft 365.

PS: For more immediate context, this query uses LETHAL-FORENSICS's Microsoft-Analyzer-Suite UserAgent Blacklist to look for events involving a known suspicious/malicious UserAgent.

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
let TargetUserAgents =
    externaldata (UserAgent: string, Category: string, Severity: string)
    ["https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/UserAgent-Blacklist.csv"]
    with (format=csv, ignoreFirstRecord=true)
    | distinct UserAgent;
let TargetUserAgentsScalar = toscalar(TargetUserAgents
| summarize l=make_list(UserAgent));
CloudAppEvents
| where UserAgent has_any (TargetUserAgentsScalar)
```
## Microsoft Sentinel ##
### Microsoft Defender for Cloud Apps via CloudAppEvents ###
```KQL
let TargetUserAgents =
    externaldata (UserAgent: string, Category: string, Severity: string)
    ["https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/UserAgent-Blacklist.csv"]
    with (format=csv, ignoreFirstRecord=true)
    | distinct UserAgent;
let TargetUserAgentsScalar = toscalar(TargetUserAgents
| summarize l=make_list(UserAgent));
CloudAppEvents
| where UserAgent has_any (TargetUserAgentsScalar)
```
### OfficeActivity ###
```KQL
let TargetUserAgents =
    externaldata (UserAgent: string, Category: string, Severity: string)
    ["https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/UserAgent-Blacklist.csv"]
    with (format=csv, ignoreFirstRecord=true)
    | distinct UserAgent;
let TargetUserAgentsScalar = toscalar(TargetUserAgents
| summarize l=make_list(UserAgent));
OfficeActivity
| where UserAgent has_any (TargetUserAgentsScalar)

```
### SigninLogs and AADNonInteractiveUserSignInLogs ###
```KQL
let TargetUserAgents =
    externaldata (UserAgent: string, Category: string, Severity: string)
    ["https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/refs/heads/main/Blacklists/UserAgent-Blacklist.csv"]
    with (format=csv, ignoreFirstRecord=true)
    | distinct UserAgent;
let TargetUserAgentsScalar = toscalar(TargetUserAgents
| summarize l=make_list(UserAgent));
union SigninLogs, AADNonInteractiveUserSignInLogs
| where UserAgent has_any (TargetUserAgentsScalar)
```
