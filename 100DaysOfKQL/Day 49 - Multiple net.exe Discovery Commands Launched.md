# *Multiple net.exe Discovery Commands Launched*

## Query Information

This query returns events when multiple net.exe discovery commands are launched.

##

#### Description

Dislaimer: Today's query was documented quite quickly due to a personal emergency on my end. I'll enhance it later as I have time.

This query returns events when multiple net.exe discovery commands (for users and groups, may they be local or domain) are launched within a short timespan.

net.exe remains one of the most commonly used utility used by threat actors (and even malware at some point) for discovery of:

- Local users
- Local groups
- Domain users
- Domain groups

It is therefore not rare to see net.exe commands being launched by threat actors as their first actions in a compromised environment. May it be to get more information on the user they currently have, users they may have compromised, users they are interested in compromising, etc. These commands can be launched in rapid succession, under a matter of minutes. It is therefore interesting to identify events where X number of net.exe discovery commands are launched within Y minutes. And from there:

- Identify which account launched them
- Identify on which device these commands were executed
- Expand the scope and look at commands (e.g.: process execution) and/or logon events before and after these commands were launched for anything out of the ordinary
- Etc.

This query is more suited as a "hunting query" and is what we call a "threshold-based" query. A query in which you need to define threshold (arbitrary values) that are used to define the scope of the query. Which means, these values may have to be baselined for your own environment.

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
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let TimeBin = 5m;
let ProcessCount = 5;
DeviceProcessEvents
| where FileName =~ "net.exe"
| where ProcessCommandLine has_any (" user ", " localgroup ", " group ")
// We are not interested in manipulation operations here where users are created and/or added to groups
// Though other manipulation-related parameters exists, but are more rare. Should they be returned, they are definitely worth looking into, such as /active:{yes|no}
| where ProcessCommandLine !has "/add"
| summarize count(),
            ["ProcessCommandLines"]=make_set(ProcessCommandLine),
            ["FirstCommandTime"]=min(TimeGenerated),
            ["LastCommandTime"]=max(TimeGenerated)
            by DeviceName, AccountDomain, AccountName, bin(TimeGenerated, TimeBin)
| where ProcessCount >= 5
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let TimeBin = 5m;
let ProcessCount = 5;
DeviceProcessEvents
| where FileName =~ "net.exe"
| where ProcessCommandLine has_any (" user ", " localgroup ", " group ")
// We are not interested in manipulation operations here where users are created and/or added to groups
// Though other manipulation-related parameters exists, but are more rare. Should they be returned, they are definitely worth looking into, such as /active:{yes|no}
| where ProcessCommandLine !has "/add"
| summarize count(),
            ["ProcessCommandLines"]=make_set(ProcessCommandLine),
            ["FirstCommandTime"]=min(TimeGenerated),
            ["LastCommandTime"]=max(TimeGenerated)
            by DeviceName, AccountDomain, AccountName, bin(TimeGenerated, TimeBin)
| where ProcessCount >= 5
```
