# *Summarization of net.exe use from Batch Script*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/10/14 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1552.001 | Unsecured Credentials: Credentials in Files | https://attack.mitre.org/techniques/T1552/ |

#### Description

This query looks for instances where net.exe, spawned from a batch script, is used to connect a network share with an explicit user (/user:) and from there, break downs by DeviceName, the user, destination (share/folder/etc.) and batch script involved.

More of a ... audit query if you wish, where users may still be explicitly connecting to shares using clear text credentials in batch script. Hence the TTP used.

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
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "net.exe"
| where InitiatingProcessCommandLine != "\"cmd.exe\" "
| where ProcessCommandLine has_all("use","/user:")
| extend LowerProcessCommandLine = tolower( ProcessCommandLine)
| extend ArgumentUser = extract(@"/user:([^\s]+)", 1, LowerProcessCommandLine)
| extend SanitizedScriptName = trim_end(" \"", InitiatingProcessCommandLine)
| extend ComputerName = extract(@"(?i)\\\\[^\s]+",0,ProcessCommandLine)
| extend ScriptName = tostring(split(SanitizedScriptName," ")[-1])
| extend UserToShareToScript = tostring(bag_pack("User", ArgumentUser, "Destination", ComputerName, "Script", ScriptName))
| summarize UserToShareToScriptInstances = make_set(UserToShareToScript),
            UserToShareToScriptInstancesCount = dcount(UserToShareToScript)
    by DeviceName
| project-reorder DeviceName, UserToShareToScriptInstancesCount, UserToShareToScriptInstances
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "net.exe"
| where InitiatingProcessCommandLine != "\"cmd.exe\" "
| where ProcessCommandLine has_all("use","/user:")
| extend LowerProcessCommandLine = tolower( ProcessCommandLine)
| extend ArgumentUser = extract(@"/user:([^\s]+)", 1, LowerProcessCommandLine)
| extend SanitizedScriptName = trim_end(" \"", InitiatingProcessCommandLine)
| extend ComputerName = extract(@"(?i)\\\\[^\s]+",0,ProcessCommandLine)
| extend ScriptName = tostring(split(SanitizedScriptName," ")[-1])
| extend UserToShareToScript = tostring(bag_pack("User", ArgumentUser, "Destination", ComputerName, "Script", ScriptName))
| summarize UserToShareToScriptInstances = make_set(UserToShareToScript),
            UserToShareToScriptInstancesCount = dcount(UserToShareToScript)
    by DeviceName
| project-reorder DeviceName, UserToShareToScriptInstancesCount, UserToShareToScriptInstances
```
