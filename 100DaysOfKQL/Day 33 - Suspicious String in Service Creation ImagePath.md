# *Suspicious String in Service Creation ImagePath*

## Query Information

These queries returns events where a suspicious string was found in the ImagePath of a service creation event.

##

#### Description

These queries returns events where a suspicious string, defined in a dynamic property, was found in the ImagePath of a service creation event.

Another "low-hanging fruit" detection and/or hunting query. A lot of tools allowing for lateral movement and/or remote execution (think Cobalt Strike, Impacket, etc.) will stuff the same "execution template" in the ImagePath of a Windows service they create. May it be calling %COMSPEC% or calling the ImagePath from the ADMIN$ share directly.

Looking for service creation where these strings are present allows you to detect or uncover such lateral movement and/or remote execution events.

Luckily for us, some of these patterns already triggers some good detection from Defender for Endpoint (MDE). But, we're looking to get 100% guaranteed alert trigger for these here, or simply hunting for them when they fell through the crack.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://www.crowdstrike.com/en-us/blog/getting-the-bacon-from-cobalt-strike-beacon/
- https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query
- Microsoft Sentinel (SecurityEvents) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
let SuspiciousStrings = dynamic([
    "COMSPEC",
    "cmd",
    "powershell",
    "ADMIN$",
    "C$",
    "127.0.0.1"
]);
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend FullPath = strcat(FolderPath,@"\",FileName)
| where FullPath has_any (SuspiciousStrings)
    or ProcessCommandLine has_any (SuspiciousStrings)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
let SuspiciousStrings = dynamic([
    "COMSPEC",
    "cmd",
    "powershell",
    "ADMIN$",
    "C$",
    "127.0.0.1"
]);
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend FullPath = strcat(FolderPath,@"\",FileName)
| where FullPath has_any (SuspiciousStrings)
    or ProcessCommandLine has_any (SuspiciousStrings)
```
### SecurityEvents ###
```KQL
let SuspiciousStrings = dynamic([
    "COMSPEC",
    "cmd",
    "powershell",
    "ADMIN$",
    "C$",
    "127.0.0.1"
]);
SecurityEvent
| where EventID == 4697
| where ServiceFileName has_any (SuspiciousStrings)
```
