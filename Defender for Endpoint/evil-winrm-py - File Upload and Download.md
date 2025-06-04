# *evil-winrm-py - File Upload and Download.md*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/06/04 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.006 | Remote Services: Windows Remote Management | https://attack.mitre.org/techniques/T1021/006/ |

#### Description

This query looks for potential file upload and/or download activity originating from evil-winrm-py (https://github.com/adityatelange/evil-winrm-py) by @adityatelange (on Twitter/X)

These static detections are possible because of the underlying send.ps1 script and run_ps Python method that is used, which executes PowerShell commands.

When downloading a file via evil-winrm-py (e.g.: download C:\Temp\FileToExfil.txt /tmp ), a Resolve-Path PowerShell command will be executed against that target file. Which is interesting because it'll precisely identify which file was downloaded.

As for the file upload, through send.ps1, the [System.IO.Path]::GetTempFileName() call is used to get a temporary filename (e.g.: tmp1234E.tmp, which is basically tmp*.tmp) to drop it in the temp location first (e.g.: %TEMP%) before moving it to the destination passed to the upload command.

For both operations, the process involved is wsmprovhost.exe. Which means, there is a possibility to widen these queries for other kind of WinRM abuse should other tools be used.

The inspiration for these queries is @TJ_Null (on Twitter/X) when he tweeted about that tool (https://x.com/TJ_Null/status/1930272511326933310). All credits goes to him for that. And @adityatelange for the tool!

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 2 queries

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceFileEvents - File Upload ###
```KQL
DeviceFileEvents
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where PreviousFileName matches regex @"(?i)tmp[A-Za-z0-9]+\.tmp"
```
### Defender for Endpoint (MDE) via DeviceEvents - File Download ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where AdditionalFields has "Resolve-Path
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceFileEvents - File Upload ###
```KQL
DeviceFileEvents
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where PreviousFileName matches regex @"(?i)tmp[A-Za-z0-9]+\.tmp"
```
### Defender for Endpoint (MDE) via DeviceEvents - File Download ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where AdditionalFields has "Resolve-Path
```
