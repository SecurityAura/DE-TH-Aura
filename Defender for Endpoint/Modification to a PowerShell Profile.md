# *Modification to a PowerShell Profile*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/06/04 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1546.013 | Event Triggered Execution: PowerShell Profile | https://attack.mitre.org/techniques/T1546/013/ |

#### Description

This query looks for DeviceFileEvents where a PowerShell profile (.ps1) file (Profile.ps1, Microsoft.PowerShell_profile.ps1) is involved in one of the known (default) location. This query only cover PowerShell classic and PowerShell (new) profile paths. At a user level, PowerShell profiles are usually located in the user's Documents folder. However, with OneDrive redirection of the Documents folder, it would fall under the OneDrive\Documents folder and not your standard $USERNAME\Documents folder.

https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.5

Threat Actors can modify/tamper with a PowerShell profile, even create one, in order to execute code whenever PowerShell is launched. This can be used for code execution or even persistence. The code will be executed in the context of the user that launched the process, which can lead to privilege escalation.

If this query return any hits, you'll want to investigate what process was involved in modifying that file (or even deleting it) and how.

All the credits for this query idea goes to @Wietze (on Twitter/X) who shared this via his #HuntingTipOfTheDay.

https://x.com/Wietze/status/1930203495807832545

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
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where FolderPath matches regex @"(?i):\\Program\ Files\\PowerShell\\7\\(Profile|Microsoft\.PowerShell_profile)\.ps1"
    or FolderPath matches regex @"(?i):\\Windows\\System32\\WindowsPowerShell\\v1.0\\(Profile|Microsoft\.PowerShell_profile)\.ps1"
    or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Documents\\PowerShell\\(Profile|Microsoft\.PowerShell_profile)\.ps1"
    or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\OneDrive([^\\]+)\\Documents\\PowerShell\\(Profile|Microsoft\.PowerShell_profile)\.ps1"
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where FolderPath matches regex @"(?i):\\Program\ Files\\PowerShell\\7\\(Profile|Microsoft\.PowerShell_profile)\.ps1"
    or FolderPath matches regex @"(?i):\\Windows\\System32\\WindowsPowerShell\\v1.0\\(Profile|Microsoft\.PowerShell_profile)\.ps1"
    or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\Documents\\PowerShell\\(Profile|Microsoft\.PowerShell_profile)\.ps1"
    or FolderPath matches regex @"(?i):\\Users\\[^\\]+\\OneDrive([^\\]+)\\Documents\\PowerShell\\(Profile|Microsoft\.PowerShell_profile)\.ps1"
```
