# *PowerShell COM Interaction*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/04/08 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1559.001 | Inter-Process Communication: Component Object Model | https://attack.mitre.org/techniques/T1559/001/ |

#### Description

This query return events where PowerShell interacts with a Component Object Model (COM), such as creating a new one and then interacting with it.

For instance, a threat actor (or malware) could use the WScript.Shell COM object to then access the Windows Shell features, such as launching processes.

One can also interact with Schedule.Service to interact with Windows Scheduled Tasks.

Bringing the power of COM to a PowerShell near you.

The queries below are more suited for hunting, unless there's very little use of PowerShell to interact with COM in your environment and/or you want to target specific COM (e.g.: WScript.Shell).

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://isc.sans.edu/diary/24282
- https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 2 queries

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "-ComObject"
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "-ComObject"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "-ComObject"
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has "-ComObject"
```
