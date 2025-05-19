# *PowerShell IEX or Invoke-Expression*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/04/05 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |

#### Description

This query return events where the PowerShell Invoke-Expression/IEX (shortened version) cmdlet was used.

The most popular cmdlet used by threat actors, malware and everything in between to just straight up pipe to PowerShell the content of a script (or commands) to execute. Even more suspicious if these are present in encoded PowerShell commands (being in the encoded part, or getting in input the encoded command).

Should be quite easy to spot suspicious/malicious behavior with this through Threat Hunting. And depending of your environment, could be fine-tuned into a detection rule.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 2 queries

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("IEX", "Invoke-Expression")
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("IEX", "Invoke-Expression")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("IEX", "Invoke-Expression")
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("IEX", "Invoke-Expression")
```
