# *Potential Discovery via PowerShell Test-Connection and Test-NetConnection*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/08 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1046 | Network Service Discovery | https://attack.mitre.org/techniques/T1046/ |

#### Description

DISCLAIMER - I'm currently sick and fighting sleepiness as I post this. As usual, I'll enhance that page with more information when I get better/get back. For now, consider this as a hunting query.

This query returns events where the Test-Connection or Test-NetConnection PowerShell cmdlet has been used.

PS: For more immediate context, these cmdlets have been observed being used in "homemade" discovery commands and/or PowerShell scripts by threat actors.
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://unit42.paloaltonetworks.com/thanos-ransomware/

### Queries Overview ###

- Defender for Endpoint (MDE) - 3 queries

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| extend Command = tostring(parse_json(AdditionalFields).Command)
| where Command has_any ("Test-Connection","Test-NetConnection")
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Test-Connection","Test-NetConnection")
```
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where InitiatingProcessCommandLine has_any ("Test-Connection","Test-NetConnection")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| extend Command = tostring(parse_json(AdditionalFields).Command)
| where Command has_any ("Test-Connection","Test-NetConnection")
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Test-Connection","Test-NetConnection")
```
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where InitiatingProcessCommandLine has_any ("Test-Connection","Test-NetConnection")
```
