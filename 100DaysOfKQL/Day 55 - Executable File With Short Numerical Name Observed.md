# *Executable File With Short Numerical Name Observed*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/24| Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1036 | Masqueraring | https://attack.mitre.org/techniques/T1036/ |

#### Description

This query returns events where an executable file, per its extension, with a short numerical name (less than 3 numbers) was observed.

The query basically speaks for itself. It is not uncommon during incidents to see that threat actors dropped and/or leveraged binaries with extremely short numerical names: 1.exe, 2.ps1, def.bat, etc.

Therefore, we're looking for file events involving files with executable extensions (common ones) whose name are 3 numbers or less (excluding the extension). You can add extensions as needed and even play with the number of characters to increment the minimum (4, 5, etc.) to see what comes up.

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
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
let FileNameRegex = @'^[0-9]{1,3}\.(exe|msi|dll|ps1|bat|cmd)';
DeviceFileEvents
| where FileName matches regex FileNameRegex
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
let FileNameRegex = @'^[0-9]{1,3}\.(exe|msi|dll|ps1|bat|cmd)';
DeviceFileEvents
| where FileName matches regex FileNameRegex
```
