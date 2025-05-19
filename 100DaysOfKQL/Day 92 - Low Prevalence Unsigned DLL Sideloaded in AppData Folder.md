# *Low Prevalence Unsigned or Invalid Signed DLL Sideloaded in AppData Folder*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/04/04 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1574.001 | Hijack Execution Flow: DLL | https://attack.mitre.org/techniques/T1574/001/ |
| T1036.001 | Masquerading: Invalid Code Signature | https://attack.mitre.org/techniques/T1036/001/ |

#### Description

This query returns events where an unsigned DLL gets sideloaded in an AppData folder. A small twist on #100DaysOfKQL Query 18.

By AppData folder, I mean a subfolder of either %LOCALAPPDATA% or %APPDATA% like so:

- C:\Users\$USERNAME\AppData\Local\SomeFolder\Application.exe loading C:\Users\$USERNAME\AppData\Local\SomeFolder\Module.dll
- C:\Users\$USERNAME\AppData\Roaming\SomeFolder\Application.exe loading C:\Users\$USERNAME\AppData\Roaming\SomeFolder\Module.dll

This query uses the ever so popular FileProfile() to get the signature state of a file. This kind of check can be applied to multiple folders as well (winkwink Downloads folder) where malware are known to be executed initially and/or dropped early on in the infection chain. Not all payloads are signed which makes this an easy detection.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function
- https://cyble.com/blog/threat-actor-targets-manufacturing-industry-with-malware/
- https://asec.ahnlab.com/en/64106/

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceImageLoadEvents ###
```KQL
let UnsignedLowPrevDLLs = (DeviceImageLoadEvents
| where InitiatingProcessFolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\[^\\]+\\[^\\]+$"
| where FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\[^\\]+\\[^\\]+$"
| where FileName endswith ".dll"
| where isnotempty( SHA1)
| distinct SHA1
| invoke FileProfile("SHA1",1000)
| where SignatureState in ("Unsigned", "SignedInvalid")
| where GlobalPrevalence < 500);
DeviceImageLoadEvents
| where InitiatingProcessFolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\[^\\]+\\[^\\]+$"
| where FolderPath matches regex @"(?i)C\:\\Users\\[^\\]+\\AppData\\(Local|Roaming)\\[^\\]+\\[^\\]+$"
| where FileName endswith ".dll"
| join UnsignedLowPrevDLLs on SHA1
```
