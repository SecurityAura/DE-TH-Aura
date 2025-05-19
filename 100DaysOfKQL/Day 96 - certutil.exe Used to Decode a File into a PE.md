# *certutil.exe Used to Decode a File into a PE*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/01 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1140 | Deobfuscate/Decode Files or Information | https://attack.mitre.org/techniques/T1140/ |

#### Description

This query return events where certutil.exe is used to decode a file into a PE. The idea here is that the original file is simply a base64 encoded file (e.g.: payload.txt) that, when decoded with certutil.exe, will turn into a valid PE (e.g.: payload.exe), which can then be executed.

That file can be brought on a system in different ways, or even create (e.g.: you could echo a whole base64 encoded string in a file and then use certutil decode it). The REvil attack which leveraged Kaseya leveraged that concept:

https://blog.qualys.com/vulnerabilities-threat-research/2021/07/07/analyzing-the-revil-ransomware-attack

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 1 query

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where InitiatingProcessFileName =~ "certutil.exe"
| where InitiatingProcessCommandLine has "decode"
| extend FileType = tostring(parse_json(AdditionalFields).FileType)
| where FileType == "PortableExecutable"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
DeviceFileEvents
| where InitiatingProcessFileName =~ "certutil.exe"
| where InitiatingProcessCommandLine has "decode"
| extend FileType = tostring(parse_json(AdditionalFields).FileType)
| where FileType == "PortableExecutable"
```
