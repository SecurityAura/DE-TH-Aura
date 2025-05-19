# *mshta.exe Executing Raw Script From Command Line*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/22 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.005 | System Binary Proxy Execution: Mshta | https://attack.mitre.org/techniques/T1218/005/ |

#### Description

DISCLAIMER - I have to post this query quickly today. I'll comeback to it and update it with more information later on.

This query returns events where mshta.exe executes a raw script, may it be VBScript or JavaScript, provided in the command line.

This query can be used as a detection, since that kind of usage for mshta.exe is very rare. You may see it in environment which relies on a lot of legacy scripts that were never updated and/or migrated to newer languages or technologies, but even there, these are rare.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://www.mcafee.com/learn/what-is-mshta-how-can-it-be-used-and-how-to-protect-against-it/
- https://www.ired.team/offensive-security/code-execution/t1170-mshta-code-execution
- https://redcanary.com/blog/threat-detection/windows-registry-attacks-threat-detection/
- https://redcanary.com/blog/threat-detection/microsoft-html-application-hta-abuse-part-deux/

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("javascript:", "vbscript:")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("javascript:", "vbscript:")
```
