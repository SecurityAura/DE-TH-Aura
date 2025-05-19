# *PowerShell Process Launching PowerShell Process with Encoded Command*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/21 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | https://attack.mitre.org/techniques/T1027/010/ |

#### Description

DISCLAIMER - I have to post this query quickly today. I'll comeback to it and update it with more information later on.

This query returns events a PowerShell process launches another PowerShell process that has an encoded command (-EncodedCommand) or vice-versa.

This query should be considered as a threat hunting query. Depending on what is running an environment, that sort of behavior should be quite rare, if not absent. False positives could occur with solutions such as Ansible.

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
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let EncodedCommandStrings = dynamic([
    "-e ",
    "-ec ",
    "-en ",
    "-enc ",
    "-enco ",
    "-encod ",
    "-encoded ",
    "-EncodedCommand "
]);
DeviceProcessEvents
| where (InitiatingProcessFileName =~ "powershell.exe"
    and FileName =~ "powershell.exe"
    and ProcessCommandLine has_any (EncodedCommandStrings))
    or (InitiatingProcessFileName =~ "powershell.exe"
    and InitiatingProcessCommandLine has_any (EncodedCommandStrings)
    and FileName =~ "powershell.exe")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let EncodedCommandStrings = dynamic([
    "-e ",
    "-ec ",
    "-en ",
    "-enc ",
    "-enco ",
    "-encod ",
    "-encoded ",
    "-EncodedCommand "
]);
DeviceProcessEvents
| where (InitiatingProcessFileName =~ "powershell.exe"
    and FileName =~ "powershell.exe"
    and ProcessCommandLine has_any (EncodedCommandStrings))
    or (InitiatingProcessFileName =~ "powershell.exe"
    and InitiatingProcessCommandLine has_any (EncodedCommandStrings)
    and FileName =~ "powershell.exe")
```
