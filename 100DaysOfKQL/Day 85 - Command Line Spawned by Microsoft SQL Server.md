# *Command Line Spawned by Microsoft SQL Server*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/28 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | https://attack.mitre.org/techniques/T1059/003/ |

#### Description

DISCLAIMER - I have to post this query quickly today. I'll comeback to it and update it with more information later on.

This query returns events where a command line (cmd.exe) was spawned by Microsoft SQL Server (sqlservr.exe).

Could be an indication of xp_cmdshell usage. Not every cmd.exe instances gets flagged by Defender XDR as being suspicious/malicious. Starting as a hunting query, you can develop it in a more robust detection by filtering out known/benign invocations of cmd.exe by sqlservr.exe.

You can also develop it further, and make it so that if the process ancestry looks like sqlservr.exe -> cmd.exe -> typical discovery command such as net.exe, whoami.exe, etc., you alert on it.

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
### Microsoft Defender for Endpoint via ProcessEvents ###
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where FileName =~ "cmd.exe"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via ProcessEvents ###
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where FileName =~ "cmd.exe"
```
