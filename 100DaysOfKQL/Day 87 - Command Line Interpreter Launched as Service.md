# *Command Line Interpreter Launched as Service*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/30 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | https://attack.mitre.org/techniques/T1059/001/ |
| T1569.002 | System Services: Service Execution | https://attack.mitre.org/techniques/T1569/002/ |
| T1543.003 | Create or Modify System Process: Windows Service | https://attack.mitre.org/techniques/T1543/003/ |

#### Description

This query returns events where a command line interpreter (cmd.exe, powershell.exe or pwsh.exe) is spawned by services.exe, therefore, most likely launched as Windows Service.

Threat Actors can execute commands remotely on hosts through the Service Control Manager (SCM) where a Windows Service can be created or manipulated (read: modified) to execute either one-time commands and/or persistent commands that will be executed when that service launch. Windows Services are launched by services.exe, and depending on the environment, having services.exe launch a command line interpreter is highly unsual, to not say downright suspicious.

If you've ever dealt with Cobalt Strike, you know.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://redcanary.com/threat-detection-report/techniques/windows-command-shell/
- https://www.logpoint.com/en/blog/how-to-detect-stealthy-cobalt-strike-activity-in-your-enterprise/#

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via ProcessEvents ###
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via ProcessEvents ###
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "services.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe")
```
