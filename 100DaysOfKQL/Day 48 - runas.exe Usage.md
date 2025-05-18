# *runas.exe Usage*

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/17 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1134.002 | Access Token Manipulation: Create Process with Token | https://attack.mitre.org/techniques/T1134/002/ |

#### Description

This query returns events where runas.exe was used.

In Windows, runas.exe is a nifty little utility that allows you to run specific tools, programs, etc. as a different user. Different user being, other than the one that is currently logged in. Which means that you can spawn a cmd.exe or powershell.exe process using another set of credentials for instance and end up in a newly created process running at that user.

From a threat actor's perspective, this can allow either for Defense Evasion or Privilege Escalation. For Defense Evasion, they may be spawning new processes as another user that may be less suspicious or monitored, depending on what processes, and therefore, subsequent commands, they launch. As for the Privilege Escalation part, they could spawn a new process that has higher privilege or level of access than their current user, and use it to perform operations/commands that couldn't be executed before. For instance, they may use runas.exe to spawn a cmd.exe shell with a user that can login/access Domain Controllers. And from there, simply "net use" the main Windows drive (C$) and from there, get remote access to a DC.

The use of runas.exe with /savecred is also important/dangerous. As it means that any credential that would be entered in this command will be saved in the Windows Credential Manager and subsequent runas.exe commands calling that user will not require/prompt the user for the password of that target account.

PS: Akira still uses runas.exe in 2025, don't sleep on it!

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "runas.exe"
    or InitiatingProcessFileName =~ "runas.exe"
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName =~ "runas.exe"
    or InitiatingProcessFileName =~ "runas.exe"
```
