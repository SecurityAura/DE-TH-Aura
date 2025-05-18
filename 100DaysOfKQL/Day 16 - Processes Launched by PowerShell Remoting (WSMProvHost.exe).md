# *Processes Launched by PowerShell Remoting (WSMProvHost.exe)*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/16 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1021.006 | Remote Services: Windows Remote Management | https://attack.mitre.org/techniques/T1021/006/ |


#### Description

This query returns a quick summarized view of processes that were launched through PowerShell Remoting where the parent process is WSMProvHost.exe.

PowerShell Remoting allows you to connect/establish a session to a remote system and execute commands through PowerShell. On the remote (target) system, this will return in processes being launched by the WSMProvHost.exe process. It is therefore quite easy to get a list of all the processes it launched and review them for ones that could be suspicious/malicious. Such as a threat actor attempting to move laterally around the environment.

By summarizing the various ProcessCommandLine involved by FolderPath involved, you end up with a lot less results to review. And you can also order results by the number of unique ProcessCommandLine in order to find unique/uncommon ones.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/powershell-remoting-faq?view=powershell-7.4
- https://www.splunk.com/en_us/blog/security/powershell-web-access-your-network-s-backdoor-in-plain-sight.html (because it works for PSWA too!)
- https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 1 query

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| summarize ["ProcessCommandLines"]=make_set(ProcessCommandLine),
            ["ProcessCommandLineCount"]=dcount(ProcessCommandLine)
            by FolderPath
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents ###
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| summarize ["ProcessCommandLines"]=make_set(ProcessCommandLine),
            ["ProcessCommandLineCount"]=dcount(ProcessCommandLine)
            by FolderPath
```
