# *Command Line Interpreters Launched via Scheduled Tasks*

## Query Information

This query looks for command line interpreters that were launched by Scheduled Tasks on Windows systems.

##

#### Description

This query looks for command line interpreters, and therefore, scripts (e.g.: BAT, CMD, PS1, etc.) that were launched by Scheduled Tasks on Windows systems. Threat actors can leverage Scheduled Tasks for Execution and Persistence, but also Privilege Escalation.

The Privilege Escalation angle is interesting, because if a Scheduled Task set to run in the NT AUTHORITY\SYSTEM context executes a file that is modifiable by low-privileged users, it could lead to the user modifying this file to execute any commands he wants. Think of files that are located on servers where a user is not an Administrator, but can modify the content/files within the folder where the called script file is located.

As for Execution, you could typically look for "unique", kind of "one-off" commands that are ran (e.g.: cmd.exe /c net BLABLA). For Persistence, a lot of popular malware nowaday leveraged Scheduled Tasks for persistence, think uncommon/suspicious paths under %APPDATA%, %LOCALAPPDATA%, C:\ProgramData, etc.

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

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
let CommandLineInterpreters = dynamic([
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wmic.exe",
    "mshta.exe",
    "cscript.exe",
    "wscript.exe"
]);
DeviceProcessEvents
// For anything pre-Windows 10 version 1511
| where ((InitiatingProcessFileName =~ "taskeng.exe")
// For anything post Windows 10 version 1511
    or (InitiatingProcessFileName =~ "svchost.exe" and InitiatingProcessCommandLine has "Schedule"))
| where FileName in~ (CommandLineInterpreters)
// Summarize the output to make it cleaner to read and identify possible outliers
// However, you can remove this summarization if you want to get the "raw" results and simply start with a simple "distinct" for instance
| summarize ["Devices"]=make_set(DeviceName), 
            ["Number of Devices"]=dcount(DeviceName)
            by ProcessCommandLine
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) via DeviceProcessEvents ###
```KQL
let CommandLineInterpreters = dynamic([
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wmic.exe",
    "mshta.exe",
    "cscript.exe",
    "wscript.exe"
]);
DeviceProcessEvents
// For anything pre-Windows 10 version 1511
| where ((InitiatingProcessFileName =~ "taskeng.exe")
// For anything post Windows 10 version 1511
    or (InitiatingProcessFileName =~ "svchost.exe" and InitiatingProcessCommandLine has "Schedule"))
| where FileName in~ (CommandLineInterpreters)
// Summarize the output to make it cleaner to read and identify possible outliers
// However, you can remove this summarization if you want to get the "raw" results and simply start with a simple "distinct" for instance
| summarize ["Devices"]=make_set(DeviceName), 
            ["Number of Devices"]=dcount(DeviceName) 
            by ProcessCommandLine
```
