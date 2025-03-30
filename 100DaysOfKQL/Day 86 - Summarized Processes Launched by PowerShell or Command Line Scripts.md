# *Summarized Processes Launched by PowerShell or Command Line Scripts*

## Query Information

This query returns a summarized view of processes that are launched by PowerShell and/or command line scripts.

##

#### Description

This query returns a summarized view of processes that are launched by PowerShell (powershell.exe, pwsh.exe) and/or command line (cmd.exe) scripts (PS1, BAT, CMD).

A summarization query that can be used when you're trying to get a good view of which distinct processes/commands have been launched by various PowerShell and/or command line scripts. The query can be adjusted to target specific scripts, e.g.:

| where ProcessCommandLine has "myscript.ps1"

Or even a folder which would have a collection of scripts, e.g.:

| where ProcessCommandLine has @"C:\Scripts\"

This is mostly for investigation purposes (and possibly Threat Hunting), not fit for detection. Though it could be with a bit of fine-tuning. Which I leave as an exercise to you, or to me, in another #100DaysOfKQL post!

Came up with this when investigating an incident where a threat actor was making use of BAT scripts to do everything on an endpoint, but they were all running from the same directory. This query allowed me to basically understand what each script was doing and from there, better understand the intent and the impacts.

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
| where (InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
        and ProcessCommandLine has ".ps1")
        or (InitiatingProcessFileName =~ "cmd.exe"
        and ProcessCommandLine has_any (".bat", ".cmd"))
| summarize ["Commands"]=make_set(ProcessCommandLine),
            ["DistinctCommandsCount"]=dcount(ProcessCommandLine)
            by InitiatingProcessCommandLine
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via ProcessEvents ###
```KQL
DeviceProcessEvents
| where (InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
        and ProcessCommandLine has ".ps1")
        or (InitiatingProcessFileName =~ "cmd.exe"
        and ProcessCommandLine has_any (".bat", ".cmd"))
| summarize ["Commands"]=make_set(ProcessCommandLine),
            ["DistinctCommandsCount"]=dcount(ProcessCommandLine)
            by InitiatingProcessCommandLine
```
