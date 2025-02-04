# *Scheduled Task Creation*

## Query Information

These queries returns events where a Scheduled Task was created.

##

#### Description

These queries returns events where a Scheduled Task was created on Windows, through various different methods.

Scheduled Tasks remain one of the best way to set up stealthy persistence for malware and/or threat actors. They're easy to configure, malleable and you can also define exactly when they should trigger and what they should run in response. Some people have done also pretty nifty tricks with Scheduled Tasks in the past for good reasons (https://x.com/NathanMcNulty/status/1775072655139574042).

You can imagine that if the good peeps can use create Scheduled Tasks to fit their needs, so can malware/threat actors. And they can do so in a few different ways under Windows. You can create Scheduled Tasks via, at least:

- schtasks.exe
- at.exe (deprecated)
- Windows PowerShell

Fortunately for us, most of these methods can be detected and/or hunted for using the DeviceEvents or DeviceProcessEvents tables in Defender for Endpoint (MDE).

The queries below are more suited for hunting rather than detection, though they could probably be easily turned into those depending on the prevalence of some of these behavior in your environment. Not everyday will you see at.exe being called (it shouldn't anyway).

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://app.any.run/tasks/072483fe-b0d3-4296-a877-fb9bff58b3ed?p=672b6f94d59bb4c86f7be95d (look at that neat little update_task_ad.ps1)
- https://redcanary.com/threat-detection-report/techniques/scheduled-task/
- https://www.pwndefend.com/2023/01/17/malicious-scheduled-tasks/ (go give him a like and follow on Twitter folks, one of the good guys: https://x.com/UK_Daniel_Card)

### Queries Overview ###

- Defender for Endpoint (MDE) - 4 queries

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Register-ScheduledTask","New-ScheduledTask")
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
// To make it easier to filter/read the results
| extend Command = parse_json(tostring(parse_json(tostring(parse_json(tostring(AdditionalFields.TaskContent)).Actions)).Exec)).Command
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
// If this query return any events involving at.exe, be sure to investigate them
| where FileName in~ ("schtasks.exe","at.exe")
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Register-ScheduledTask","New-ScheduledTask")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where AdditionalFields has_any ("Register-ScheduledTask","New-ScheduledTask")
```
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
// To make it easier to filter/read the results
| extend Command = parse_json(tostring(parse_json(tostring(parse_json(tostring(AdditionalFields.TaskContent)).Actions)).Exec)).Command
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
// If this query return any events involving at.exe, be sure to investigate them
| where FileName in~ ("schtasks.exe","at.exe")
```
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Register-ScheduledTask","New-ScheduledTask")
```
