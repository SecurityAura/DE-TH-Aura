# *Windows Service Creation or Modification With binpath via sc.exe*

## Query Information

This query returns events where a Windows service is created and/or modified via sc.exe.

##

#### Description

This query returns events where a Windows service is created with its binpath and/or its binpath is modified via sc.exe. Threat actors can leverage Windows Services for persistence, privilege escalation or even simple execution (think Impacket).

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config

One way of creating and/or modifying a service is through the sc.exe utility. To create a service, you need to specify the binpath option, which is the binary, executable, file, etc. that will be launched by that service. Threat actors can create a service to launch whatever binary they want, depending on their goal.

They can also modify an existing service to replace its binpath (permanently or temporarily) with a binary, executable, file, etc. of their choosing.

Therefore, you can easily set up a detection and/or run scheduled hunts for new services that gets created or services whose binpath gets modified. You can even improve the query below by adding a filter in the ProcessCommandLine for paths where it would be unsual to have a service binary. Which may be the same paths you can find in the query below.

https://github.com/SecurityAura/DE-TH-Aura/blob/main/Defender%20for%20Endpoint/Process%20Execution%20or%20File%20Creation%20From%20Unusual%20Location.md

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s) ###

- https://redcanary.com/threat-detection-report/techniques/windows-service/
- https://arcticwolf.com/resources/blog/tellmethetruth-exploitation-of-cve-2023-46604-leading-to-ransomware/
- https://www.forescout.com/resources/common-ransomware-ttps-threat-briefing/
- https://offsec.blog/hidden-danger-how-to-identify-and-mitigate-insecure-windows-services/

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let ServiceCreateParameters = dynamic(["create","binpath"]);
let ServiceModifyParameters = dynamic(["config","binpath"]);
DeviceProcessEvents
| where InitiatingProcessFileName =~ "cmd.exe"
| where FileName =~ "sc.exe"
| where ProcessCommandLine has_any (ServiceCreateParameters) 
    or ProcessCommandLine has_all (ServiceModifyParameters)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceProcessEvents ###
```KQL
let ServiceCreateParameters = dynamic(["create","binpath"]);
let ServiceModifyParameters = dynamic(["config","binpath"]);
DeviceProcessEvents
| where InitiatingProcessFileName =~ "cmd.exe"
| where FileName =~ "sc.exe"
| where ProcessCommandLine has_any (ServiceCreateParameters) 
    or ProcessCommandLine has_all (ServiceModifyParameters)
```
