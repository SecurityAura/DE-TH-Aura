# *CLR DLLs Loaded by Process with Low Prevalence*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/03/26 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1620 | Reflective Code Loading | https://attack.mitre.org/techniques/T1620/ |

#### Description

DISCLAIMER - I have to post this query quickly today. I'll comeback to it and update it with more information later on.

This query returns events where a process with a low prevalence loads a CLR DLL.

Another one for the "low prevalence X that does Y thing!". CLR DLL being loaded in a low prevalence process could point toward an implant, beacon or piece of malware loading .NET assemblies.

Note: This will not detect implants, beacons, etc. that would be injected in legitimate processes (e.g.: svchost.exe) and then are used to execute/load .NET assemblies.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://redhead0ntherun.medium.com/detecting-net-c-injection-execute-assembly-1894dbb04ff7
- https://detect.fyi/exploring-execute-assembly-a-deep-dive-into-in-memory-threat-execution-60adc61aef8

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceImageLoadEvents ###
```KQL
let LowPrevProcessesLoadingCLRDLLs = (
    DeviceImageLoadEvents
    | where FileName in~ ("clr.dll", "clrjit.dll", "mscoree.dll", "mscorlib.dll", "mscoreei.dll", "mscorlib.ni.dll")
    | where isnotempty( InitiatingProcessSHA1)
    | distinct InitiatingProcessSHA1
    | invoke FileProfile("InitiatingProcessSHA1",1000)
    // Adjust the GlobalPrevalence filter as needed
    | where GlobalPrevalence < 500
);
DeviceImageLoadEvents
| where FileName in~ ("clr.dll", "clrjit.dll", "mscoree.dll", "mscorlib.dll", "mscoreei.dll", "mscorlib.ni.dll")
| join kind=inner LowPrevProcessesLoadingCLRDLLs on InitiatingProcessSHA1
```
