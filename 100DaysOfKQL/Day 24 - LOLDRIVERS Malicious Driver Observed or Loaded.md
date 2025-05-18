# *LOLDRIVERS Malicious Driver Observed or Loaded*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/24 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1068 | Exploitation for Privilege Escalation | https://attack.mitre.org/techniques/T1068/ |

#### Description

This query returns events where a malicious driver listed in the LOLDRIVERS project is either seen through file events on a system or loaded.

https://www.loldrivers.io/

A popular technique now for threat actor to disable/impair defenses is to use a BYOVD (Bring Your Own Vulnerable Driver) technique where they bring a vulnerable driver that they can control/abuse in order to kill and/or cripple endpoint security solution. This allows them to execute their payloads and/or perform their malicious commands without risk of being detected, nor blocked.

In ransomware deployments, we've now seen threat actors using that BYOVD technique to kill the resident Antivirus/EDR on the system just before launching the ransomware, and not just at the beginning of their intrusion. This makes the ransomware deployment more effective by disabling whatever defense is on a system before it gets encrypted (assuming Microsoft Defender doesn't get enabled as a result and crash the party).

The queries below can be adjusted to look for known vulnerable drivers as well if needed. Simply swap the URL for the appropriate one from the LOLDRIVERS Github repo.

https://github.com/magicsword-io/LOLDrivers/tree/main/detections/hashes

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References

- https://blogs.vmware.com/security/2023/04/bring-your-own-backdoor-how-vulnerable-drivers-let-hackers-in.html
- https://www.crowdstrike.com/en-us/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/
- https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/strategies-to-monitor-and-prevent-vulnerable-driver-attacks/4103985
- https://www.huntress.com/blog/readtext34-ransomware-incident

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 2 queries

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
let MaliciousLOLDrivers = (
    externaldata(SHA1:string)
    ["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/refs/heads/main/detections/hashes/samples_vulnerable.sha1"]
);
DeviceEvents
| where ActionType == "DriverLoad"
| where SHA1 in (MaliciousLOLDrivers)
```
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
let MaliciousLOLDrivers = (
    externaldata(SHA1:string)
    ["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/refs/heads/main/detections/hashes/samples_vulnerable.sha1"]
);
DeviceFileEvents
| where ActionType == "FileCreated"
| where SHA1 in (MaliciousLOLDrivers)
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents ###
```KQL
let MaliciousLOLDrivers = (
    externaldata(SHA1:string)
    ["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/refs/heads/main/detections/hashes/samples_vulnerable.sha1"]
);
DeviceEvents
| where ActionType == "DriverLoad"
| where SHA1 in (MaliciousLOLDrivers)
```
### Microsoft Defender for Endpoint via DeviceFileEvents ###
```KQL
let MaliciousLOLDrivers = (
    externaldata(SHA1:string)
    ["https://raw.githubusercontent.com/magicsword-io/LOLDrivers/refs/heads/main/detections/hashes/samples_vulnerable.sha1"]
);
DeviceFileEvents
| where ActionType == "FileCreated"
| where SHA1 in (MaliciousLOLDrivers)
```
