# *Scheduled Task Created Remotely*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/12 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.005 | Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ |

#### Description

This query returns events where a Windows Scheduled Task was created remotely from another system.

Threat Actors (or even malware) can create Scheduled Tasks on remote systems for execution and/or persistence. This has the advantage on limiting their footprint in the network since they would stay one one host instead of moving laterally to another and therefore, leaving breadcrumbs.

However, creating a Scheduled Task on a remote system will still end up leaving one of our favorite event: a logon event. This logon event with its LogonId, and the Scheduled Task creation event with the LogonId of the user that created it can then be matched together to see if a Scheduled Task was created by a user from a remote system.

You can test this yourself by simply going on a Windows system, opening the Microsoft Management Console (mmc.exe), adding the Task Scheduler add-in, selecting a remote system and from there, create a new Scheduled Task.

This can be detected both via Defender for Endpoint (MDE) and native Security Event Logs on Windows.

PS: Yes, the same logic can be applied to Windows Service creation events. Be patient, it's coming!

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://redcanary.com/blog/threat-intelligence/blue-mockingbird-cryptominer/
- https://lolbas-project.github.io/lolbas/Binaries/Schtasks/

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query
- Microsoft Sentinel (SecurityEvent) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint DeviceEvents, DeviceLogonEvents ###
```KQL
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| join (
    DeviceLogonEvents
    | where LogonType == "Network"
    // Filtering out some weird edge case where the logon would come from a link-local IPv6 address, seen in my testing
    | where not (ipv6_is_in_range(RemoteIP, "fe80::/10"))
    ) on DeviceName, $left.InitiatingProcessLogonId == $right.LogonId
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint DeviceEvents, DeviceLogonEvents ###
```KQL
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| join (
    DeviceLogonEvents
    | where LogonType == "Network"
    // Filtering out some weird edge case where the logon would come from a link-local IPv6 address, seen in my testing
    | where not (ipv6_is_in_range(RemoteIP, "fe80::/10"))
    ) on DeviceName, $left.InitiatingProcessLogonId == $right.LogonId
```
### SecurityEvents ###
```KQL
SecurityEvent
| where EventID == 4698
| extend ParsedEventData = parse_xml(EventData)
| extend SubjectLogonId = tostring(parse_json(tostring(parse_json(tostring(ParsedEventData.EventData)).Data))[3].["#text"])
| join (
    SecurityEvent
    | where EventID == 4624
    | where LogonType == 3
    // Filtering out some weird edge case where the logon would come from a link-local IPv6 address, seen in my testing
    | where not (ipv6_is_in_range(IpAddress, "fe80::/10"))
    ) on Computer, $left.SubjectLogonId == $right.TargetLogonId
```
