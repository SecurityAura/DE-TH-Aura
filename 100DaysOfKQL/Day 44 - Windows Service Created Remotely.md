# *Windows Service Created Remotely*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/13 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1569.002 | System Services: Service Execution | https://attack.mitre.org/techniques/T1569/002/ |
| T1543.003 | Create or Modify System Process: Windows Service | https://attack.mitre.org/techniques/T1543/003/ |

#### Description

This query returns events where a Windows Service was created following a connection from a remote system.

The "sister query" to "Scheduled Task Created Remotely". It is there normal for the description to be similar. However, what we're looking at here is more use cases like PsExec, Cobalt Strike PsExec, Metasploit PsExec, etc. Where a Threat Actor would be executing commands from a remote system through a Windows Service.

However, creating a Windows Service on a remote system will still end up leaving one of our favorite event: a logon event. This logon event with its LogonId, and the Windows Service creation event with the LogonId of the user that created it can then be matched together to see if a Windows Service was created by a user from a remote system.

You can test this yourself by simply using PsExec (psexec64.exe \\COMPUTER1 cmd.exe) and looking at your Defender for Endpoint (MDE) telemetry or Security Event Logs.

This can be detected both via Defender for Endpoint (MDE) and native Security Event Logs on Windows.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_lateral-movement.htm
- https://threathunterplaybook.com/hunts/windows/190815-RemoteServiceInstallation/notebook.html

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query
- Microsoft Sentinel (SecurityEvent) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint DeviceEvents, DeviceLogonEvents ###
```KQL
DeviceEvents
| where ActionType == "ServiceInstalled"
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
| where ActionType == "ServiceInstalled"
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
| where EventID == 4697
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
