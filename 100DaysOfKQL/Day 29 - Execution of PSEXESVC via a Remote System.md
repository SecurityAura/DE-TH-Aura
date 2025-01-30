# *Execution of PSEXESVC via a Remote System*

## Query Information

These queries returns events where a PSEXESVC service install was triggered by a remote system.

##

#### Description

DISCLAIMER: This query has been posted quickly due to exceptional conditions on my end today which made it that I only have a small windows of time left to post it on January 29, 2025. I'll update/enchance that page tomorrow or later this week.

These queries returns events where a PSEXESVC service install, which would have executed a command/process on the host system, was triggered by a remote system, who sent a PsExec command.

This is achieved by maching the LogonId present in the ServiceInstall (MDE) or SecurityEvents (Event ID 4697) to the LogonId of the DeviceLogonEvents that happened on the endpoint.

PS: As I was posting this, I realized that another query would be possible that doesn't rely on MDE, but uses two (2) SecurityEvents: 4624 (Successful Logon) and 4697 (New service install). I'll add it later.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Reference(s)

- https://intel471.com/blog/threat-hunting-case-study-psexec
- https://aboutdfir.com/the-key-to-identify-psexec/

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query
- Microsoft Sentinel (SecurityEvents) x Defender for Endpoint (MDE)  - 2 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceEvents, DeviceLogonEvents ###
```KQL
let PSEXESVCInstallEvents = (DeviceEvents
| where ActionType == "ServiceInstalled"
| where AdditionalFields.ServiceName =~ "PSEXESVC"
| project DeviceName, LogonId);
DeviceLogonEvents
| join PSEXESVCInstallEvents on DeviceName, LogonId
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceEvents, DeviceLogonEvents ###
```KQL
let PSEXESVCInstallEvents = (DeviceEvents
| where ActionType == "ServiceInstalled"
| where AdditionalFields.ServiceName =~ "PSEXESVC"
| project DeviceName, LogonId);
DeviceLogonEvents
| join PSEXESVCInstallEvents on DeviceName, LogonId
```
### SecurityEvents x Defender for Endpoint (DeviceLogonEvents) ###
```KQL
let PSEXESVCInstallEvents = (SecurityEvent
| where EventID == "4697"
| extend ParsedXML = parse_xml(EventData)
| extend LogonIdHex = parse_json(tostring(parse_json(tostring(ParsedXML.EventData)).Data))[3].["#text"]
| where parse_json(tostring(parse_json(tostring(ParsedXML.EventData)).Data))[4].["#text"] == "PSEXESVC"
| extend LogonIdDec = tolong(LogonIdHex)
| extend ComputerLower = tolower(Computer)
| project ComputerLower, LogonIdDec);
DeviceLogonEvents
| join PSEXESVCInstallEvents on $left.DeviceName == $right.ComputerLower, $left.LogonId == $right.LogonIdDec
```
### SecurityEvents ###
```KQL
let PSEXESVCInstallEvents = (SecurityEvent
| where EventID == "4697"
| extend ParsedXML = parse_xml(EventData)
| extend LogonIdHex = parse_json(tostring(parse_json(tostring(ParsedXML.EventData)).Data))[3].["#text"]
| where parse_json(tostring(parse_json(tostring(ParsedXML.EventData)).Data))[4].["#text"] == "PSEXESVC"
| extend LogonIdDec = tolong(LogonIdHex)
| project Computer, LogonIdDec);
SecurityEvent
| where EventID == "4624"
| extend LogonIdDec = tolong(TargetLogonId)
| join PSEXESVCInstallEvents on Computer, $left.LogonIdDec == $right.LogonIdDec
```
