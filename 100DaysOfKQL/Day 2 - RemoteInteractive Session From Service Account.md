# *Interactive or RemoteInteractive Session From Service Account*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/02 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078/ |
| T1021.001 | Remote Services: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

#### Description

This query looks for remote interactive (RDP) sessions from service accounts. Service accounts, as "understood" by most SMBs are often just an account that powers a service, task, process, etc. They may or may not use a specific naming convention as well, for instance:

- svcExchange
- svc-MSSQL
- Web.svc

A lot of these accounts are often just created as normal users and plugged in a Windows service or configured in an application. Therefore, unless they've been explicitly restricted via GPOs or else, they can still be used for RDP.

When a threat actor compromise a service account, he may use it to perform lateral movement throughout an environment, even RDP.

These accounts should never be used for such tasks, but because they're often not configured appropriately, threat actor can abuse them. They'll also often have high-privilege (e.g.: local Administrator on server(s) or even be part of the Domain Admins group).

Depending on your environment, these queries can be used to look for remote interactive sessions from service accounts based on a naming convention or a regex. You could even push this further by grabbing their name from another table (e.g.: IdentityInfo) or an external source (a Watchlist) if their name aren't standardized.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query (3 variants)
- Defender for Identity (MDI) - 1 query (3 variants)
- Microsoft Sentinel (SecurityEvent, Microsoft-Windows-TerminalServices-LocalSessionManager) - 2 queries (3 variants each)

## Defender XDR ##
### Query 1 - Defender for Endpoint (MDE) via DeviceLogonEvents ###
```KQL
// Replace the values in the variable by the ones used for your service accounts, if it's a tokenized value
let ServiceAccountStrings = dynamic([
    "svc",
    "service",
]);
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where AccountName has_any (ServiceAccountStrings)
```

```KQL
// Use this variant if the service account naming convention cannot be tokenized
// Replace the value of the "contains" filter by the string you're lookign for
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where AccountName contains "svc"
```

```KQL
// Use this variant if you're really good at regex and want to flex it
// For instance, if the Account Name starts with "svc" or "service"
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where AccountName matches regex @'(?i)(svc|service)'
```
### Query 2 - Defender for Identity (MDI) via IdentityLogonEvents ###
```KQL
// Replace the values in the variable by the ones used for your service accounts, if it's a tokenized value
let ServiceAccountStrings = dynamic([
    "svc",
    "service",
]);
IdentityLogonEvents
| where Application == "Active Directory"
| where LogonType == "Remote desktop"
| where AccountName has_any (ServiceAccountStrings)
```

```KQL
// Use this variant if the service account naming convention cannot be tokenized
// Replace the value of the "contains" filter by the string you're lookign for
IdentityLogonEvents
| where Application == "Active Directory"
| where LogonType == "Remote desktop"
| where AccountName contains "svc"
```

```KQL
// Use this variant if you're really good at regex and want to flex it
// For instance, if the Account Name starts with "svc" or "service"
IdentityLogonEvents
| where Application == "Active Directory"
| where LogonType == "Remote desktop"
| where AccountName matches regex @'(?i)(svc|service)'
```
## Microsoft Sentinel ##
### Query 1 - Defender for Endpoint (MDE) via DeviceLogonEvents ###
```KQL
// Replace the values in the variable by the ones used for your service accounts, if it's a tokenized value
let ServiceAccountStrings = dynamic([
    "svc",
    "service",
]);
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where AccountName has_any (ServiceAccountStrings)
```

```KQL
// Use this variant if the service account naming convention cannot be tokenized
// Replace the value of the "contains" filter by the string you're lookign for
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where AccountName contains "svc"
```

```KQL
// Use this variant if you're really good at regex and want to flex it
// For instance, if the Account Name starts with "svc" or "service"
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where AccountName matches regex @'(?i)(svc|service)'
```
### Query 2 - Defender for Identity (MDI) via IdentityLogonEvents ###
```KQL
// Replace the values in the variable by the ones used for your service accounts, if it's a tokenized value
let ServiceAccountStrings = dynamic([
    "svc",
    "service",
]);
IdentityLogonEvents
| where Application == "Active Directory"
| where LogonType == "Remote desktop"
| where AccountName has_any (ServiceAccountStrings)
```

```KQL
// Use this variant if the service account naming convention cannot be tokenized
// Replace the value of the "contains" filter by the string you're lookign for
IdentityLogonEvents
| where Application == "Active Directory"
| where LogonType == "Remote desktop"
| where AccountName contains "svc"
```

```KQL
// Use this variant if you're really good at regex and want to flex it
// For instance, if the Account Name starts with "svc" or "service"
IdentityLogonEvents
| where Application == "Active Directory"
| where LogonType == "Remote desktop"
| where AccountName matches regex @'(?i)(svc|service)'
```
### Query 3 - Security Event ID 4624 (Successful Logon) ###
```KQL
// Replace the values in the variable by the ones used for your service accounts, if it's a tokenized value
let ServiceAccountStrings = dynamic([
    "svc",
    "service",
]);
SecurityEvent
| where EventID == "4624"
| where LogonType == "10"
| where TargetUserName has_any (ServiceAccountStrings)
```

```KQL
// Use this variant if the service account naming convention cannot be tokenized
// Replace the value of the "contains" filter by the string you're lookign for
SecurityEvent
| where EventID == "4624"
| where LogonType == "10"
| where TargetUserName contains "svc"
```

```KQL
// Use this variant if you're really good at regex and want to flex it
// For instance, if the Account Name starts with "svc" or "service"
SecurityEvent
| where EventID == "4624"
| where LogonType == "10"
| where TargetUserName matches regex @'(?i)(svc|service)'
```
### Query #4 - Microsoft-Windows-TerminalServices-LocalSessionManager (Event ID 21 to 25)
```KQL
// Replace the values in the variable by the ones used for your service accounts, if it's a tokenized value
let ServiceAccountStrings = dynamic([
    "svc",
    "service",
]);
Event
| where Source == "Microsoft-Windows-TerminalServices-LocalSessionManager"
| where EventID in ("21","22","23","24","25")
| extend ParsedAccount = tostring(parse_xml(EventData).DataItem.UserData.EventXML.User)
| extend AccountName = tostring(split(ParsedAccount,"\\")[1])
| where AccountName has_any (ServiceAccountStrings)
```

```KQL
// Use this variant if the service account naming convention cannot be tokenized
// Replace the value of the "contains" filter by the string you're lookign for
Event
| where Source == "Microsoft-Windows-TerminalServices-LocalSessionManager"
| where EventID in ("21","22","23","24","25")
| extend ParsedAccount = tostring(parse_xml(EventData).DataItem.UserData.EventXML.User)
| extend AccountName = tostring(split(ParsedAccount,"\\")[1])
| where AccountName contains "svc"
```

```KQL
// Use this variant if you're really good at regex and want to flex it
// For instance, if the Account Name starts with "svc" or "service"
Event
| where Source == "Microsoft-Windows-TerminalServices-LocalSessionManager"
| where EventID in ("21","22","23","24","25")
| extend ParsedAccount = tostring(parse_xml(EventData).DataItem.UserData.EventXML.User)
| extend AccountName = tostring(split(ParsedAccount,"\\")[1])
| where AccountName matches regex @'(?i)(svc|service)'
```
