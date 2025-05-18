# *RDP Logon Outside Work Hours or During The Weekend*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/01/01 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.001 | Remote Services: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

#### Description

This query returns events when a RDP session is observed to be initiated outside of (your defined) work hours or during the weekend.

Depending on the threat actors, being stealthy during an intrusion isn't always their number one goal. At the very least, most ransomware operators don't seem to care one bit about it. Which is quite obvious for Incident Responders who've investigated these incidents in the past.

If there's one thing that threat actors still loves for lateral movement, it's using the Remote Desktop Protocol (RDP). It's fast, easy, convenient and ... it just works. It is therefore very common for threat actors to move laterally from system to system within a network using RDP. May it be between systems in the environment itself (e.g.: SERVER1 to SERVER2) or from their own machine (e.g.: they managed to login to the VPN) to a system in the environment (e.g.: SERVER1).

Now here's the interesting bit, threat actors have a schedule like you and me. They work during certain hours/days, go live their life, and then get back to work. Should you be located in a timezone different than their, with little to no overlap during their work hours and yours, you're bound to see them being active at these odd hours. Doesn't a RDP logon from a Domain Admin account to a Domain Controller at 3 AM on a Thursday seem odd to you?

With KQL, and Defender for Endpoint, Defender for Identity and SecurityEvent, it is possible to craft KQL queries that will return RDP logon events that happens outside the hours and/or days you define. For instance, outside 7 AM to 5 PM from Monday to Friday, and nothing over the weekend.

Simply adjust the queries below for your timezone and working hours and weekend days, and you'll have a pretty good threat hunting query looking for RDP logon at odd hours/days. Or even a detection, if you run a very tight ship (though do not discount these overnight deployments, manual updates, etc.).

Note: If you have systems and/or users across different timezone geographically ... well, it's still possible to use these queries, they'll just require "some" fine-tuning and adjustments.

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
- Defender for Identity (MDI) - 1 query
- Microsoft Sentinel (via SecurityEvent) - 1 query

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
let DaysOfWeek = dynamic([
    "Sunday", // 0
    "Monday", // 1
    "Tuesday", // 2
    "Wednesday", // 3
    "Thursday", // 4
    "Friday", // 5
    "Saturday" // 6
]);
// Define your timezone: https://learn.microsoft.com/en-us/kusto/query/timezone?view=microsoft-sentinel
let Timezone = "YOUR_TIMEZONE_HERE";
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| extend LocalDateTime = datetime_utc_to_local(TimeGenerated,Timezone)
| extend DayOfWeek = toint((dayofweek(LocalDateTime))/1d)
| extend HourOfDay = datetime_part("hour", LocalDateTime)
| where DayOfWeek in (0, 6)
    or (DayOfWeek between ( 1 .. 5 ) and (HourOfDay between (17 .. 23) or HourOfDay between ( 00 .. 07)))
| extend ActualDay = DaysOfWeek[DayOfWeek]
```
### Microsoft Defender for Identity via IdentityLogonEvents ###
```KQL
let DaysOfWeek = dynamic([
    "Sunday", // 0
    "Monday", // 1
    "Tuesday", // 2
    "Wednesday", // 3
    "Thursday", // 4
    "Friday", // 5
    "Saturday" // 6
]);
// Define your timezone: https://learn.microsoft.com/en-us/kusto/query/timezone?view=microsoft-sentinel
let Timezone = "YOUR_TIMEZONE_HERE";
IdentityLogonEvents
| where LogonType == "Remote desktop"
| extend LocalDateTime = datetime_utc_to_local(TimeGenerated,Timezone)
| extend DayOfWeek = toint((dayofweek(LocalDateTime))/1d)
| extend HourOfDay = datetime_part("hour", LocalDateTime)
| where DayOfWeek in (0, 6)
    or (DayOfWeek between ( 1 .. 5 ) and (HourOfDay between (17 .. 23) or HourOfDay between ( 00 .. 07)))
| extend ActualDay = DaysOfWeek[DayOfWeek]
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
let DaysOfWeek = dynamic([
    "Sunday", // 0
    "Monday", // 1
    "Tuesday", // 2
    "Wednesday", // 3
    "Thursday", // 4
    "Friday", // 5
    "Saturday" // 6
]);
// Define your timezone: https://learn.microsoft.com/en-us/kusto/query/timezone?view=microsoft-sentinel
let Timezone = "YOUR_TIMEZONE_HERE";
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| extend LocalDateTime = datetime_utc_to_local(TimeGenerated,Timezone)
| extend DayOfWeek = toint((dayofweek(LocalDateTime))/1d)
| extend HourOfDay = datetime_part("hour", LocalDateTime)
| where DayOfWeek in (0, 6)
    or (DayOfWeek between ( 1 .. 5 ) and (HourOfDay between (17 .. 23) or HourOfDay between ( 00 .. 07)))
| extend ActualDay = DaysOfWeek[DayOfWeek]
```
### Microsoft Defender for Identity via IdentityLogonEvents ###
```KQL
let DaysOfWeek = dynamic([
    "Sunday", // 0
    "Monday", // 1
    "Tuesday", // 2
    "Wednesday", // 3
    "Thursday", // 4
    "Friday", // 5
    "Saturday" // 6
]);
// Define your timezone: https://learn.microsoft.com/en-us/kusto/query/timezone?view=microsoft-sentinel
let Timezone = "YOUR_TIMEZONE_HERE";
IdentityLogonEvents
| where LogonType == "Remote desktop"
| extend LocalDateTime = datetime_utc_to_local(TimeGenerated,Timezone)
| extend DayOfWeek = toint((dayofweek(LocalDateTime))/1d)
| extend HourOfDay = datetime_part("hour", LocalDateTime)
| where DayOfWeek in (0, 6)
    or (DayOfWeek between ( 1 .. 5 ) and (HourOfDay between (17 .. 23) or HourOfDay between ( 00 .. 07)))
| extend ActualDay = DaysOfWeek[DayOfWeek]
```
### SecurityEvent ###
```KQL
let DaysOfWeek = dynamic([
    "Sunday", // 0
    "Monday", // 1
    "Tuesday", // 2
    "Wednesday", // 3
    "Thursday", // 4
    "Friday", // 5
    "Saturday" // 6
]);
// Define your timezone: https://learn.microsoft.com/en-us/kusto/query/timezone?view=microsoft-sentinel
let Timezone = "YOUR_TIMEZONE_HERE";
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| extend LocalDateTime = datetime_utc_to_local(TimeGenerated,Timezone)
| extend DayOfWeek = toint((dayofweek(LocalDateTime))/1d)
| extend HourOfDay = datetime_part("hour", LocalDateTime)
| where DayOfWeek in (0, 6)
    or (DayOfWeek between ( 1 .. 5 ) and (HourOfDay between (17 .. 23) or HourOfDay between ( 00 .. 07)))
| extend ActualDay = DaysOfWeek[DayOfWeek]
```
