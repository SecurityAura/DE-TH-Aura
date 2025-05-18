# *Identify Accounts Used From a Threat Actor Device*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/02/23 | Initial version (part of #100DaysOfKQL) |
| 2025/05/17 | Added MITRE ATT&CK and Changelog |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.001 | Remote Services: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

#### Description

Disclaimer: More of an "investigation" query and/or a query you would most likely run when you're investigating an incident in an environment where Defender for Endpoint (MDE) was deployed beforehand.

This query returns a summarization of the accounts that are used from a threat actor's device on an environment where MDE is deployed. The scenario we're talking about here is one where the threat actor managed to connect his device to the network. Most often, through the VPN. For more information about this, you can go down a little #TBT (even though I'm posting this on Sunday, anyway) and read the 1st query of the #100DaysOfKQL:

https://github.com/SecurityAura/DE-TH-Aura/blob/main/100DaysOfKQL/Day%201%20-%20Authentication%20From%20Suspicious%20WorkstationName.md

This query can quickly help grasp (read: identify) which accounts were successfully used by the threat actor from his device. In order to use that query however, you need to know at least one piece of information:

- The threat actor's device name (once again, #TBT to Day 1 query to help you get started)
- The threat actor's device IP (e.g.: the IP in the VPN subnet that was assigned to its device when it connected to the network)

From there, you can simply query the DeviceLogonEvents (MDE) or IdentityLogonEvents (MDI) table for all successful authentication related events coming from that device name or remote IP, and get a list of compromised accounts.

One thing to consider as well is the association between the threat actor's device name and its IP address. Not all events are created equal, which means, not all events have BOTH the device name AND remote IP column populated, though the remote IP one should always have a value in it. Therefore, if in your results, you get a set of accounts being used from a remote IP with no remote device name, make sure that when these events occured, that IP really was associated to the threat actor's machine.

I strongly suggest to also run the query without the "LogonSuccess" filter, to see what other accounts were tried by the threat actor. Just because those logon failed, it doesn't mean that the account wasn't compromised (e.g.: logon failed because the account is locked, doesn't mean the credentials aren't valid and therefore, compromised).

PS: There are dozen of ways to get that information, and then some, here in this scenario. These queries should be seen as the most ... basic way to get that information and nothing more. I do plan on enhancing this page with more queries in the future. Such as ones that may return the LogonType for each account, on which DeviceNames they were tried, etc. OR, if you're following these queries to learn... you can consider it as a challenge!

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

## Microsoft Defender XDR ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
let TARemoteDeviceNames = dynamic([ 
    "THREAT ACTOR",
    "DEVICE NAMES",
    "HERE"
]); 
let TARemoteIPs = dynamic([ 
    "THREAT ACTOR",
    "REMOTE IPs",
    "HERE" 
]); 
DeviceLogonEvents
| where RemoteDeviceName has_any (TARemoteDeviceNames)
    or RemoteIP has_any (TARemoteIPs)
| where ActionType == "LogonSuccess"
| extend Account = strcat(AccountDomain,"\\",AccountName)
| summarize ["Accounts"]=make_set(Account),
            ["AccountCount"]=dcount(Account)
            by RemoteDeviceName, RemoteIP
```
### Microsoft Defender for Endpoint via IdentityLogonEvents ###
```KQL
let TARemoteDeviceNames = dynamic([ 
    "THREAT ACTOR",
    "DEVICE NAMES",
    "HERE"
]); 
let TARemoteIPs = dynamic([ 
    "THREAT ACTOR",
    "REMOTE IPs",
    "HERE" 
]); 
IdentityLogonEvents
| where AdditionalFields.["FROM.DEVICE"] has_any (TARemoteDeviceNames)
    or AdditionalFields.["FROM.DEVICE"] has_any (TARemoteIPs)
| where ActionType == "LogonSuccess"
| extend Account = strcat(AccountDomain,"\\",AccountName)
| summarize ["Accounts"]=make_set(Account),
            ["AccountCount"]=dcount(Account)
            by tostring(AdditionalFields.["FROM.DEVICE"])
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
let TARemoteDeviceNames = dynamic([ 
    "THREAT ACTOR",
    "DEVICE NAMES",
    "HERE"
]); 
let TARemoteIPs = dynamic([ 
    "THREAT ACTOR",
    "REMOTE IPs",
    "HERE" 
]); 
DeviceLogonEvents
| where RemoteDeviceName has_any (TARemoteDeviceNames)
    or RemoteIP has_any (TARemoteIPs)
| where ActionType == "LogonSuccess"
| extend Account = strcat(AccountDomain,"\\",AccountName)
| summarize ["Accounts"]=make_set(Account),
            ["AccountCount"]=dcount(Account)
            by RemoteDeviceName, RemoteIP
```
### Microsoft Defender for Endpoint via IdentityLogonEvents ###
```KQL
let TARemoteDeviceNames = dynamic([ 
    "THREAT ACTOR",
    "DEVICE NAMES",
    "HERE"
]); 
let TARemoteIPs = dynamic([ 
    "THREAT ACTOR",
    "REMOTE IPs",
    "HERE" 
]); 
IdentityLogonEvents
| where AdditionalFields.["FROM.DEVICE"] has_any (TARemoteDeviceNames)
    or AdditionalFields.["FROM.DEVICE"] has_any (TARemoteIPs)
| where ActionType == "LogonSuccess"
| extend Account = strcat(AccountDomain,"\\",AccountName)
| summarize ["Accounts"]=make_set(Account),
            ["AccountCount"]=dcount(Account)
            by tostring(AdditionalFields.["FROM.DEVICE"])
```
