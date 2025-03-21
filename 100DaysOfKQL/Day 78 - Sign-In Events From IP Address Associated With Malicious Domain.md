# *Sign-In Events From IP Address Associated With Malicious Domain*

## Query Information

This query returns events where a sign-in was observed from an IP address associated with a malicious domain of your choice.

##

#### Description

This query returns events where a sign-in was observed from an IP address associated with a malicious domain of your choice, that you define.

This is an investigate query, not a detection, which is meant to investigate situations where users may have accessed a specific phishing domain you identified (through whatever means you want) and for which that domain (or IP) will attempt a sign-in (failed or not) when a user provides his credentials (e.g.: AiTM).

PS: Disregard the ugly distinct tostring(), mv-expand and distinct tostring() hack which I will fix later. It's been a very long week.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### Queries Overview ###

- Microsoft Sentinel - 1 query

## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceNetworkEvents and Entra ID via SigninLogs, AADNonInteractiveUserSignInLogs ###
```KQL
let PhishingDomain = "INSERT_PHISHING_DOMAIN_HERE";
let NetworkEventsDns = (
    DeviceNetworkEvents
    | where ActionType == "DnsConnectionInspected"
    | where AdditionalFields has PhishingDomain
    | extend DNSAnswerIP = parse_json(AdditionalFields).answers
    | distinct tostring(DNSAnswerIP)
    | mv-expand todynamic(DNSAnswerIP)
    | distinct tostring(DNSAnswerIP)
);
let NetworkEventsConnections = (
    DeviceNetworkEvents
    | where RemoteUrl has PhishingDomain
        or RemoteIP in (NetworkEventsDns)
    | distinct RemoteIP
);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where IPAddress in (NetworkEventsConnections)

```
