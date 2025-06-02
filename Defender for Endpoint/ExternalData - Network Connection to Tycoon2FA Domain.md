# *ExternalData - Network Connection to Tycoon2FA Domain*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/06/02 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T566 | Phishing | https://attack.mitre.org/techniques/T1566/ |

#### Description

This query looks for network connection events, connections and DNS queries, to Tycoon2FA domain.

This is made possible by @RacWatchin8872 (https://x.com/RacWatchin8872) tracking these domains via his @NoMorePhis (https://x.com/NoMorePhis) bot and making the domains available on his GitHub.

All credits goes to @RacWatchin8872 for that data leveraged in this query.

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

### References ###

- https://github.com/NoMorePhish/Tycoon2FADomains
- https://blog.sekoia.io/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit/
- https://www.proofpoint.com/us/blog/email-and-cloud-threats/tycoon-2fa-phishing-kit-mfa-bypass

### Queries Overview ###

- Defender for Endpoint (MDE) - 1 query

## Defender XDR ##
### Defender for Endpoint (MDE) via DeviceNetworkEvents ###
```KQL
let Tycoon2FADomains = externaldata (Domain:string)
["https://raw.githubusercontent.com/NoMorePhish/Tycoon2FADomains/refs/heads/main/MaliciousDomains"]
with(format=txt);
DeviceNetworkEvents
| extend Query = iif(ActionType == "DnsConnectionInspected", tostring(parse_json(AdditionalFields).query), "")
| where RemoteUrl has_any (Tycoon2FADomains)
    or Query has_any (Tycoon2FADomains)
```
## Microsoft Sentinel ##
### Query 1 - Defender for Endpoint (MDE) via DeviceLogonEvents ###
```KQL
let Tycoon2FADomains = externaldata (Domain:string)
["https://raw.githubusercontent.com/NoMorePhish/Tycoon2FADomains/refs/heads/main/MaliciousDomains"]
with(format=txt);
DeviceNetworkEvents
| extend Query = iif(ActionType == "DnsConnectionInspected", tostring(parse_json(AdditionalFields).query), "")
| where RemoteUrl has_any (Tycoon2FADomains)
    or Query has_any (Tycoon2FADomains)
```
