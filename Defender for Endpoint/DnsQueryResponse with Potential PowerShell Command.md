# *DnsQueryResponse with Potential PowerShell Command*

## Query Information

#### Changelog

| Date | Comments |
|---|---|
| 2025/07/18 | Initial version |

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1059.001 | Command and Scripting Interpreter: PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| T1071.004 | Application Layer Protocol: DNS | https://attack.mitre.org/techniques/T1071/004/ |

#### Description

This query looks for DnsQueryResponse events where the DnsQueryResult contains the "powershell" string, as tweeted by @1nt3l_hunt (on Twitter/X) on July 18, 2025.

https://x.com/1nt3l_hunt/status/1946221664452166083

This is a developping situation, though this query can serve as a base to start looking for these events in your Microsoft Defender XDR or Microsoft Sentinel.

contains is used here instead of has since the "powershell" string may not be tokenized in certain TXT records, such as the one from tohknet[.]com

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

## Microsoft Defender XDR ##
### Defender for Endpoint (MDE) via DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "DnsQueryResponse"
| extend DnsQueryResult = tostring(parse_json(AdditionalFields).DnsQueryResult)
| where DnsQueryResult contains "powershell"
```
## Microsoft Sentinel ##
### Defender for Endpoint (MDE) DeviceEvents ###
```KQL
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where AdditionalFields.DnsQueryResult contains "powershell"
```
