# *Potential Tunneled RDP Session*

## Query Information

This query return events where a RDP session may have been opened through a tunnel on a Windows host.

##

#### Description

This query return events where a RDP session may have been opened through a tunnel, set-up with tools such as plink and ngrok, or built-in binaries such as SSH on a Windows host.

Identification of these session come from the distinct IP address that is present in these logon events, namely:

- 127.0.0.1
- ::1
- ::%16777216

The last one is quite distinctive when the RDP session is opened through a ngrok tunnel. See the tweet below from Stephan Berger (@malmoeb), in which I was also tagged back then (feelold.png).

https://x.com/malmoeb/status/1519710302820089857?lang=ar-x-fm

#### Author <Optional>
- **Name:** SecurityAura
- **Github:** https://github.com/SecurityAura
- **Twitter:** https://x.com/SecurityAura
- **BlueSky:** https://bsky.app/profile/securityaura.bsky.social
- **Mastodon (InfoSec.Exchange):** https://infosec.exchange/@SecurityAura
- **LinkedIn:** Coming Soon!
- **Website:** https://medium.com/@securityaura

#### Reference(s)

- https://x.com/malmoeb/status/1519710302820089857?lang=ar-x-fm
- https://www.logpoint.com/en/blog/a-deep-look-at-the-darkside-ransomware-operators-and-their-affiliates/
- https://news.sophos.com/en-us/2022/07/14/rapid-response-the-ngrok-incident-guide/
- https://cloud.google.com/blog/topics/threat-intelligence/bypassing-network-restrictions-through-rdp-tunneling

### Queries Overview ###

- Microsoft Defender for Endpoint (MDE) - 1 query
- Microsoft Sentinel (SecurityEvents) - 1 query
- Microsoft Sentinel (Microsoft-Windows-TerminalServices-LocalSessionManager/Operational) - 1 query

## Defender XDR ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where RemoteIP in ("127.0.0.1","::1","::%16777216")
```
## Microsoft Sentinel ##
### Microsoft Defender for Endpoint via DeviceLogonEvents ###
```KQL
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where RemoteIP in ("127.0.0.1","::1","::%16777216")
```
### Microsoft Sentinel via SecurityEvents (Event ID 4624) ###
```KQL
SecurityEvent
| where EventID == "4624"
| where LogonType == "10"
| where IpAddress in ("127.0.0.1","::1","::%16777216")
```
### Microsoft Sentinel via Microsoft-Windows-TerminalServices-LocalSessionManager/Operational (Event ID 21 to 25)
```KQL
Event
| where Source == "Microsoft-Windows-TerminalServices-LocalSessionManager"
| where EventID in ("21","22","23","24","25")
| where ParameterXml has_any ("127.0.0.1","::1","::%16777216")
```
